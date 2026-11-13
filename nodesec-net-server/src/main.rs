use anyhow::Result;
use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        State,
    },
    response::Response,
    routing::get,
    Json, Router,
};
use futures_util::{SinkExt, StreamExt};
use nodesec_core::{
    models::{NetworkConnection, NetworkProtocol, Platform, ThreatAlert},
    network::common::{WSMessage, AgentInfo, RuleSet},
};
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::{
    sync::{broadcast, mpsc, Mutex},
    time::interval,
};
use tracing::{info, error};
use uuid::Uuid;
use rand::{thread_rng, Rng, SeedableRng, rngs::SmallRng};

// Shared state
#[derive(Clone)]
struct AppState {
    agents: Arc<Mutex<HashMap<String, AgentInfo>>>,
    connections_tx: broadcast::Sender<NetworkConnection>,
    alerts_tx: broadcast::Sender<ThreatAlert>,
    rules: Arc<Mutex<RuleSet>>,
    stats: Arc<Mutex<ServerStats>>,
}

#[derive(Default, Clone, serde::Serialize)]
struct ServerStats {
    total_connections: u64,
    total_alerts: u64,
    connected_agents: usize,
    uptime_seconds: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    
    let (connections_tx, _) = broadcast::channel(1000);
    let (alerts_tx, _) = broadcast::channel(1000);
    
    let state = AppState {
        agents: Arc::new(Mutex::new(HashMap::new())),
        connections_tx,
        alerts_tx,
        rules: Arc::new(Mutex::new(RuleSet::default())),
        stats: Arc::new(Mutex::new(ServerStats::default())),
    };
    
    // Start stats updater
    let stats_state = state.clone();
    tokio::spawn(async move {
        let mut interval = interval(Duration::from_secs(1));
        loop {
            interval.tick().await;
            let mut stats = stats_state.stats.lock().await;
            stats.uptime_seconds += 1;
            stats.connected_agents = stats_state.agents.lock().await.len();
        }
    });
    
    // Start mock data generator (for testing)
    let mock_state = state.clone();
    tokio::spawn(async move {
        generate_mock_data(mock_state).await;
    });
    
    let app = Router::new()
        .route("/ws", get(ws_handler))
        .route("/api/agents", get(list_agents).post(register_agent))
        .route("/api/agents/:id", axum::routing::delete(revoke_agent))
        .route("/api/rules", get(list_rules).post(add_rule))
        .route("/api/rules/:id", axum::routing::delete(remove_rule))
        .route("/api/stats", get(get_stats))
        .route("/api/health", get(health_check))
        .with_state(state);
    
    let addr = "0.0.0.0:8080".parse::<SocketAddr>()?;
    info!("Starting nodesec network server on {}", addr);
    
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    
    Ok(())
}

async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
) -> Response {
    ws.on_upgrade(|socket| handle_websocket(socket, state))
}

// Messages that can be sent to the WebSocket sender task
enum WsOutMessage {
    Text(String),
    Ping(Vec<u8>),
    Close,
}

async fn handle_websocket(socket: WebSocket, state: AppState) {
    let agent_id = Uuid::new_v4().to_string();
    info!("New WebSocket connection: {}", agent_id);
    
    let (sender, mut receiver) = socket.split();
    let mut connections_rx = state.connections_tx.subscribe();
    let mut alerts_rx = state.alerts_tx.subscribe();
    
    // Channel for sending messages to the sender task
    let (ws_out_tx, mut ws_out_rx) = mpsc::channel::<WsOutMessage>(100);
    
    // Register agent
    let agent = AgentInfo {
        id: agent_id.clone(),
        name: format!("Agent-{}", &agent_id[..8]),
        platform: Platform::detect(),
        connected_at: chrono::Utc::now().timestamp() as u64,
        last_seen: chrono::Utc::now().timestamp() as u64,
        status: "connected".to_string(),
    };
    
    state.agents.lock().await.insert(agent_id.clone(), agent.clone());
    
    // Spawn sender task
    let agent_id_clone = agent_id.clone();
    let welcome = WSMessage::AgentStatus(agent.clone());
    let sender_task = tokio::spawn(async move {
        let mut sender = sender;
        
        // Send welcome message
        if let Ok(msg) = serde_json::to_string(&welcome) {
            let _ = sender.send(Message::Text(msg.into())).await;
        }
        
        loop {
            tokio::select! {
                Ok(conn) = connections_rx.recv() => {
                    let msg = WSMessage::ConnectionEvent(conn);
                    if let Ok(text) = serde_json::to_string(&msg) {
                        if sender.send(Message::Text(text.into())).await.is_err() {
                            break;
                        }
                    }
                }
                Ok(alert) = alerts_rx.recv() => {
                    let msg = WSMessage::ThreatAlert(alert);
                    if let Ok(text) = serde_json::to_string(&msg) {
                        if sender.send(Message::Text(text.into())).await.is_err() {
                            break;
                        }
                    }
                }
                Some(out_msg) = ws_out_rx.recv() => {
                    match out_msg {
                        WsOutMessage::Text(text) => {
                            if sender.send(Message::Text(text.into())).await.is_err() {
                                break;
                            }
                        }
                        WsOutMessage::Ping(data) => {
                            if sender.send(Message::Pong(data)).await.is_err() {
                                break;
                            }
                        }
                        WsOutMessage::Close => break,
                    }
                }
                else => break,
            }
        }
    });
    
    // Handle incoming messages
    while let Some(msg) = receiver.next().await {
        match msg {
            Ok(Message::Text(text)) => {
                if let Ok(ws_msg) = serde_json::from_str::<WSMessage>(&text) {
                    handle_ws_message(ws_msg, &state, &agent_id_clone).await;
                }
            }
            Ok(Message::Close(_)) => {
                let _ = ws_out_tx.send(WsOutMessage::Close).await;
                break;
            }
            Ok(Message::Ping(data)) => {
                let _ = ws_out_tx.send(WsOutMessage::Ping(data)).await;
            }
            Err(e) => {
                error!("WebSocket error: {}", e);
                break;
            }
            _ => {}
        }
    }
    
    let _ = ws_out_tx.send(WsOutMessage::Close).await;
    sender_task.abort();
    
    // Cleanup
    state.agents.lock().await.remove(&agent_id);
    info!("Agent disconnected: {}", agent_id);
}

async fn handle_ws_message(msg: WSMessage, state: &AppState, agent_id: &str) {
    match msg {
        WSMessage::Heartbeat => {
            if let Some(agent) = state.agents.lock().await.get_mut(agent_id) {
                agent.last_seen = chrono::Utc::now().timestamp() as u64;
            }
        }
        WSMessage::ConnectionEvent(conn) => {
            let _ = state.connections_tx.send(conn);
            let mut stats = state.stats.lock().await;
            stats.total_connections += 1;
        }
        WSMessage::ThreatAlert(alert) => {
            let _ = state.alerts_tx.send(alert);
            let mut stats = state.stats.lock().await;
            stats.total_alerts += 1;
        }
        WSMessage::RuleUpdate(rules) => {
            *state.rules.lock().await = rules;
        }
        _ => {}
    }
}

// REST API handlers
async fn list_agents(State(state): State<AppState>) -> Json<Vec<AgentInfo>> {
    let agents = state.agents.lock().await;
    Json(agents.values().cloned().collect())
}

async fn register_agent(
    State(state): State<AppState>,
    Json(payload): Json<serde_json::Value>,
) -> Json<AgentInfo> {
    let name = payload.get("name").and_then(|v| v.as_str()).unwrap_or("Unknown Agent");
    let agent = AgentInfo {
        id: Uuid::new_v4().to_string(),
        name: name.to_string(),
        platform: Platform::detect(),
        connected_at: chrono::Utc::now().timestamp() as u64,
        last_seen: chrono::Utc::now().timestamp() as u64,
        status: "registered".to_string(),
    };
    state.agents.lock().await.insert(agent.id.clone(), agent.clone());
    Json(agent)
}

async fn revoke_agent(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<Json<serde_json::Value>, axum::http::StatusCode> {
    state.agents.lock().await.remove(&id);
    Ok(Json(serde_json::json!({ "success": true })))
}

async fn list_rules(State(state): State<AppState>) -> Json<RuleSet> {
    let rules = state.rules.lock().await;
    Json(rules.clone())
}

async fn add_rule(
    State(state): State<AppState>,
    Json(payload): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let mut rules = state.rules.lock().await;
    let rule_id = Uuid::new_v4().to_string();
    let rule = serde_json::json!({
        "id": rule_id,
        "name": payload.get("name").and_then(|v| v.as_str()).unwrap_or("Custom Rule"),
        "description": payload.get("description").and_then(|v| v.as_str()).unwrap_or(""),
        "severity": payload.get("severity").and_then(|v| v.as_str()).unwrap_or("medium"),
        "enabled": true,
    });
    rules.custom_rules.push(rule.clone());
    Json(rule)
}

async fn remove_rule(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<Json<serde_json::Value>, axum::http::StatusCode> {
    let mut rules = state.rules.lock().await;
    rules.custom_rules.retain(|r| r.get("id").and_then(|v| v.as_str()) != Some(&id));
    Ok(Json(serde_json::json!({ "success": true })))
}

async fn get_stats(State(state): State<AppState>) -> Json<ServerStats> {
    let stats = state.stats.lock().await;
    Json(stats.clone())
}

async fn health_check() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "healthy", "service": "nodesec-net-server" }))
}

// Mock data generator for testing
async fn generate_mock_data(state: AppState) {
    let processes = ["chrome", "firefox", "curl", "ssh", "docker", "node", "python", "code"];
    let destinations = [
        ("8.8.8.8", 53), ("1.1.1.1", 53), ("192.168.1.1", 80),
        ("10.0.0.1", 22), ("172.16.0.5", 443), ("203.0.113.10", 8080),
        ("198.51.100.2", 3389), ("10.10.10.10", 445)
    ];
    let protocols = ["TCP", "UDP"];
    
    let mut interval = interval(Duration::from_secs(2));
    let mut rng = SmallRng::from_rng(&mut thread_rng()).unwrap();
    
    loop {
        interval.tick().await;
        
        let proc = processes[rng.gen_range(0..processes.len())];
        let (dst_ip, dst_port) = destinations[rng.gen_range(0..destinations.len())];
        let protocol_str = protocols[rng.gen_range(0..protocols.len())];
        let protocol = match protocol_str {
            "TCP" => NetworkProtocol::Tcp,
            "UDP" => NetworkProtocol::Udp,
            _ => NetworkProtocol::Tcp,
        };
        let score = rng.gen_range(0..=255) as u8;
        
        let src_ip: IpAddr = format!("192.168.1.{}", rng.gen_range(0..=255)).parse().unwrap();
        
        let conn = NetworkConnection {
            timestamp: chrono::Utc::now().timestamp() as u64,
            pid: (rng.gen_range(0..50000) as u32) + 1000,
            process_name: proc.to_string(),
            protocol,
            src_ip,
            src_port: rng.gen_range(0..=65535) as u16,
            dst_ip: dst_ip.parse().unwrap(),
            dst_port,
            threat_score: score,
            is_suspicious: score > 50,
            process_path: None,
            command_line: None,
            user: None,
        };
        
        let _ = state.connections_tx.send(conn.clone());
        
        if score > 70 {
            let alert = ThreatAlert {
                timestamp: chrono::Utc::now().timestamp() as u64,
                severity: if score > 90 { "critical".to_string() } else { "high".to_string() },
                message: format!("{} (PID: {}) -> {}:{} [{}]", proc, conn.pid, dst_ip, dst_port, protocol_str),
                connection: Some(conn),
            };
            let _ = state.alerts_tx.send(alert);
        }
    }
}