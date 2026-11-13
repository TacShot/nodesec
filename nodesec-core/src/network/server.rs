//! Network server configuration and types

use crate::models::{MonitorMode, NetworkConnection, Platform};
use anyhow::Result;
use async_trait::async_trait;
use std::collections::VecDeque;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub bind_addr: String,
    pub tls_enabled: bool,
    pub cert_path: Option<String>,
    pub key_path: Option<String>,
    pub max_connections: usize,
    pub heartbeat_interval: u64,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0:8080".to_string(),
            tls_enabled: false,
            cert_path: None,
            key_path: None,
            max_connections: 1000,
            heartbeat_interval: 30,
        }
    }
}

pub struct NetworkServer {
    config: ServerConfig,
    platform: Platform,
    mode: MonitorMode,
}

impl NetworkServer {
    pub fn new(config: ServerConfig) -> Self {
        Self {
            config,
            platform: Platform::detect(),
            mode: MonitorMode::ClientServer,
        }
    }
    
    pub async fn run(&self) -> Result<()> {
        // This would start the WebSocket server
        // Implementation in nodesec-net-server crate
        Ok(())
    }
}

// Remote network monitor that connects to server
pub struct RemoteNetworkMonitor {
    config: ServerConfig,
    events: Arc<Mutex<VecDeque<NetworkConnection>>>,
    platform: Platform,
    mode: MonitorMode,
}

impl RemoteNetworkMonitor {
    pub fn new(config: ServerConfig) -> Self {
        Self {
            config,
            events: Arc::new(Mutex::new(VecDeque::new())),
            platform: Platform::detect(),
            mode: MonitorMode::ClientServer,
        }
    }
}

#[async_trait]
impl crate::network::common::NetworkMonitor for RemoteNetworkMonitor {
    async fn start(&mut self) -> Result<()> {
        // Connect to WebSocket server and start receiving events
        Ok(())
    }
    
    async fn stop(&mut self) -> Result<()> {
        Ok(())
    }
    
    async fn scan_once(&mut self) -> Result<()> {
        // Remote monitor receives events via WebSocket, no local scanning needed
        Ok(())
    }
    
    fn events(&self) -> Arc<Mutex<VecDeque<NetworkConnection>>> {
        self.events.clone()
    }
    
    fn platform(&self) -> Platform {
        self.platform.clone()
    }
    
    fn mode(&self) -> MonitorMode {
        self.mode.clone()
    }
}