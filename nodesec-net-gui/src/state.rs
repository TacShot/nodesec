use std::sync::{Arc, Mutex};
use tokio::sync::Mutex as TokioMutex;
use nodesec_core::{
    models::{NetworkConnection, Platform},
    network::{common::NetworkMonitor},
};

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum ThreatLevel {
    Safe,
    Low,
    Medium,
    High,
    Critical,
}

impl ThreatLevel {
    pub fn color(&self) -> egui::Color32 {
        match self {
            ThreatLevel::Safe => egui::Color32::from_rgb(0, 255, 0),
            ThreatLevel::Low => egui::Color32::from_rgb(255, 255, 0),
            ThreatLevel::Medium => egui::Color32::from_rgb(255, 165, 0),
            ThreatLevel::High => egui::Color32::from_rgb(255, 100, 100),
            ThreatLevel::Critical => egui::Color32::from_rgb(255, 0, 0),
        }
    }
    
    pub fn label(&self) -> &'static str {
        match self {
            ThreatLevel::Safe => "SAFE",
            ThreatLevel::Low => "LOW",
            ThreatLevel::Medium => "MED",
            ThreatLevel::High => "HIGH",
            ThreatLevel::Critical => "CRIT",
        }
    }
}

pub fn threat_level_from_score(score: u8) -> ThreatLevel {
    match score {
        0..=25 => ThreatLevel::Safe,
        26..=49 => ThreatLevel::Low,
        50..=74 => ThreatLevel::Medium,
        75..=89 => ThreatLevel::High,
        _ => ThreatLevel::Critical,
    }
}

#[derive(Debug, Clone)]
pub struct ConnectionItem {
    pub connection: NetworkConnection,
    pub threat_level: ThreatLevel,
}

#[derive(Default, Clone)]
pub struct ConnectionStats {
    pub total: usize,
    pub active: usize,
    pub suspicious: usize,
    pub critical: usize,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

/// Process tree item for hierarchical display
#[derive(Debug, Clone)]
pub struct ProcessTreeItem {
    pub pid: u32,
    pub name: String,
    pub path: Option<String>,
    pub user: Option<String>,
    pub connections: Vec<NetworkConnection>,
    pub children: Vec<ProcessTreeItem>,
    pub total_threat_score: u8,
    pub is_suspicious: bool,
}

impl ProcessTreeItem {
    pub fn from_connections(connections: &[ConnectionItem]) -> Vec<ProcessTreeItem> {
        use std::collections::HashMap;
        
        let mut process_map: HashMap<u32, ProcessTreeItem> = HashMap::new();
        
        for item in connections {
            let conn = &item.connection;
            let entry = process_map.entry(conn.pid).or_insert_with(|| ProcessTreeItem {
                pid: conn.pid,
                name: conn.process_name.clone(),
                path: conn.process_path.clone(),
                user: conn.user.clone(),
                connections: Vec::new(),
                children: Vec::new(),
                total_threat_score: 0,
                is_suspicious: false,
            });
            
            entry.connections.push(conn.clone());
            entry.total_threat_score = entry.total_threat_score.max(conn.threat_score);
            entry.is_suspicious = entry.is_suspicious || conn.is_suspicious;
        }
        
        // Sort by threat score descending
        let mut processes: Vec<ProcessTreeItem> = process_map.into_values().collect();
        processes.sort_by(|a, b| b.total_threat_score.cmp(&a.total_threat_score));
        processes
    }
}

pub struct MonitorState {
    pub connections: Arc<Mutex<Vec<ConnectionItem>>>,
    pub alerts: Arc<Mutex<Vec<String>>>,
    pub stats: Arc<Mutex<ConnectionStats>>,
    pub monitor: Arc<tokio::sync::Mutex<Option<Box<dyn nodesec_core::network::common::NetworkMonitor + Send>>>>,
    pub monitoring: Arc<Mutex<bool>>,
    pub platform: Platform,
}

impl MonitorState {
    pub fn new(platform: Platform) -> Self {
        Self {
            connections: Arc::new(Mutex::new(Vec::new())),
            alerts: Arc::new(Mutex::new(Vec::new())),
            stats: Arc::new(Mutex::new(ConnectionStats::default())),
            monitor: Arc::new(tokio::sync::Mutex::new(None)),
            monitoring: Arc::new(Mutex::new(false)),
            platform: Platform::detect(),
        }
    }
}