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