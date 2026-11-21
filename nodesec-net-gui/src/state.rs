use std::sync::{Arc, Mutex};
use tokio::sync::Mutex as TokioMutex;
use nodesec_core::models::{ExclusionList, NetworkConnection, Platform};
use nodesec_core::threat::ThreatDetector;
use std::collections::VecDeque;

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

    pub fn from_score(score: u8) -> Self {
        match score {
            0..=25 => ThreatLevel::Safe,
            26..=49 => ThreatLevel::Low,
            50..=74 => ThreatLevel::Medium,
            75..=89 => ThreatLevel::High,
            _ => ThreatLevel::Critical,
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

        let mut process_map: HashMap<String, ProcessTreeItem> = HashMap::new();

        for item in connections {
            let conn = &item.connection;

            // For unknown PIDs (0), use a unique key per connection so they don't
            // all collapse into a single "unknown" entry. For known PIDs, group by PID.
            let map_key = if conn.pid == 0 && conn.process_name == "unknown" {
                format!("unknown:{}:{}", conn.src_port, conn.dst_port)
            } else {
                conn.pid.to_string()
            };

            let entry = process_map.entry(map_key.clone()).or_insert_with(|| {
                let display_name = if conn.pid == 0 && conn.process_name == "unknown" {
                    format!("unknown (port {})", conn.src_port)
                } else {
                    conn.process_name.clone()
                };
                ProcessTreeItem {
                    pid: conn.pid,
                    name: display_name,
                    path: conn.process_path.clone(),
                    user: conn.user.clone(),
                    connections: Vec::new(),
                    children: Vec::new(),
                    total_threat_score: 0,
                    is_suspicious: false,
                }
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

/// Filter settings for connections
#[derive(Debug, Clone, Default)]
pub struct FilterSettings {
    pub process_name: String,
    pub pid: Option<u32>,
    pub connection_type: Option<crate::graph::ConnectionType>,
    pub interface: String,
    pub min_threat_score: u8,
    pub max_threat_score: u8,
    pub only_suspicious: bool,
    pub protocol: Option<nodesec_core::models::NetworkProtocol>,
}

impl FilterSettings {
    pub fn matches(&self, item: &ConnectionItem) -> bool {
        let conn = &item.connection;
        
        if !self.process_name.is_empty() {
            if !conn.process_name.to_lowercase().contains(&self.process_name.to_lowercase()) {
                return false;
            }
        }
        
        if let Some(pid) = self.pid {
            if conn.pid != pid {
                return false;
            }
        }
        
        if let Some(proto) = &self.protocol {
            if conn.protocol != *proto {
                return false;
            }
        }
        
        if self.only_suspicious && !conn.is_suspicious {
            return false;
        }
        
        if conn.threat_score < self.min_threat_score || conn.threat_score > self.max_threat_score {
            return false;
        }
        
        true
    }
}

/// Action log entry for firewall/terminate actions
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ActionLogEntry {
    pub timestamp: String,
    pub action: ActionType,
    pub pid: u32,
    pub process_name: String,
    pub port: Option<u16>,
    pub ip: Option<String>,
    pub rule: String,
    pub success: bool,
    pub details: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum ActionType {
    Terminate,
    BlockPort,
    BlockIP,
    AllowPort,
    AllowIP,
    AddFirewallRule,
    RemoveFirewallRule,
    ScanDurationChange,
    IgnoreRuleAdd,
    IgnoreRuleRemove,
}

/// Structured alert entry with actionable data
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AlertEntry {
    pub timestamp: String,
    pub process_name: String,
    pub dst_ip: String,
    pub dst_port: u16,
    pub pid: u32,
    pub threat_score: u8,
    pub is_suspicious: bool,
    pub dismissed: bool,
}

/// Ignore rule for connections
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IgnoreRule {
    pub id: String,
    pub process_name: Option<String>,
    pub process_path: Option<String>,
    pub pid: Option<u32>,
    pub port: Option<u16>,
    pub ip: Option<String>,
    pub protocol: Option<nodesec_core::models::NetworkProtocol>,
    pub created: String,
    pub description: String,
}

impl IgnoreRule {
    pub fn matches(&self, conn: &NetworkConnection) -> bool {
        if let Some(name) = &self.process_name {
            if !conn.process_name.contains(name) {
                return false;
            }
        }
        if let Some(path) = &self.process_path {
            let conn_path = conn.process_path.as_deref().unwrap_or("");
            if !conn_path.contains(path) {
                return false;
            }
        }
        if let Some(pid) = self.pid {
            if conn.pid != pid {
                return false;
            }
        }
        if let Some(port) = self.port {
            if conn.dst_port != port && conn.src_port != port {
                return false;
            }
        }
        if let Some(ip) = &self.ip {
            if conn.dst_ip.to_string() != *ip && conn.src_ip.to_string() != *ip {
                return false;
            }
        }
        if let Some(proto) = &self.protocol {
            if conn.protocol != *proto {
                return false;
            }
        }
        true
    }
}

/// Scan settings
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ScanSettings {
    pub scan_interval_seconds: u64,
    pub max_connections: usize,
    pub retention_seconds: u64,
    pub threat_threshold: u8,
    pub ignore_rules: Vec<IgnoreRule>,
    pub auto_refresh: bool,
}

impl Default for ScanSettings {
    fn default() -> Self {
        Self {
            scan_interval_seconds: 2,
            max_connections: 1000,
            retention_seconds: 300,
            threat_threshold: 50,
            ignore_rules: Vec::new(),
            auto_refresh: true,
        }
    }
}


/// Audit scan state for persistence
#[derive(Debug, Clone, Default)]
pub struct AuditState {
    pub is_scanning: bool,
    pub scan_complete: bool,
    pub compliance_cis: bool,
    pub compliance_nist: bool,
    pub compliance_pci_dss: bool,
    pub compliance_iso_27001: bool,
    pub compliance_iso_27005: bool,
    pub scan_applications: bool,
    pub scan_ad_security: bool,
    pub scan_devices: bool,
    pub enable_nvd: bool,
    pub last_scan_time: Option<String>,
    pub findings_count: usize,
    pub suspicious_count: usize,
    pub critical_count: usize,
    pub audit_results: String,
    pub selected_report: Option<String>,
}

pub struct MonitorState {
    pub connections: Arc<Mutex<Vec<ConnectionItem>>>,
    pub alerts: Arc<Mutex<Vec<AlertEntry>>>,
    pub stats: Arc<Mutex<ConnectionStats>>,
    pub monitor: Arc<TokioMutex<Option<Box<dyn nodesec_core::network::common::NetworkMonitor + Send>>>>,
    pub monitoring: Arc<Mutex<bool>>,
    pub platform: Platform,
    pub filter: Arc<Mutex<FilterSettings>>,
    pub action_log: Arc<Mutex<VecDeque<ActionLogEntry>>>,
    pub scan_settings: Arc<Mutex<ScanSettings>>,
    pub threat_detector: Arc<Mutex<ThreatDetector>>,
    pub audit_state: Arc<Mutex<AuditState>>,
    pub connected_devices: Arc<Mutex<Vec<nodesec_core::models::ConnectedDevice>>>,
    pub exclusion_list: Arc<Mutex<nodesec_core::models::ExclusionList>>,
    pub crypto_miner_rulebook: Arc<Mutex<nodesec_core::models::CryptoMinerRulebook>>,
    pub root_status: Arc<Mutex<RootStatus>>,
    pub terminated_pids: Arc<Mutex<std::collections::HashSet<u32>>>,
}

/// Root privilege status
#[derive(Debug, Clone, PartialEq)]
pub enum RootStatus {
    Unknown,
    Off,
    On,
    Requesting,
}

impl Default for RootStatus {
    fn default() -> Self {
        Self::Unknown
    }
}

impl MonitorState {
    pub fn new(_platform: Platform) -> Self {
        Self {
            connections: Arc::new(Mutex::new(Vec::new())),
            alerts: Arc::new(Mutex::new(Vec::new())),
            stats: Arc::new(Mutex::new(ConnectionStats::default())),
            monitor: Arc::new(TokioMutex::new(None)),
            monitoring: Arc::new(Mutex::new(false)),
            platform: Platform::detect(),
            filter: Arc::new(Mutex::new(FilterSettings::default())),
            action_log: Arc::new(Mutex::new(VecDeque::with_capacity(1000))),
            scan_settings: Arc::new(Mutex::new(ScanSettings::default())),
            threat_detector: Arc::new(Mutex::new(ThreatDetector::new())),
            audit_state: Arc::new(Mutex::new(AuditState::default())),
            connected_devices: Arc::new(Mutex::new(Vec::new())),
            exclusion_list: Arc::new(Mutex::new(nodesec_core::models::ExclusionList::default())),
            crypto_miner_rulebook: Arc::new(Mutex::new(nodesec_core::models::CryptoMinerRulebook::new())),
            root_status: Arc::new(Mutex::new(RootStatus::default())),
            terminated_pids: Arc::new(Mutex::new(std::collections::HashSet::new())),
        }
    }
    
    pub fn add_action_log(&self, entry: ActionLogEntry) {
        let mut log = self.action_log.lock().unwrap();
        log.push_front(entry);
        if log.len() > 1000 {
            log.pop_back();
        }
    }
    
    pub fn add_ignore_rule(&self, rule: IgnoreRule) {
        let mut settings = self.scan_settings.lock().unwrap();
        settings.ignore_rules.push(rule);
    }
    
    pub fn remove_ignore_rule(&self, rule_id: &str) {
        let mut settings = self.scan_settings.lock().unwrap();
        settings.ignore_rules.retain(|r| r.id != rule_id);
    }
    
    pub fn should_ignore(&self, conn: &NetworkConnection) -> bool {
        let settings = self.scan_settings.lock().unwrap();
        settings.ignore_rules.iter().any(|r| r.matches(conn))
    }

    pub fn add_alert(&self, entry: AlertEntry) {
        let mut alerts = self.alerts.lock().unwrap();
        alerts.insert(0, entry);
        if alerts.len() > 100 {
            alerts.pop();
        }
    }

    pub fn dismiss_alert(&self, index: usize) {
        let mut alerts = self.alerts.lock().unwrap();
        if index < alerts.len() {
            alerts[index].dismissed = true;
        }
    }

    pub fn terminate_alert_process(&self, index: usize) {
        let alerts = self.alerts.lock().unwrap();
        if let Some(alert) = alerts.get(index) {
            crate::monitor::terminate_process(alert.pid, &alert.process_name, self);
        }
    }

    pub fn block_alert_ip(&self, index: usize) {
        let alerts = self.alerts.lock().unwrap();
        if let Some(alert) = alerts.get(index) {
            crate::monitor::block_ip(&alert.dst_ip, alert.pid, &alert.process_name, self);
        }
    }

    pub fn block_alert_port(&self, index: usize) {
        let alerts = self.alerts.lock().unwrap();
        if let Some(alert) = alerts.get(index) {
            crate::monitor::block_port(alert.dst_port, alert.pid, &alert.process_name, self);
        }
    }
}