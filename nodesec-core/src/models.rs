use rand::random;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use crate::command_runner::CommandRunner;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum NetworkProtocol {
    Tcp,
    Udp,
    Icmp,
    Other(u8),
}

impl From<u8> for NetworkProtocol {
    fn from(v: u8) -> Self {
        match v {
            6 => NetworkProtocol::Tcp,
            17 => NetworkProtocol::Udp,
            1 => NetworkProtocol::Icmp,
            _ => NetworkProtocol::Other(v),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConnection {
    pub pid: u32,
    pub src_ip: std::net::IpAddr,
    pub dst_ip: std::net::IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: NetworkProtocol,
    pub process_name: String,
    pub process_path: Option<String>,
    pub command_line: Option<String>,
    pub user: Option<String>,
    pub timestamp: u64,
    pub threat_score: u8,
    pub is_suspicious: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Platform {
    Linux,
    MacOS,
    Windows,
    Unknown,
}

impl Platform {
    pub fn detect() -> Self {
        match std::env::consts::OS {
            "linux" => Platform::Linux,
            "macos" => Platform::MacOS,
            "windows" => Platform::Windows,
            _ => Platform::Unknown,
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "linux" => Some(Platform::Linux),
            "macos" | "darwin" => Some(Platform::MacOS),
            "windows" => Some(Platform::Windows),
            "auto" => Some(Platform::detect()),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum CheckStatus {
    Pass,
    Fail,
    Skip,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveQuery {
    pub keyword: String,
    pub product_hint: Option<String>,
}

pub type CheckFn = fn(&CommandRunner) -> std::result::Result<CheckResult, anyhow::Error>;

#[derive(Debug, Clone)]
pub struct AuditRule {
    pub id: String,
    pub platform: Platform,
    pub title: String,
    pub description: String,
    pub rationale: String,
    pub severity: Severity,
    pub remediation: Vec<String>,
    pub cve_queries: Vec<CveQuery>,
    pub standards: Vec<String>,
    pub check: CheckFn,
}

// Manual serde for AuditRule since it contains a function pointer
impl Serialize for AuditRule {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("AuditRule", 10)?;
        state.serialize_field("id", &self.id)?;
        state.serialize_field("platform", &self.platform)?;
        state.serialize_field("title", &self.title)?;
        state.serialize_field("description", &self.description)?;
        state.serialize_field("rationale", &self.rationale)?;
        state.serialize_field("severity", &self.severity)?;
        state.serialize_field("remediation", &self.remediation)?;
        state.serialize_field("cve_queries", &self.cve_queries)?;
        state.serialize_field("standards", &self.standards)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for AuditRule {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct AuditRuleData {
            id: String,
            platform: Platform,
            title: String,
            description: String,
            rationale: String,
            severity: Severity,
            remediation: Vec<String>,
            cve_queries: Vec<CveQuery>,
            standards: Vec<String>,
        }

        let data = AuditRuleData::deserialize(deserializer)?;
        // Note: check function cannot be deserialized, will be set by get_rules()
        Ok(AuditRule {
            id: data.id,
            platform: data.platform,
            title: data.title,
            description: data.description,
            rationale: data.rationale,
            severity: data.severity,
            remediation: data.remediation,
            cve_queries: data.cve_queries,
            standards: data.standards,
            check: |_| Ok(CheckResult {
                rule_id: String::new(),
                status: CheckStatus::Skip,
                details: "Deserialized rule - check function not available".to_string(),
                observed_value: None,
                remediation: vec![],
                related_cves: vec![],
            }),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckResult {
    pub rule_id: String,
    pub status: CheckStatus,
    pub details: String,
    pub observed_value: Option<String>,
    pub remediation: Vec<String>,
    pub related_cves: Vec<CveInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveInfo {
    pub id: Option<String>,
    pub published: Option<String>,
    pub last_modified: Option<String>,
    pub severity: Option<String>,
    pub score: Option<f32>,
    pub description: String,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandResult {
    pub returncode: i32,
    pub stdout: String,
    pub stderr: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstalledApplication {
    pub name: String,
    pub version: String,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplicationFinding {
    pub application: InstalledApplication,
    pub cpe_name: Option<String>,
    pub cves: Vec<CveInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsInfo {
    pub name: String,
    pub version: String,
    pub architecture: Option<String>,
    pub build: Option<String>,
    pub kernel: Option<String>,
    pub security_patches: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriverInfo {
    pub name: String,
    pub provider: String,
    pub signer: Option<String>,
    pub sign_type: String,
    pub is_signed: bool,
    pub is_suspicious: bool,
    pub is_dangerous: bool,
    pub inf_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunningProcess {
    pub pid: u32,
    pub name: String,
    pub executable: Option<String>,
    pub command_line: Option<String>,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessFinding {
    pub process: RunningProcess,
    pub severity: Severity,
    pub reasons: Vec<String>,
    pub recommended_action: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditReport {
    pub id: Uuid,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub target_platform: Platform,
    pub os_info: OsInfo,
    pub results: Vec<(AuditRule, CheckResult)>,
    pub summary: AuditSummary,
    pub application_findings: Vec<ApplicationFinding>,
    pub scanned_applications: Vec<InstalledApplication>,
    pub scanned_processes: Vec<RunningProcess>,
    pub process_findings: Vec<ProcessFinding>,
    pub system_logs: Vec<LogEntry>,
    pub ad_findings: Vec<AdFinding>,
    pub network_connections: Vec<NetworkConnection>,
    pub remediation_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditSummary {
    pub passed: usize,
    pub failed: usize,
    pub skipped: usize,
}

impl AuditSummary {
    pub fn from_results(results: &[(AuditRule, CheckResult)]) -> Self {
        let mut passed = 0;
        let mut failed = 0;
        let mut skipped = 0;
        for (_, result) in results {
            match result.status {
                CheckStatus::Pass => passed += 1,
                CheckStatus::Fail => failed += 1,
                CheckStatus::Skip => skipped += 1,
            }
        }
        Self { passed, failed, skipped }
    }
}

impl Default for AuditSummary {
    fn default() -> Self {
        Self { passed: 0, failed: 0, skipped: 0 }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceStandard {
    pub name: String,
    pub rules: Vec<String>,
}

impl Default for ComplianceStandard {
    fn default() -> Self {
        Self { name: "general".to_string(), rules: vec![] }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub source: String,
    pub level: String,
    pub message: String,
    pub unit: Option<String>,
    pub pid: Option<u32>,
    pub user: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdFinding {
    pub finding_type: String,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub target: String,
    pub details: String,
    pub remediation: Vec<String>,
}

// Network monitoring types
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum MonitorMode {
    OnDevice,
    ClientServer,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
pub enum WSMessage {
    ConnectionEvent(NetworkConnection),
    ThreatAlert(ThreatAlert),
    RuleUpdate(RuleSet),
    AgentStatus(AgentInfo),
    Heartbeat,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentInfo {
    pub id: String,
    pub name: String,
    pub platform: Platform,
    pub connected_at: u64,
    pub last_seen: u64,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RuleSet {
    pub builtin_rules: Vec<DetectionRule>,
    pub custom_rules: Vec<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionRule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub severity: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatAlert {
    pub timestamp: u64,
    pub severity: String,
    pub message: String,
    pub connection: Option<NetworkConnection>,
}

// Connected device tracking (USB, Bluetooth, Thunderbolt, etc.)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DeviceType {
    Usb,
    Bluetooth,
    BluetoothLe,
    Thunderbolt,
    FireWire,
    SdCard,
    Other(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectedDevice {
    pub id: String,
    pub name: String,
    pub device_type: DeviceType,
    pub vendor: Option<String>,
    pub product_id: Option<String>,
    pub vendor_id: Option<String>,
    pub serial_number: Option<String>,
    pub connected_at: u64,
    pub last_seen: u64,
    pub is_connected: bool,
}


/// Rule for excluding specific applications from network monitoring.
/// When a connection matches an exclusion rule, it is not collected or reported.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExclusionRule {
    pub id: String,
    pub process_name: Option<String>,
    pub process_path: Option<String>,
    pub pid: Option<u32>,
    pub reason: String,
    pub enabled: bool,
    pub created_at: u64,
}

impl ExclusionRule {
    pub fn new(process_name: Option<String>, process_path: Option<String>, pid: Option<u32>, reason: String) -> Self {
        Self {
            id: format!("excl-{}-{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs(), 
                      rand::random::<u32>()),
            process_name,
            process_path,
            pid,
            reason,
            enabled: true,
            created_at: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs(),
        }
    }

    /// Check if a NetworkConnection matches this exclusion rule.
    pub fn matches(&self, conn: &crate::network::common::NetworkConnection) -> bool {
        if !self.enabled {
            return false;
        }

        // Match by PID (exact match)
        if let Some(pid) = self.pid {
            if conn.pid == pid {
                return true;
            }
        }

        // Match by process name (case-insensitive contains)
        if let Some(ref name) = self.process_name {
            let name_lower = name.to_lowercase();
            if conn.process_name.to_lowercase().contains(&name_lower) {
                return true;
            }
        }

        // Match by process path (case-insensitive contains)
        if let Some(ref path) = self.process_path {
            if let Some(ref conn_path) = conn.process_path {
                let path_lower = path.to_lowercase();
                if conn_path.to_lowercase().contains(&path_lower) {
                    return true;
                }
            }
        }

        false
    }
}

/// Collection of exclusion rules with persistence support.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExclusionList {
    pub rules: Vec<ExclusionRule>,
}

impl ExclusionList {
    pub fn add(&mut self, rule: ExclusionRule) {
        // Remove existing rule with same process_name+process_path+pid combo if exists
        self.rules.retain(|r| {
            !(r.process_name == rule.process_name && r.process_path == rule.process_path && r.pid == rule.pid)
        });
        self.rules.push(rule);
    }

    pub fn remove(&mut self, id: &str) {
        self.rules.retain(|r| r.id != id);
    }

    pub fn toggle(&mut self, id: &str) {
        if let Some(rule) = self.rules.iter_mut().find(|r| r.id == id) {
            rule.enabled = !rule.enabled;
        }
    }

    pub fn is_excluded(&self, conn: &crate::network::common::NetworkConnection) -> bool {
        self.rules.iter().any(|r| r.matches(conn))
    }
}

/// Known crypto miner process names and patterns for detection.
/// Users can customize this list via the GUI or config file.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CryptoMinerRulebook {
    pub enabled: bool,
    pub process_names: Vec<String>,
    pub process_paths: Vec<String>,
    pub custom_rules: Vec<String>,
    pub threat_score: u8,
}

impl CryptoMinerRulebook {
    pub fn new() -> Self {
        Self {
            enabled: true,
            process_names: vec![
                "xmrig".to_string(),
                "xmr-stak".to_string(),
                "minerd".to_string(),
                "cgminer".to_string(),
                "bfgminer".to_string(),
                "cpuminer".to_string(),
                "ccminer".to_string(),
                "claymore".to_string(),
                "ethminer".to_string(),
                "phoenixminer".to_string(),
                "lolminer".to_string(),
                "teamredminer".to_string(),
                "nbminer".to_string(),
                "gminer".to_string(),
                "t-rex".to_string(),
                "nanominer".to_string(),
                "srbbminer".to_string(),
                "xmrrig".to_string(),
                "xmrigproxy".to_string(),
                "xmrigdaemon".to_string(),
            ],
            process_paths: vec![],
            custom_rules: vec![],
            threat_score: 85,
        }
    }

    /// Check if a process name matches any known crypto miner pattern
    pub fn is_crypto_miner(&self, process_name: &str) -> bool {
        if !self.enabled {
            return false;
        }

        let name_lower = process_name.to_lowercase();

        // Exact and contains matching for known miner names
        if self.process_names.iter().any(|known| {
            name_lower.contains(&known.to_lowercase())
        }) {
            return true;
        }

        // Custom rule matching (substring)
        for rule in &self.custom_rules {
            if !rule.is_empty() && name_lower.contains(&rule.to_lowercase()) {
                return true;
            }
        }

        false
    }

    /// Check if a process path matches any known crypto miner path pattern
    pub fn is_suspicious_path(&self, process_path: Option<&str>) -> bool {
        if !self.enabled {
            return false;
        }

        if let Some(path) = process_path {
            let path_lower = path.to_lowercase();
            // Common suspicious locations for miners
            let suspicious_dirs = [
                "/tmp/",
                "/var/tmp/",
                "/dev/shm/",
                "/app/",
                "\\temp\\",
                "\\tmp\\",
                "appdata\\local\\temp",
            ];
            if suspicious_dirs.iter().any(|dir| path_lower.contains(dir)) {
                return true;
            }
        }

        false
    }
}