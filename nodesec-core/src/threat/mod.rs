//! Threat detection engine with rule-based and ML-based analysis

use crate::models::{NetworkConnection, NetworkProtocol};
use anyhow::Result;
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct ThreatDetector {
    // Rule-based detection
    safe_ports: HashMap<u16, String>,
    suspicious_ports: HashMap<u16, String>,
    known_malicious_ips: HashMap<String, String>,
    
    // Tracking for behavioral analysis
    ip_frequency: HashMap<String, u64>,
    process_connection_history: HashMap<u32, VecDeque<ProcessConnection>>,
    process_first_seen: HashMap<u32, u64>,
    
    // Statistics
    total_analyzed: u64,
    suspicious_detected: u64,
    
    // ML anomaly detection (simplified)
    connection_features: Vec<Vec<f64>>,
    anomaly_threshold: f64,
}

#[derive(Debug, Clone)]
struct ProcessConnection {
    timestamp: u64,
    dst_ip: String,
    dst_port: u16,
    protocol: NetworkProtocol,
}

impl ThreatDetector {
    pub fn new() -> Self {
        let mut safe_ports = HashMap::new();
        safe_ports.insert(80, "HTTP".to_string());
        safe_ports.insert(443, "HTTPS".to_string());
        safe_ports.insert(22, "SSH".to_string());
        safe_ports.insert(53, "DNS".to_string());
        safe_ports.insert(25, "SMTP".to_string());
        safe_ports.insert(587, "SMTP".to_string());
        safe_ports.insert(993, "IMAPS".to_string());
        safe_ports.insert(995, "POP3S".to_string());
        safe_ports.insert(143, "IMAP".to_string());
        safe_ports.insert(110, "POP3".to_string());
        safe_ports.insert(21, "FTP".to_string());
        safe_ports.insert(8080, "HTTP-Alt".to_string());
        safe_ports.insert(8443, "HTTPS-Alt".to_string());
        safe_ports.insert(3306, "MySQL".to_string());
        safe_ports.insert(5432, "PostgreSQL".to_string());
        safe_ports.insert(6379, "Redis".to_string());
        safe_ports.insert(27017, "MongoDB".to_string());

        let mut suspicious_ports = HashMap::new();
        suspicious_ports.insert(1337, "Common backdoor".to_string());
        suspicious_ports.insert(31337, "Back Orifice".to_string());
        suspicious_ports.insert(4444, "Metasploit".to_string());
        suspicious_ports.insert(5555, "Common malware".to_string());
        suspicious_ports.insert(6666, "IRC bot".to_string());
        suspicious_ports.insert(6667, "IRC".to_string());
        suspicious_ports.insert(12345, "NetBus".to_string());
        suspicious_ports.insert(54321, "Back Orifice".to_string());
        suspicious_ports.insert(1234, "Ultors Trojan".to_string());
        suspicious_ports.insert(4343, "Common malware".to_string());

        // Known malicious IPs (placeholder - would load from threat intel feeds)
        let mut known_malicious_ips = HashMap::new();
        // These would be populated from threat intelligence feeds

        Self {
            safe_ports,
            suspicious_ports,
            known_malicious_ips,
            ip_frequency: HashMap::new(),
            process_connection_history: HashMap::new(),
            process_first_seen: HashMap::new(),
            total_analyzed: 0,
            suspicious_detected: 0,
            connection_features: Vec::new(),
            anomaly_threshold: 0.7,
        }
    }

    /// Analyze a network connection and return threat score (0-100)
    pub fn analyze(&mut self, conn: &NetworkConnection) -> u8 {
        self.total_analyzed += 1;
        let mut score = 0u16;

        // Update tracking
        let dst_ip_str = conn.dst_ip.to_string();
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

        *self.ip_frequency.entry(dst_ip_str.clone()).or_insert(0) += 1;

        let history = self.process_connection_history.entry(conn.pid).or_insert_with(VecDeque::new);
        history.push_back(ProcessConnection {
            timestamp: now,
            dst_ip: dst_ip_str.clone(),
            dst_port: conn.dst_port,
            protocol: conn.protocol.clone(),
        });

        // Keep only last 100 connections per process
        while history.len() > 100 {
            history.pop_front();
        }

        // Track first seen
        self.process_first_seen.entry(conn.pid).or_insert(now);

        // Apply detection rules
        score += self.check_destination_rarity(conn);
        score += self.check_connection_frequency(conn);
        score += self.check_suspicious_ports(conn);
        score += self.check_unusual_timing(conn);
        score += self.check_first_time_process(conn);
        score += self.check_process_anomalies(conn);
        score += self.check_connection_patterns(conn);
        score += self.check_known_malicious_indicators(conn);

        // ML-based anomaly detection
        let ml_score = self.ml_anomaly_detection(conn);
        score = score.max((ml_score * 50.0) as u16);

        // Cap at 100
        let final_score = score.min(100) as u8;

        if final_score >= 50 {
            self.suspicious_detected += 1;
        }

        final_score
    }

    fn check_destination_rarity(&self, conn: &NetworkConnection) -> u16 {
        let total = self.total_analyzed;
        if total < 10 {
            return 0;
        }

        let ip_count = *self.ip_frequency.get(&conn.dst_ip.to_string()).unwrap_or(&0) as f64;
        let frequency = ip_count / total as f64;

        if frequency < 0.001 {
            20 // Very rare (< 0.1%)
        } else if frequency < 0.005 {
            10 // Uncommon (< 0.5%)
        } else if frequency < 0.01 {
            5 // Slightly uncommon (< 1%)
        } else {
            0
        }
    }

    fn check_connection_frequency(&self, conn: &NetworkConnection) -> u16 {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let history = self.process_connection_history.get(&conn.pid);

        if let Some(history) = history {
            let recent: Vec<_> = history.iter()
                .filter(|c| now.saturating_sub(c.timestamp) <= 60)
                .collect();

            let rate = recent.len();

            // High frequency scoring
            let freq_score = if rate > 100 {
                25
            } else if rate > 50 {
                15
            } else if rate > 20 {
                10
            } else if rate > 10 {
                5
            } else {
                0
            };

            // Check for connection bursts to same destination
            let mut dst_counts = HashMap::new();
            for c in &recent {
                *dst_counts.entry(c.dst_ip.clone()).or_insert(0) += 1;
            }
            let max_dst = dst_counts.values().max().copied().unwrap_or(0);

            let burst_score = if max_dst > 20 { 15 } else { 0 };

            freq_score + burst_score
        } else {
            0
        }
    }

    fn check_suspicious_ports(&self, conn: &NetworkConnection) -> u16 {
        let mut score = 0;

        // Known suspicious ports
        if self.suspicious_ports.contains_key(&conn.dst_port) {
            score += 30;
        }

        // High ports (> 49152) that aren't known safe
        if conn.dst_port > 49152 && !self.safe_ports.contains_key(&conn.dst_port) {
            score += 10;
        }

        // Non-standard service ports (< 1024)
        if conn.dst_port < 1024 && !self.safe_ports.contains_key(&conn.dst_port) {
            score += 15;
        }

        score
    }

    fn check_unusual_timing(&self, conn: &NetworkConnection) -> u16 {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let dt = chrono::DateTime::<chrono::Utc>::from_timestamp(now as i64, 0).unwrap();
        let hour = dt.hour();
        let weekday = dt.weekday();

        let mut score = 0;

        // Late night connections (2 AM - 6 AM)
        if (2..=6).contains(&hour) {
            score += 10;
        }

        // Weekend connections to unusual ports
        if weekday == chrono::Weekday::Sat || weekday == chrono::Weekday::Sun {
            if !self.safe_ports.contains_key(&conn.dst_port) {
                score += 5;
            }
        }

        score
    }

    fn check_first_time_process(&self, conn: &NetworkConnection) -> u16 {
        if self.process_first_seen.contains_key(&conn.pid) {
            return 0;
        }

        // Check if it's a system process making first connection
        let process_name = conn.process_name.to_lowercase();
        let system_processes = ["systemd", "kernel", "init", "kthreadd", "launchd", "svchost.exe", "services.exe", "lsass.exe"];

        if system_processes.iter().any(|s| process_name.contains(s)) {
            30 // System processes shouldn't make network connections
        } else {
            15 // First connection is moderately suspicious
        }
    }

    fn check_process_anomalies(&self, conn: &NetworkConnection) -> u16 {
        let mut score = 0;
        let process_name = conn.process_name.to_lowercase();
        let cmdline = conn.command_line.as_deref().unwrap_or("").to_lowercase();
        let exe_path = conn.process_path.as_deref().unwrap_or("").to_lowercase();

        // Suspicious process names
        let suspicious_names = ["nc", "ncat", "netcat", "python", "perl", "bash", "sh", "powershell", "cmd", "wscript", "cscript", "mshta", "regsvr32", "rundll32"];
        if suspicious_names.iter().any(|s| process_name.contains(s)) {
            score += 20;
        }

        // Suspicious command line arguments
        let suspicious_args = ["-e", "--execute", "/bin/sh", "/bin/bash", "reverse", "shell", "base64", "-enc", "download", "iex", "invoke-expression"];
        if suspicious_args.iter().any(|s| cmdline.contains(s)) {
            score += 25;
        }

        // Executable in temp directory
        if exe_path.contains("/tmp/") || exe_path.contains("/var/tmp/") || exe_path.contains("\\temp\\") || exe_path.contains("\\appdata\\local\\temp\\") {
            score += 30;
        }

        // Hidden executable (starts with .)
        if exe_path.starts_with("/.") || exe_path.contains("/.") {
            score += 20;
        }

        score
    }

    fn check_connection_patterns(&self, conn: &NetworkConnection) -> u16 {
        let mut score = 0;
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

        if let Some(history) = self.process_connection_history.get(&conn.pid) {
            // Check unique destinations
            let unique_dsts: std::collections::HashSet<_> = history.iter().map(|c| &c.dst_ip).collect();
            if unique_dsts.len() > 50 {
                score += 15;
            } else if unique_dsts.len() > 20 {
                score += 10;
            } else if unique_dsts.len() > 10 {
                score += 5;
            }

            // Check for port scanning (sequential ports in short time)
            let recent_ports: Vec<u16> = history.iter()
                .filter(|c| now.saturating_sub(c.timestamp) <= 30)
                .map(|c| c.dst_port)
                .collect();

            if recent_ports.len() >= 5 {
                let mut sorted_ports = recent_ports.clone();
                sorted_ports.sort();
                sorted_ports.dedup();

                let mut sequential = 1;
                let mut max_sequential = 1;
                for i in 1..sorted_ports.len() {
                    if sorted_ports[i] == sorted_ports[i-1] + 1 {
                        sequential += 1;
                        max_sequential = max_sequential.max(sequential);
                    } else {
                        sequential = 1;
                    }
                }

                if max_sequential >= 5 {
                    score += 20; // Likely port scanning
                }
            }
        }

        score
    }

    fn check_known_malicious_indicators(&self, conn: &NetworkConnection) -> u16 {
        let mut score = 0;
        let dst_ip_str = conn.dst_ip.to_string();

        // Check against known malicious IPs
        if self.known_malicious_ips.contains_key(&dst_ip_str) {
            score += 40;
        }

        // Check for private IPs (less suspicious for internal connections)
        if conn.dst_ip.is_loopback() || conn.dst_ip.is_private() || conn.dst_ip.is_link_local() {
            score = score.saturating_sub(10); // Reduce score for internal
        }

        score
    }

    fn ml_anomaly_detection(&mut self, conn: &NetworkConnection) -> f64 {
        // Simplified isolation forest-like anomaly detection
        // In production, use linfa or smartcore for actual ML
        
        let features = self.extract_features(conn);
        
        if self.connection_features.len() < 100 {
            // Not enough training data yet
            self.connection_features.push(features);
            return 0.0;
        }

        // Simple statistical anomaly detection
        let mean = self.calculate_mean(&self.connection_features);
        let std = self.calculate_std(&self.connection_features, &mean);
        
        let mut anomaly_score = 0.0;
        for (i, &feat) in features.iter().enumerate() {
            if i < mean.len() && std[i] > 0.0 {
                let z_score = ((feat - mean[i]) / std[i]).abs();
                anomaly_score += z_score;
            }
        }
        
        anomaly_score = anomaly_score / features.len() as f64;
        
        // Add to training set
        self.connection_features.push(features);
        if self.connection_features.len() > 10000 {
            self.connection_features = self.connection_features.split_off(5000);
        }
        
        // Normalize to 0-1
        (anomaly_score / 5.0).min(1.0)
    }

    fn extract_features(&self, conn: &NetworkConnection) -> Vec<f64> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let dt = chrono::DateTime::<chrono::Utc>::from_timestamp(now as i64, 0).unwrap();

        vec![
            conn.dst_port as f64 / 65535.0,
            conn.src_port as f64 / 65535.0,
            if conn.dst_ip.is_private() { 1.0 } else { 0.0 },
            if self.safe_ports.contains_key(&conn.dst_port) { 1.0 } else { 0.0 },
            conn.process_name.len() as f64 / 50.0,
            conn.command_line.as_deref().unwrap_or("").len() as f64 / 200.0,
            dt.hour() as f64 / 24.0,
            dt.weekday() as u8 as f64 / 7.0,
        ]
    }

    fn calculate_mean(&self, data: &[Vec<f64>]) -> Vec<f64> {
        if data.is_empty() {
            return vec![0.0; 8];
        }
        let n = data.len() as f64;
        let mut mean = vec![0.0; 8];
        for row in data {
            for (i, &val) in row.iter().enumerate() {
                if i < 8 {
                    mean[i] += val;
                }
            }
        }
        for v in &mut mean {
            *v /= n;
        }
        mean
    }

    fn calculate_std(&self, data: &[Vec<f64>], mean: &[f64]) -> Vec<f64> {
        if data.is_empty() {
            return vec![1.0; 8];
        }
        let n = data.len() as f64;
        let mut std = vec![0.0; 8];
        for row in data {
            for (i, &val) in row.iter().enumerate() {
                if i < 8 {
                    let diff = val - mean[i];
                    std[i] += diff * diff;
                }
            }
        }
        for v in &mut std {
            *v = (*v / n).sqrt().max(0.001);
        }
        std
    }

    pub fn get_process_analysis(&self, pid: u32) -> ProcessAnalysis {
        let history = self.process_connection_history.get(&pid);
        
        if let Some(history) = history {
            let conns: Vec<_> = history.iter().collect();
            let unique_dsts: std::collections::HashSet<_> = conns.iter().map(|c| &c.dst_ip).collect();
            let unique_ports: std::collections::HashSet<_> = conns.iter().map(|c| c.dst_port).collect();
            let rate = conns.len() as f64 / 60.0; // per minute (approximate)

            let mut risk_factors = Vec::new();
            if rate > 50.0 { risk_factors.push("High connection frequency".to_string()); }
            if unique_dsts.len() > 20 { risk_factors.push("Many unique destinations".to_string()); }
            if unique_ports.len() > 10 { risk_factors.push("Port scanning pattern".to_string()); }

            let risk_score = ((rate * 0.5) + (unique_dsts.len() as f64 * 2.0) + (unique_ports.len() as f64 * 3.0)).min(100.0) as u8;

            let risk_level = if risk_score >= 75 { "Critical" }
                else if risk_score >= 50 { "High" }
                else if risk_score >= 25 { "Medium" }
                else { "Low" }.to_string();

            ProcessAnalysis {
                pid,
                risk_level,
                risk_score,
                risk_factors,
                total_connections: conns.len(),
                unique_destinations: unique_dsts.len(),
                unique_ports: unique_ports.len(),
                connection_rate_per_minute: rate,
            }
        } else {
            ProcessAnalysis {
                pid,
                risk_level: "Unknown".to_string(),
                risk_score: 0,
                risk_factors: vec!["Process not found".to_string()],
                total_connections: 0,
                unique_destinations: 0,
                unique_ports: 0,
                connection_rate_per_minute: 0.0,
            }
        }
    }

    pub fn get_statistics(&self) -> ThreatStats {
        ThreatStats {
            total_analyzed: self.total_analyzed,
            suspicious_detected: self.suspicious_detected,
            suspicious_percentage: if self.total_analyzed > 0 {
                (self.suspicious_detected as f64 / self.total_analyzed as f64) * 100.0
            } else { 0.0 },
            unique_ips_tracked: self.ip_frequency.len(),
            processes_tracked: self.process_connection_history.len(),
        }
    }
}

impl Default for ThreatDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ProcessAnalysis {
    pub pid: u32,
    pub risk_level: String,
    pub risk_score: u8,
    pub risk_factors: Vec<String>,
    pub total_connections: usize,
    pub unique_destinations: usize,
    pub unique_ports: usize,
    pub connection_rate_per_minute: f64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ThreatStats {
    pub total_analyzed: u64,
    pub suspicious_detected: u64,
    pub suspicious_percentage: f64,
    pub unique_ips_tracked: usize,
    pub processes_tracked: usize,
}