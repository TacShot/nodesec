//! Connection handler with sliding window and threat detection integration

use crate::network::common::{NetworkConnection, NetworkMonitor};
use crate::models::Platform;
use crate::threat::ThreatDetector;
use anyhow::Result;
use std::collections::VecDeque;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::{interval, Duration};

pub struct ConnectionHandler {
    monitor: Box<dyn NetworkMonitor>,
    events: Arc<Mutex<VecDeque<NetworkConnection>>>,
    threat_detector: Arc<Mutex<ThreatDetector>>,
    max_events: usize,
    retention_seconds: u64,
}

impl ConnectionHandler {
    pub fn new(monitor: Box<dyn NetworkMonitor>, max_events: usize, retention_seconds: u64) -> Self {
        let events = monitor.events().clone();
        let threat_detector = Arc::new(Mutex::new(ThreatDetector::new()));

        Self {
            monitor,
            events,
            threat_detector,
            max_events,
            retention_seconds,
        }
    }

    pub async fn start(&mut self) -> Result<()> {
        self.monitor.start().await?;

        // Start periodic scanning
        let events = self.events.clone();
        let threat_detector = self.threat_detector.clone();
        let retention_seconds = self.retention_seconds;
        let max_events = self.max_events;

        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(2));
            loop {
                interval.tick().await;

                // Trigger platform-specific scan
                // This would call the monitor's scan_once method
                // For now, we just maintain the sliding window
                
                let mut events_lock = events.lock().await;
                let now = chrono::Utc::now().timestamp() as u64;
                
                // Remove old events beyond retention
                while let Some(front) = events_lock.front() {
                    if now - front.timestamp > retention_seconds {
                        events_lock.pop_front();
                    } else {
                        break;
                    }
                }
                
                // Limit total events
                while events_lock.len() > max_events {
                    events_lock.pop_front();
                }
            }
        });

        Ok(())
    }

    pub async fn get_recent_connections(&self, limit: usize) -> Vec<NetworkConnection> {
        let events = self.events.lock().await;
        let mut threat_detector = self.threat_detector.lock().await;
        
        events
            .iter()
            .rev()
            .take(limit)
            .map(|e| Self::analyze_connection(e, &mut threat_detector))
            .collect()
    }

    pub async fn get_connection_stats(&self) -> ConnectionStats {
        let events = self.events.lock().await;
        let mut threat_detector = self.threat_detector.lock().await;
        
        let total = events.len();
        let mut suspicious = 0;
        let mut critical = 0;
        let mut by_protocol = std::collections::HashMap::new();
        let mut by_process = std::collections::HashMap::new();

        for event in events.iter() {
            let analyzed = Self::analyze_connection(event, &mut threat_detector);
            if analyzed.is_suspicious {
                suspicious += 1;
            }
            if analyzed.threat_score >= 90 {
                critical += 1;
            }
            
            *by_protocol.entry(format!("{:?}", analyzed.protocol)).or_insert(0) += 1;
            *by_process.entry(analyzed.process_name.clone()).or_insert(0) += 1;
        }

        ConnectionStats {
            total_connections: total,
            suspicious_connections: suspicious,
            critical_threats: critical,
            by_protocol,
            by_process,
        }
    }

    fn analyze_connection(conn: &NetworkConnection, detector: &mut ThreatDetector) -> NetworkConnection {
        let threat_score = detector.analyze(conn);
        
        let mut analyzed = conn.clone();
        analyzed.threat_score = threat_score;
        analyzed.is_suspicious = threat_score >= 50;
        analyzed
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ConnectionStats {
    pub total_connections: usize,
    pub suspicious_connections: usize,
    pub critical_threats: usize,
    pub by_protocol: std::collections::HashMap<String, usize>,
    pub by_process: std::collections::HashMap<String, usize>,
}

impl Default for ConnectionStats {
    fn default() -> Self {
        Self {
            total_connections: 0,
            suspicious_connections: 0,
            critical_threats: 0,
            by_protocol: std::collections::HashMap::new(),
            by_process: std::collections::HashMap::new(),
        }
    }
}

impl ConnectionHandler {
    pub fn platform(&self) -> Platform {
        self.monitor.platform()
    }
}