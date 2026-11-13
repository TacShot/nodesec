//! Connection handler with sliding window and threat detection integration

use crate::network::common::{ConnectionEvent, NetworkMonitor};
use crate::models::{Platform, NetworkConnection};
use crate::threat::ThreatDetector;
use anyhow::Result;
use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::{interval, Duration};

pub struct ConnectionHandler {
    monitor: Box<dyn NetworkMonitor>,
    events: Arc<Mutex<VecDeque<ConnectionEvent>>>,
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
                // For now, we just clean up old events
                Self::cleanup_old_events(&events, retention_seconds, max_events).await;

                // Process new events for threat detection
                Self::process_events_for_threats(&events, &threat_detector).await;
            }
        });

        Ok(())
    }

    pub async fn stop(&mut self) -> Result<()> {
        self.monitor.stop().await
    }

    pub async fn get_recent_connections(&self, limit: usize) -> Vec<NetworkConnection> {
        let events = self.events.lock().await;
        let mut threat_detector = self.threat_detector.lock().await;

        events
            .iter()
            .rev()
            .take(limit)
            .map(|e| self.event_to_network_connection(e, &mut threat_detector))
            .collect()
    }

    pub async fn get_connection_stats(&self) -> ConnectionStats {
        let events = self.events.lock().await;
        let threat_detector = self.threat_detector.lock().await;

        let total = events.len();
        let connections: Vec<_> = events.iter()
            .map(|e| self.event_to_network_connection(e, &mut ThreatDetector::new()))
            .collect();
        let mut threat_detector_clone = ThreatDetector::new();
        let suspicious = connections.iter()
            .map(|c| threat_detector_clone.analyze(c))
            .filter(|s| *s >= 50)
            .count();

        let mut process_counts = std::collections::HashMap::new();
        let mut dst_ip_counts = std::collections::HashMap::new();
        let mut port_counts = std::collections::HashMap::new();

        for e in events.iter() {
            *process_counts.entry(e.process_name.clone()).or_insert(0) += 1;
            *dst_ip_counts.entry(e.dst_ip.to_string()).or_insert(0) += 1;
            *port_counts.entry(e.dst_port).or_insert(0) += 1;
        }

        ConnectionStats {
            total_connections: total,
            suspicious_connections: suspicious,
            unique_processes: process_counts.len(),
            unique_destinations: dst_ip_counts.len(),
            top_processes: Self::top_n(process_counts, 10),
            top_destinations: Self::top_n(dst_ip_counts, 10),
            top_ports: Self::top_n(port_counts, 10),
        }
    }

    fn event_to_network_connection(&self, event: &ConnectionEvent, detector: &mut ThreatDetector) -> NetworkConnection {
        let threat_score = detector.analyze(&NetworkConnection {
            pid: event.pid,
            src_ip: event.src_ip,
            dst_ip: event.dst_ip,
            src_port: event.src_port,
            dst_port: event.dst_port,
            protocol: event.protocol.clone(),
            process_name: event.process_name.clone(),
            process_path: event.process_path.clone(),
            command_line: event.command_line.clone(),
            user: event.user.clone(),
            timestamp: event.timestamp,
            threat_score: 0,
            is_suspicious: false,
        });

        NetworkConnection {
            pid: event.pid,
            src_ip: event.src_ip,
            dst_ip: event.dst_ip,
            src_port: event.src_port,
            dst_port: event.dst_port,
            protocol: event.protocol.clone(),
            process_name: event.process_name.clone(),
            process_path: event.process_path.clone(),
            command_line: event.command_line.clone(),
            user: event.user.clone(),
            timestamp: event.timestamp,
            threat_score,
            is_suspicious: threat_score >= 50,
        }
    }

    async fn cleanup_old_events(events: &Arc<Mutex<VecDeque<ConnectionEvent>>>, retention_seconds: u64, max_events: usize) {
        let mut events = events.lock().await;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        let cutoff = now.saturating_sub(retention_seconds * 1_000_000_000);

        events.retain(|e| e.timestamp > cutoff);

        while events.len() > max_events {
            events.pop_front();
        }
    }

    async fn process_events_for_threats(
        events: &Arc<Mutex<VecDeque<ConnectionEvent>>>,
        threat_detector: &Arc<Mutex<ThreatDetector>>,
    ) {
        // Process recent events for threat detection
        // This is where ML anomaly detection would run
        let _ = events;
        let _ = threat_detector;
        // Implementation would go here
    }

    fn top_n<T: Clone + Ord, C: Ord + Clone>(map: std::collections::HashMap<T, C>, n: usize) -> Vec<(T, C)> {
        let mut vec: Vec<_> = map.into_iter().collect();
        vec.sort_by(|a, b| b.1.cmp(&a.1));
        vec.into_iter().take(n).collect()
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ConnectionStats {
    pub total_connections: usize,
    pub suspicious_connections: usize,
    pub unique_processes: usize,
    pub unique_destinations: usize,
    pub top_processes: Vec<(String, usize)>,
    pub top_destinations: Vec<(String, usize)>,
    pub top_ports: Vec<(u16, usize)>,
}

impl ConnectionHandler {
    pub fn platform(&self) -> Platform {
        self.monitor.platform()
    }
}