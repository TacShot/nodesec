//! Common types for network monitoring

use anyhow::Result;
use async_trait::async_trait;
use std::collections::VecDeque;
use std::sync::Arc;
use tokio::sync::Mutex;

// Re-export from models
pub use crate::models::{
    MonitorMode, NetworkConnection, NetworkProtocol, Platform,
    WSMessage, AgentInfo, RuleSet, ThreatAlert, DetectionRule,
};

#[derive(Debug, Clone)]
pub struct ConnectionEvent {
    pub timestamp: u64,
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
}

#[async_trait]
pub trait NetworkMonitor: Send + Sync {
    async fn start(&mut self) -> Result<()>;
    async fn stop(&mut self) -> Result<()>;
    async fn scan_once(&mut self) -> Result<()>;
    /// Blocking version of scan_once for use in background threads
    fn scan_once_blocking(&mut self) -> Result<()>;
    fn events(&self) -> Arc<Mutex<VecDeque<NetworkConnection>>>;
    fn platform(&self) -> Platform;
    fn mode(&self) -> MonitorMode;

    /// Drain all events from the internal queue
    async fn drain_events(&self) -> Vec<NetworkConnection> {
        let events_arc = self.events();
        let mut events = events_arc.lock().await;
        events.drain(..).collect()
    }

    /// Enumerate USB devices
    fn enumerate_usb_devices(&self) -> Vec<crate::models::ConnectedDevice> {
        let _ = ();
        Vec::new()
    }

    /// Enumerate Bluetooth devices
    fn enumerate_bluetooth_devices(&self) -> Vec<crate::models::ConnectedDevice> {
        let _ = ();
        Vec::new()
    }

    /// Enumerate all connected devices (USB + Bluetooth + etc.)
    fn enumerate_all_devices(&self) -> Vec<crate::models::ConnectedDevice> {
        let mut devices = self.enumerate_usb_devices();
        devices.extend(self.enumerate_bluetooth_devices());
        devices
    }

    /// Detect virtual machine environments
    fn detect_virtual_machine(&self) -> Option<String> {
        let _ = ();
        None
    }
}