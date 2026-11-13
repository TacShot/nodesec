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
    fn events(&self) -> Arc<Mutex<VecDeque<NetworkConnection>>>;
    fn platform(&self) -> Platform;
    fn mode(&self) -> MonitorMode;
}