//! Common types for network monitoring

use crate::models::NetworkProtocol;
use anyhow::Result;
use async_trait::async_trait;
use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Debug, Clone)]
pub struct ConnectionEvent {
    pub timestamp: u64,
    pub pid: u32,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
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
    fn events(&self) -> Arc<Mutex<VecDeque<ConnectionEvent>>>;
    fn platform(&self) -> crate::models::Platform;
}