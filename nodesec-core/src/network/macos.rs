//! macOS network monitoring using libproc and NetworkExtension

use crate::network::common::{ConnectionEvent, NetworkMonitor};
use crate::models::{NetworkProtocol, Platform};
use anyhow::{Context, Result};
use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;

pub struct MacOSNetworkMonitor {
    events: Arc<Mutex<VecDeque<ConnectionEvent>>>,
    running: Arc<Mutex<bool>>,
}

impl MacOSNetworkMonitor {
    pub fn new() -> Self {
        Self {
            events: Arc::new(Mutex::new(VecDeque::with_capacity(10000))),
            running: Arc::new(Mutex::new(false)),
        }
    }

    async fn scan_connections(&self) -> Result<()> {
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos() as u64;

        // Use netstat or lsof for connection info on macOS
        self.scan_via_netstat(timestamp).await?;

        Ok(())
    }

    async fn scan_via_netstat(&self, timestamp: u64) -> Result<()> {
        // Use netstat -an for all connections
        let output = tokio::process::Command::new("netstat")
            .args(["-an", "-p", "tcp"])
            .output()
            .await
            .context("Failed to run netstat")?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines().skip(2) { // Skip headers
            if let Some(event) = self.parse_netstat_line(line, timestamp, NetworkProtocol::Tcp).await? {
                self.add_event(event).await;
            }
        }

        // UDP
        let output = tokio::process::Command::new("netstat")
            .args(["-an", "-p", "udp"])
            .output()
            .await
            .context("Failed to run netstat for UDP")?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines().skip(2) {
            if let Some(event) = self.parse_netstat_line(line, timestamp, NetworkProtocol::Udp).await? {
                self.add_event(event).await;
            }
        }

        Ok(())
    }

    async fn parse_netstat_line(&self, line: &str, timestamp: u64, protocol: NetworkProtocol) -> Result<Option<ConnectionEvent>> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 {
            return Ok(None);
        }

        // netstat output format: Proto Recv-Q Send-Q Local Address Foreign Address (state)
        let local_addr = parts[3];
        let foreign_addr = parts[4];

        // Skip listening sockets
        if foreign_addr == "*.*" || foreign_addr == "[::]:*" {
            return Ok(None);
        }

        let (src_ip, src_port) = self.parse_addr(local_addr)?;
        let (dst_ip, dst_port) = self.parse_addr(foreign_addr)?;

        // Skip if destination port is 0
        if dst_port == 0 {
            return Ok(None);
        }

        // Try to get PID using lsof
        let (pid, process_name, process_path, command_line, user) = self.get_process_info(&src_ip, src_port, &dst_ip, dst_port).await;

        Ok(Some(ConnectionEvent {
            timestamp,
            pid,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
            process_name,
            process_path,
            command_line,
            user,
        }))
    }

    fn parse_addr(&self, addr: &str) -> Result<(IpAddr, u16)> {
        // Handle both IPv4 (192.168.1.1.80) and IPv6 ([::1].80) formats
        if addr.starts_with('[') {
            // IPv6
            let end_bracket = addr.find(']').ok_or_else(|| anyhow::anyhow!("Invalid IPv6 address"))?;
            let ip_str = &addr[1..end_bracket];
            let port_str = &addr[end_bracket+2..]; // Skip "]:"
            let ip = ip_str.parse::<IpAddr>()?;
            let port = port_str.parse::<u16>()?;
            Ok((ip, port))
        } else {
            // IPv4
            let parts: Vec<&str> = addr.rsplitn(2, '.').collect();
            if parts.len() != 2 {
                return Err(anyhow::anyhow!("Invalid address format"));
            }
            let port = parts[0].parse::<u16>()?;
            let ip_str = parts[1];
            let ip = ip_str.parse::<IpAddr>()?;
            Ok((ip, port))
        }
    }

    async fn get_process_info(
        &self,
        src_ip: &IpAddr,
        src_port: u16,
        dst_ip: &IpAddr,
        dst_port: u16,
    ) -> (u32, String, Option<String>, Option<String>, Option<String>) {
        // Use lsof to find the process owning this connection
        let output = tokio::process::Command::new("lsof")
            .args(["-i", &format!("{}@{}:{}", if matches!(src_ip, IpAddr::V4(_)) { "4" } else { "6" }, src_ip, src_port)])
            .output()
            .await;

        let mut pid = 0;
        let mut process_name = "unknown".to_string();
        let mut process_path = None;
        let mut command_line = None;
        let mut user = None;

        if let Ok(output) = output {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    if let Ok(p) = parts[1].parse::<u32>() {
                        pid = p;
                        process_name = parts[0].to_string();
                        user = Some(parts[2].to_string()); // user column
                        break;
                    }
                }
            }
        }

        if pid > 0 {
            // Get more process details using ps
            if let Ok(output) = tokio::process::Command::new("ps")
                .args(["-p", &pid.to_string(), "-o", "comm="])
                .output()
                .await
            {
                let comm = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !comm.is_empty() {
                    process_name = comm;
                }
            }

            // Get executable path
            if let Ok(output) = tokio::process::Command::new("ps")
                .args(["-p", &pid.to_string(), "-o", "args="])
                .output()
                .await
            {
                let args_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !args_str.is_empty() {
                    command_line = Some(args_str.clone());
                    // First word is usually the executable
                    if let Some(exe) = args_str.split_whitespace().next() {
                        process_path = Some(exe.to_string());
                    }
                }
            }
        }

        (pid, process_name, process_path, command_line, user)
    }

    async fn add_event(&self, event: ConnectionEvent) {
        let mut events = self.events.lock().await;
        events.push_back(event);
        while events.len() > 10000 {
            events.pop_front();
        }
    }
}

impl Default for MacOSNetworkMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl NetworkMonitor for MacOSNetworkMonitor {
    async fn start(&mut self) -> Result<()> {
        *self.running.lock().await = true;
        Ok(())
    }

    async fn stop(&mut self) -> Result<()> {
        *self.running.lock().await = false;
        Ok(())
    }

    fn events(&self) -> Arc<Mutex<VecDeque<ConnectionEvent>>> {
        self.events.clone()
    }

    fn platform(&self) -> Platform {
        Platform::MacOS
    }
}

impl MacOSNetworkMonitor {
    /// Scan connections once (called by ConnectionHandler)
    pub async fn scan_once(&self) -> Result<()> {
        self.scan_connections().await
    }
}