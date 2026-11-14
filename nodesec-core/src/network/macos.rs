//! macOS network monitoring using libproc and NetworkExtension

use crate::models::{MonitorMode, NetworkProtocol, Platform};
use crate::network::common::{NetworkConnection, NetworkMonitor};
use anyhow::{Context, Result};
use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;

pub struct MacOSNetworkMonitor {
    events: Arc<Mutex<VecDeque<NetworkConnection>>>,
    running: Arc<Mutex<bool>>,
}

impl MacOSNetworkMonitor {
    pub fn new() -> Self {
        Self {
            events: Arc::new(Mutex::new(VecDeque::with_capacity(10000))),
            running: Arc::new(Mutex::new(false)),
        }
    }

    /// Static helper for fuzzing netstat line parsing
    pub fn parse_netstat_line_static(line: &str, timestamp: u64, protocol: NetworkProtocol) -> Result<Option<NetworkConnection>> {
        // Skip listening sockets
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 {
            return Ok(None);
        }

        let local_addr = parts[3];
        let foreign_addr = parts[4];

        if foreign_addr == "*.*" || foreign_addr == "[::]:*" {
            return Ok(None);
        }

        let (src_ip, src_port) = Self::parse_addr_static(local_addr)?;
        let (dst_ip, dst_port) = Self::parse_addr_static(foreign_addr)?;

        if dst_port == 0 {
            return Ok(None);
        }

        Ok(Some(NetworkConnection {
            timestamp,
            pid: 0,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
            process_name: "unknown".to_string(),
            process_path: None,
            command_line: None,
            user: None,
            threat_score: 0,
            is_suspicious: false,
        }))
    }

    /// Static helper for fuzzing address parsing
    pub fn parse_addr_static(addr: &str) -> Result<(IpAddr, u16)> {
        if addr.contains("*") {
            return Err(anyhow::anyhow!("Wildcard address"));
        }

        if addr.starts_with('[') {
            let end_bracket = addr.find(']').ok_or_else(|| anyhow::anyhow!("Invalid IPv6 address"))?;
            let ip_str = &addr[1..end_bracket];
            let port_str = &addr[end_bracket+2..];
            let ip = ip_str.parse::<IpAddr>()?;
            let port = port_str.parse::<u16>()?;
            Ok((ip, port))
        } else if addr.starts_with("::") || addr.contains("::") {
            if let Some(last_dot) = addr.rfind('.') {
                let ip_str = &addr[..last_dot];
                let port_str = &addr[last_dot+1..];
                let ip = ip_str.parse::<IpAddr>()?;
                let port = port_str.parse::<u16>()?;
                Ok((ip, port))
            } else {
                Err(anyhow::anyhow!("Invalid IPv6 address format"))
            }
        } else {
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

    async fn scan_connections(&self) -> Result<()> {
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

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

    async fn parse_netstat_line(&self, line: &str, timestamp: u64, protocol: NetworkProtocol) -> Result<Option<NetworkConnection>> {
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

        // Skip wildcard addresses early
        if local_addr.contains("*") || foreign_addr.contains("*") {
            return Ok(None);
        }

        let (src_ip, src_port) = match self.parse_addr(local_addr) {
            Ok(v) => v,
            Err(_) => return Ok(None), // Skip unparseable addresses silently
        };
        let (dst_ip, dst_port) = match self.parse_addr(foreign_addr) {
            Ok(v) => v,
            Err(_) => return Ok(None),
        };

        // Skip if destination port is 0
        if dst_port == 0 {
            return Ok(None);
        }

        // Try to get PID using lsof
        let (pid, process_name, process_path, command_line, user) = self.get_process_info(&src_ip, src_port, &dst_ip, dst_port).await;

        Ok(Some(NetworkConnection {
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
            threat_score: 0,
            is_suspicious: false,
        }))
    }

    fn parse_addr(&self, addr: &str) -> Result<(IpAddr, u16)> {
        // Handle various formats from macOS netstat:
        // IPv4: 192.168.1.1.80
        // IPv6: ::1.11470 or [::1].80
        // Wildcard: *.50789 or *.*
        // IPv4-mapped: 127.0.0.1.53635
        
        // Skip wildcard/listening addresses
        if addr.contains("*") {
            return Err(anyhow::anyhow!("Wildcard address"));
        }
        
        if addr.starts_with('[') {
            // IPv6 with brackets: [::1].80
            let end_bracket = addr.find(']').ok_or_else(|| anyhow::anyhow!("Invalid IPv6 address"))?;
            let ip_str = &addr[1..end_bracket];
            let port_str = &addr[end_bracket+2..]; // Skip "]:"
            let ip = ip_str.parse::<IpAddr>()?;
            let port = port_str.parse::<u16>()?;
            Ok((ip, port))
        } else if addr.starts_with("::") || addr.contains("::") {
            // IPv6 without brackets: ::1.11470
            // Find the last dot which separates IP from port
            if let Some(last_dot) = addr.rfind('.') {
                let ip_str = &addr[..last_dot];
                let port_str = &addr[last_dot+1..];
                let ip = ip_str.parse::<IpAddr>()?;
                let port = port_str.parse::<u16>()?;
                Ok((ip, port))
            } else {
                Err(anyhow::anyhow!("Invalid IPv6 address format"))
            }
        } else {
            // IPv4: 192.168.1.1.80 or 127.0.0.1.53635
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
        _dst_ip: &IpAddr,
        _dst_port: u16,
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

    async fn add_event(&self, event: NetworkConnection) {
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

    async fn scan_once(&mut self) -> Result<()> {
        self.scan_connections().await
    }

    fn scan_once_blocking(&mut self) -> Result<()> {
        self.scan_once_blocking_impl()
    }

    fn events(&self) -> Arc<Mutex<VecDeque<NetworkConnection>>> {
        self.events.clone()
    }

    fn platform(&self) -> Platform {
        Platform::MacOS
    }

    fn mode(&self) -> MonitorMode {
        MonitorMode::OnDevice
    }
}

impl MacOSNetworkMonitor {
    /// Blocking scan for connections (for use in background threads)
    pub fn scan_once_blocking_impl(&mut self) -> Result<()> {
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

        // Use netstat for TCP
        let output = std::process::Command::new("netstat")
            .args(["-an", "-p", "tcp"])
            .output()
            .context("Failed to run netstat")?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines().skip(2) {
            if let Some(event) = self.parse_netstat_line_blocking(line, timestamp, NetworkProtocol::Tcp)? {
                self.add_event_blocking(event)?;
            }
        }

        // UDP
        let output = std::process::Command::new("netstat")
            .args(["-an", "-p", "udp"])
            .output()
            .context("Failed to run netstat for UDP")?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines().skip(2) {
            if let Some(event) = self.parse_netstat_line_blocking(line, timestamp, NetworkProtocol::Udp)? {
                self.add_event_blocking(event)?;
            }
        }

        Ok(())
    }

    /// Blocking parse of netstat line
    fn parse_netstat_line_blocking(&self, line: &str, timestamp: u64, protocol: NetworkProtocol) -> Result<Option<NetworkConnection>> {
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

        // Skip wildcard addresses early
        if local_addr.contains("*") || foreign_addr.contains("*") {
            return Ok(None);
        }

        let (src_ip, src_port) = match self.parse_addr(local_addr) {
            Ok(v) => v,
            Err(_) => return Ok(None), // Skip unparseable addresses silently
        };
        let (dst_ip, dst_port) = match self.parse_addr(foreign_addr) {
            Ok(v) => v,
            Err(_) => return Ok(None),
        };

        // Skip if destination port is 0
        if dst_port == 0 {
            return Ok(None);
        }

        // Try to get PID using lsof (blocking)
        let (pid, process_name, process_path, command_line, user) = self.get_process_info_blocking(&src_ip, src_port, &dst_ip, dst_port);

        Ok(Some(NetworkConnection {
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
            threat_score: 0,
            is_suspicious: false,
        }))
    }

    /// Blocking add event
    fn add_event_blocking(&self, event: NetworkConnection) -> Result<()> {
        let mut events = self.events.blocking_lock();
        events.push_back(event);
        while events.len() > 10000 {
            events.pop_front();
        }
        Ok(())
    }

    /// Blocking process info lookup
    fn get_process_info_blocking(
        &self,
        src_ip: &IpAddr,
        src_port: u16,
        _dst_ip: &IpAddr,
        _dst_port: u16,
    ) -> (u32, String, Option<String>, Option<String>, Option<String>) {
        // Use lsof to find the process owning this connection
        let output = std::process::Command::new("lsof")
            .args(["-i", &format!("{}@{}:{}", if matches!(src_ip, IpAddr::V4(_)) { "4" } else { "6" }, src_ip, src_port)])
            .output();

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
            if let Ok(output) = std::process::Command::new("ps")
                .args(["-p", &pid.to_string(), "-o", "comm="])
                .output()
            {
                let comm = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !comm.is_empty() {
                    process_name = comm;
                }
            }

            // Get executable path
            if let Ok(output) = std::process::Command::new("ps")
                .args(["-p", &pid.to_string(), "-o", "args="])
                .output()
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

    /// Scan connections once (called by ConnectionHandler)
    pub async fn scan_once(&self) -> Result<()> {
        self.scan_connections().await
    }
}