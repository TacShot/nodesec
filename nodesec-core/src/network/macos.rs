//! macOS network monitoring using libproc and NetworkExtension

use crate::models::{MonitorMode, NetworkProtocol, Platform};
use crate::network::common::{NetworkConnection, NetworkMonitor};
use anyhow::{Context, Result};
use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;

#[derive(Clone)]
struct ProcessInfo {
    pid: u32,
    src_port: u16,
    process_name: String,
    process_path: Option<String>,
    command_line: Option<String>,
    user: Option<String>,
}

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

        // Batch lsof once per scan cycle instead of per-connection (slow + needs root)
        let lsof_map = self.get_all_process_info().await;

        // Use netstat or lsof for connection info on macOS
        self.scan_via_netstat_with_lsof(timestamp, &lsof_map).await?;

        Ok(())
    }

    /// Run lsof once and build a map of (ip, port) -> process info for all connections.
    /// This avoids spawning lsof once per connection (which is slow and requires root).
    async fn get_all_process_info(&self) -> std::collections::HashMap<(u32, u16), ProcessInfo> {
        let mut map: std::collections::HashMap<(u32, u16), ProcessInfo> = std::collections::HashMap::new();

        let output = match tokio::process::Command::new("lsof")
            .args(["-nP", "-i"])
            .output()
            .await
        {
            Ok(o) => o,
            Err(_) => return map, // lsof not available or no permissions
        };

        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 9 {
                continue;
            }

            let process_name = parts[0].to_string();
            let pid: u32 = match parts[1].parse() {
                Ok(p) => p,
                Err(_) => continue,
            };
            let user = parts[2].to_string();

            // lsof -i output: COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
            // NAME column looks like: "tcp4->ip:port" or "udp4->ip:port" or "tcp4@ip:port" or "ip:port"
            // Find the last column (NAME) which may contain spaces — join remaining parts
            let name = parts[9..].join(" ");

            // Parse local and remote addresses from NAME field
            // Formats: "tcp4->192.168.1.1:80" or "udp4->[::1]:50789" or "tcp4@*:50789"
            if let Some(process_info) = self.parse_lsof_name(&name, pid, &process_name, &user) {
                map.insert((process_info.pid, process_info.src_port), process_info);
            }
        }

        map
    }

    fn parse_lsof_name(&self, name: &str, pid: u32, process_name: &str, user: &str) -> Option<ProcessInfo> {
        // lsof NAME formats:
        // "tcp4->192.168.1.1:50789" (established, has remote)
        // "tcp4@*:50789" (listening, wildcard local)
        // "tcp4->[::1]:50789" (IPv6)

        let arrow_pos = name.find("->").or_else(|| name.find("@"))?;
        let addr_part = &name[arrow_pos + 2..];

        // Parse "ip:port" or "[ipv6]:port"
        let (ip_str, port_str) = if addr_part.starts_with('[') {
            let end = addr_part.find(']')?;
            let ip = &addr_part[1..end];
            let port = &addr_part[end + 2..]; // skip "]:"
            (ip, port)
        } else {
            let last_dot = addr_part.rfind('.')?;
            let ip = &addr_part[..last_dot];
            let port = &addr_part[last_dot + 1..];
            (ip, port)
        };

        let src_port: u16 = port_str.parse().ok()?;

        // Try to get more details via ps
        let (process_path, command_line) = self.get_process_details(pid);

        Some(ProcessInfo {
            pid,
            src_port,
            process_name: process_name.to_string(),
            process_path,
            command_line,
            user: Some(user.to_string()),
        })
    }

    fn get_process_details(&self, pid: u32) -> (Option<String>, Option<String>) {
        let result = std::process::Command::new("ps")
            .args(["-p", &pid.to_string(), "-o", "args="])
            .output()
            .ok()
            .and_then(|o| Some(String::from_utf8_lossy(&o.stdout).trim().to_string()))
            .filter(|s| !s.is_empty())
            .map(|args| {
                let exe = args.split_whitespace().next().unwrap_or("").to_string();
                (Some(exe.clone()), Some(args))
            });

        match result {
            Some((path, cmd)) => (path, cmd),
            None => (None, None),
        }
    }

    async fn scan_via_netstat_with_lsof(&self, timestamp: u64, lsof_map: &std::collections::HashMap<(u32, u16), ProcessInfo>) -> Result<()> {
        // Use netstat -an for all connections
        let output = tokio::process::Command::new("netstat")
            .args(["-an", "-p", "tcp"])
            .output()
            .await
            .context("Failed to run netstat")?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines().skip(2) { // Skip headers
            if let Some(event) = self.parse_netstat_line_with_lsof(line, timestamp, NetworkProtocol::Tcp, lsof_map) {
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
            if let Some(event) = self.parse_netstat_line_with_lsof(line, timestamp, NetworkProtocol::Udp, lsof_map) {
                self.add_event(event).await;
            }
        }

        Ok(())
    }

    fn parse_netstat_line_with_lsof(
        &self,
        line: &str,
        timestamp: u64,
        protocol: NetworkProtocol,
        lsof_map: &std::collections::HashMap<(u32, u16), ProcessInfo>,
    ) -> Option<NetworkConnection> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 {
            return None;
        }

        // netstat output format: Proto Recv-Q Send-Q Local Address Foreign Address (state)
        let local_addr = parts[3];
        let foreign_addr = parts[4];

        // Skip listening sockets
        if foreign_addr == "*.*" || foreign_addr == "[::]:*" {
            return None;
        }

        // Skip wildcard addresses early
        if local_addr.contains("*") || foreign_addr.contains("*") {
            return None;
        }

        let (src_ip, src_port) = match self.parse_addr(local_addr) {
            Ok(v) => v,
            Err(_) => return None, // Skip unparseable addresses silently
        };
        let (dst_ip, dst_port) = match self.parse_addr(foreign_addr) {
            Ok(v) => v,
            Err(_) => return None,
        };

        // Skip if destination port is 0
        if dst_port == 0 {
            return None;
        }

        // Look up process info from batched lsof data
        // lsof gives us (pid, src_port) -> ProcessInfo
        // We match by src_port since netstat local port = lsof local port
        let mut pid = 0u32;
        let mut process_name = "unknown".to_string();
        let mut process_path = None;
        let mut command_line = None;
        let mut user = None;

        for (key, info) in lsof_map.iter() {
            if key.1 == src_port {
                pid = info.pid;
                process_name = info.process_name.clone();
                process_path = info.process_path.clone();
                command_line = info.command_line.clone();
                user = info.user.clone();
                break;
            }
        }

        Some(NetworkConnection {
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
        })
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

        // Batch lsof once per scan cycle
        let lsof_map = self.get_all_process_info_blocking();

        // Use netstat for TCP
        let output = std::process::Command::new("netstat")
            .args(["-an", "-p", "tcp"])
            .output()
            .context("Failed to run netstat")?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines().skip(2) {
            if let Some(event) = self.parse_netstat_line_blocking_with_lsof(line, timestamp, NetworkProtocol::Tcp, &lsof_map) {
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
            if let Some(event) = self.parse_netstat_line_blocking_with_lsof(line, timestamp, NetworkProtocol::Udp, &lsof_map) {
                self.add_event_blocking(event)?;
            }
        }

        Ok(())
    }

    /// Blocking lsof — run once, build process map
    fn get_all_process_info_blocking(&self) -> std::collections::HashMap<(u32, u16), ProcessInfo> {
        let mut map: std::collections::HashMap<(u32, u16), ProcessInfo> = std::collections::HashMap::new();

        let output = match std::process::Command::new("lsof")
            .args(["-nP", "-i"])
            .output()
        {
            Ok(o) => o,
            Err(_) => return map,
        };

        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 9 {
                continue;
            }

            let process_name = parts[0].to_string();
            let pid: u32 = match parts[1].parse() {
                Ok(p) => p,
                Err(_) => continue,
            };
            let user = parts[2].to_string();

            let name = parts[9..].join(" ");

            if let Some(process_info) = self.parse_lsof_name(&name, pid, &process_name, &user) {
                map.insert((process_info.pid, process_info.src_port), process_info);
            }
        }

        map
    }

    /// Blocking parse of netstat line with batched lsof data
    fn parse_netstat_line_blocking_with_lsof(
        &self,
        line: &str,
        timestamp: u64,
        protocol: NetworkProtocol,
        lsof_map: &std::collections::HashMap<(u32, u16), ProcessInfo>,
    ) -> Option<NetworkConnection> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 {
            return None;
        }

        let local_addr = parts[3];
        let foreign_addr = parts[4];

        if foreign_addr == "*.*" || foreign_addr == "[::]:*" {
            return None;
        }

        if local_addr.contains("*") || foreign_addr.contains("*") {
            return None;
        }

        let (src_ip, src_port) = match self.parse_addr(local_addr) {
            Ok(v) => v,
            Err(_) => return None,
        };
        let (dst_ip, dst_port) = match self.parse_addr(foreign_addr) {
            Ok(v) => v,
            Err(_) => return None,
        };

        if dst_port == 0 {
            return None;
        }

        // Look up process info from batched lsof data
        let mut pid = 0u32;
        let mut process_name = "unknown".to_string();
        let mut process_path = None;
        let mut command_line = None;
        let mut user = None;

        for (key, info) in lsof_map.iter() {
            if key.1 == src_port {
                pid = info.pid;
                process_name = info.process_name.clone();
                process_path = info.process_path.clone();
                command_line = info.command_line.clone();
                user = info.user.clone();
                break;
            }
        }

        Some(NetworkConnection {
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
        })
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

    /// Scan connections once (called by ConnectionHandler)
    pub async fn scan_once(&self) -> Result<()> {
        self.scan_connections().await
    }
}