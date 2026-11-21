//! macOS network monitoring using libproc and NetworkExtension

use crate::models::{MonitorMode, NetworkProtocol, Platform, ExclusionList};
use serde_json::{Map, Value};
use crate::network::common::{NetworkConnection, NetworkMonitor};
use anyhow::{Context, Result};
use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::{Arc, Mutex as StdMutex};
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

/// Process information from `ps` enumeration (no root required)
#[derive(Clone, Debug)]
struct PsProcess {
    pid: u32,
    process_name: String,
    process_path: Option<String>,
    command_line: Option<String>,
    user: Option<String>,
}

pub struct MacOSNetworkMonitor {
    events: Arc<Mutex<VecDeque<NetworkConnection>>>,
    running: Arc<Mutex<bool>>,
    exclusion_list: Arc<StdMutex<ExclusionList>>,
}

impl MacOSNetworkMonitor {
    pub fn new() -> Self {
        Self {
            events: Arc::new(Mutex::new(VecDeque::with_capacity(10000))),
            running: Arc::new(Mutex::new(false)),
            exclusion_list: Arc::new(StdMutex::new(ExclusionList::default())),
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
    /// Also enriches with `ps ax` data for processes that lsof couldn't fully resolve.
    async fn get_all_process_info(&self) -> std::collections::HashMap<(u32, u16), ProcessInfo> {
        let mut map: std::collections::HashMap<(u32, u16), ProcessInfo> = std::collections::HashMap::new();

        // Enumerate all processes via ps (no root required)
        let ps_map = self.enumerate_all_processes();

        // Run lsof to get connections -> PID mapping
        let output = match tokio::process::Command::new("lsof")
            .args(["-nP", "-i"])
            .output()
            .await
        {
            Ok(o) => o,
            Err(_) => {
                // lsof not available — fall back to ps-only data with port 0
                // (we can't map connections to PIDs without lsof, but we still have process list)
                return map;
            }
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
let name = parts[8..].join(" ");

            // Parse local and remote addresses from NAME field
            if let Some(mut process_info) = self.parse_lsof_name(&name, pid, &process_name, &user) {
                // Enrich with ps data if available (better path, command line, user)
                if let Some(ps_proc) = ps_map.get(&pid) {
                    if process_info.process_path.is_none() {
                        process_info.process_path = ps_proc.process_path.clone();
                    }
                    if process_info.command_line.is_none() {
                        process_info.command_line = ps_proc.command_line.clone();
                    }
                    if process_info.user.is_none() {
                        process_info.user = ps_proc.user.clone();
                    }
                    // Use ps process_name if lsof name is generic/empty
                    if process_info.process_name.is_empty() || process_info.process_name == "unknown" {
                        process_info.process_name = ps_proc.process_name.clone();
                    }
                }
                map.insert((process_info.pid, process_info.src_port), process_info);
            }
        }

        map
    }

    fn parse_lsof_name(&self, name: &str, pid: u32, process_name: &str, user: &str) -> Option<ProcessInfo> {
        // Actual lsof -nP -i NAME formats on macOS:
        // "TCP 192.168.29.231:53168->140.82.112.26:443 (ESTABLISHED)"
        // "TCP [2405:201:4051:b040:c464:e0a3:4444:2261]:49722->[2606:4700:9641:d8b7:9a0c:631:ccf5:ac50]:443 (ESTABLISHED)"
        // "UDP *:*"
        // "TCP *:50789"
        // "TCP6 [::1]:50789->[::1]:443"

        // Strip protocol prefix (TCP, UDP, TCP6, UDP6, etc.) and whitespace
        let name = name.trim_start();
        let name = name.strip_prefix("TCP ").or_else(|| name.strip_prefix("UDP "))
            .or_else(|| name.strip_prefix("TCP6 ")).or_else(|| name.strip_prefix("UDP6 "))
            .unwrap_or(name);

        // Find the local address:port — it's everything before "->" (remote separator)
        // or the whole string if listening (no remote)
        let local_part = if let Some(arrow_pos) = name.find("->") {
            &name[..arrow_pos].trim_end()
        } else {
            name.trim_end()
        };

        // Remove trailing state like "(ESTABLISHED)" if present
        let local_part = local_part.split_whitespace().next().unwrap_or(local_part);

        if local_part.is_empty() || local_part == "*" || local_part == "*:*" {
            return None; // listening wildcard, skip
        }

        // Parse "ip:port" or "[ipv6]:port" from local_part
        let port_str = if local_part.starts_with('[') {
            // IPv6: [addr]:port
            let end = local_part.find(']')?;
            let after_bracket = &local_part[end + 1..];
            after_bracket.strip_prefix(':').unwrap_or(after_bracket)
        } else {
            // IPv4: ip:port — split on last colon
            local_part.rsplitn(2, ':').next().unwrap_or(local_part)
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

    /// Enumerate all processes via `ps ax` (no root required for own processes).
    /// Returns a map of PID -> PsProcess for all processes visible to this user.
    fn enumerate_all_processes(&self) -> std::collections::HashMap<u32, PsProcess> {
        let mut map: std::collections::HashMap<u32, PsProcess> = std::collections::HashMap::new();

        let output = match std::process::Command::new("ps")
            .args(["ax", "-o", "pid=,comm=,user=,args="])
            .output()
        {
            Ok(o) => o,
            Err(_) => return map,
        };

        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let parts: Vec<&str> = line.splitn(4, char::is_whitespace).collect();
            if parts.len() < 3 {
                continue;
            }

            let pid: u32 = match parts[0].trim().parse() {
                Ok(p) => p,
                Err(_) => continue,
            };
            let process_name = parts[1].trim().to_string();
            let user = parts[2].trim().to_string();
            let args = if parts.len() > 3 { Some(parts[3].trim().to_string()) } else { None };

            // Get executable path via lsof -p <pid> (works for own processes without root)
            let process_path = self.get_process_executable_path_via_lsof(pid);

            map.insert(pid, PsProcess {
                pid,
                process_name,
                process_path,
                command_line: args,
                user: Some(user),
            });
        }

        map
    }

    /// Get executable path for a process via `lsof -p <pid>`.
    /// Works without root for processes owned by the current user.
    fn get_process_executable_path_via_lsof(&self, pid: u32) -> Option<String> {
        let output = match std::process::Command::new("lsof")
            .args(["-p", &pid.to_string(), "-Fn"])
            .output()
        {
            Ok(o) => o,
            Err(_) => return None,
        };

        let stdout = String::from_utf8_lossy(&output.stdout);
        // lsof -Fn output: each line starts with 'f' followed by the file path
        for line in stdout.lines() {
            if line.starts_with('f') && line.len() > 1 {
                let path = line[1..].to_string();
                // The first 'f' line is typically the executable path (text segment)
                return Some(path);
            }
        }

        None
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

    fn set_exclusion_list(&mut self, list: Arc<StdMutex<ExclusionList>>) {
        self.exclusion_list = list;
    }

    fn is_excluded(&self, conn: &NetworkConnection) -> bool {
        let exclusion_list = self.exclusion_list.try_lock();
        match exclusion_list {
            Ok(list) => list.is_excluded(conn),
            Err(_) => false,
        }
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
                if self.is_excluded(&event) {
                    continue;
                }
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
                if self.is_excluded(&event) {
                    continue;
                }
                self.add_event_blocking(event)?;
            }
        }

        Ok(())
    }

    /// Blocking lsof — run once, build process map
    /// Also enriches with `ps ax` data for processes that lsof couldn't fully resolve.
    fn get_all_process_info_blocking(&self) -> std::collections::HashMap<(u32, u16), ProcessInfo> {
        let mut map: std::collections::HashMap<(u32, u16), ProcessInfo> = std::collections::HashMap::new();

        // Enumerate all processes via ps (no root required)
        let ps_map = self.enumerate_all_processes();

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

let name = parts[8..].join(" ");

            if let Some(mut process_info) = self.parse_lsof_name(&name, pid, &process_name, &user) {
                // Enrich with ps data if available
                if let Some(ps_proc) = ps_map.get(&pid) {
                    if process_info.process_path.is_none() {
                        process_info.process_path = ps_proc.process_path.clone();
                    }
                    if process_info.command_line.is_none() {
                        process_info.command_line = ps_proc.command_line.clone();
                    }
                    if process_info.user.is_none() {
                        process_info.user = ps_proc.user.clone();
                    }
                    if process_info.process_name.is_empty() || process_info.process_name == "unknown" {
                        process_info.process_name = ps_proc.process_name.clone();
                    }
                }
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

// Bluetooth/USB device enumeration using system_profiler
impl MacOSNetworkMonitor {
    /// Enumerate USB devices using system_profiler (with recursive hub traversal)
    fn enumerate_usb_devices_sp(&self) -> Vec<crate::models::ConnectedDevice> {
        let mut devices = Vec::new();
        
        let output = match std::process::Command::new("system_profiler")
            .args(["SPUSBDataType", "-json"])
            .output()
        {
            Ok(o) => o,
            Err(_) => return devices,
        };
        
        let stdout = String::from_utf8_lossy(&output.stdout);
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
            if let Some(items) = json.get("SPUSBDataType").and_then(|v| v.as_array()) {
                for item in items {
                    Self::extract_usb_from_json_item(&item, &mut devices);
                }
            }
        }
        
        devices
    }

    /// Recursively extract USB devices from JSON items (handles USB hubs with _items)
    fn extract_usb_from_json_item(item: &serde_json::Value, devices: &mut Vec<crate::models::ConnectedDevice>) {
        let name = item.get("_name").and_then(|v| v.as_str()).unwrap_or("Unknown USB Device").to_string();
        let vendor = item.get("_vendor").and_then(|v| v.as_str()).map(|s| s.to_string());
        let product_id = item.get("product_id").and_then(|v| v.as_str()).map(|s| s.to_string());
        let vendor_id = item.get("vendor_id").and_then(|v| v.as_str()).map(|s| s.to_string());
        let serial = item.get("serial_num").and_then(|v| v.as_str()).map(|s| s.to_string());
        
        // Only add leaf devices (those with a vendor_id or product_id, or that aren't hubs/controllers)
        let is_hub = name.to_lowercase().contains("hub") || vendor_id.is_none();
        
        if !is_hub || vendor_id.is_some() {
            devices.push(crate::models::ConnectedDevice {
                id: format!("usb:{}:{}", vendor_id.as_deref().unwrap_or("unknown"), product_id.as_deref().unwrap_or("unknown")),
                name,
                device_type: crate::models::DeviceType::Usb,
                vendor,
                product_id,
                vendor_id,
                serial_number: serial,
                driver: None,
                bus_location: None,
                entry_id: None,
                is_hub,
                connected_at: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs(),
                last_seen: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs(),
                is_connected: true,
            });
        }
        
        // Recurse into _items (devices connected through hubs)
        if let Some(sub_items) = item.get("_items").and_then(|v| v.as_array()) {
            for sub in sub_items {
                Self::extract_usb_from_json_item(sub, devices);
            }
        }
    }

    /// Enumerate USB devices using ioreg (fallback when system_profiler returns empty)
    fn enumerate_usb_devices_ioreg(&self) -> Vec<crate::models::ConnectedDevice> {
        let mut devices = Vec::new();
        
        let output = match std::process::Command::new("ioreg")
            .args(["-r", "-c", "IOUSBDevice", "-a"])
            .output()
        {
            Ok(o) => o,
            Err(_) => return devices,
        };
        
        let stdout = String::from_utf8_lossy(&output.stdout);
        // Parse ioreg output for USB device entries
        // Format: "IOUSBDevice" with properties like "USB Product Name", "idVendor", "idProduct"
        let mut current_name = String::new();
        let mut current_vendor_id: Option<String> = None;
        let mut current_product_id: Option<String> = None;
        let mut current_serial: Option<String> = None;
        
        for line in stdout.lines() {
            let line = line.trim();
            if line.contains("\"USB Product Name\"") {
                if let Some(start) = line.find('=') {
                    let val = line[start+1..].trim().trim_matches('"');
                    if !val.is_empty() && val != "0" {
                        current_name = val.to_string();
                    }
                }
            } else if line.contains("\"idVendor\"") {
                if let Some(start) = line.find('=') {
                    current_vendor_id = Some(line[start+1..].trim().trim_matches('"').to_string());
                }
            } else if line.contains("\"idProduct\"") {
                if let Some(start) = line.find('=') {
                    current_product_id = Some(line[start+1..].trim().trim_matches('"').to_string());
                }
            } else if line.contains("\"USB Serial Number\"") {
                if let Some(start) = line.find('=') {
                    current_serial = Some(line[start+1..].trim().trim_matches('"').to_string());
                }
} else if line.contains("IOUSBDevice") && !current_name.is_empty() {
                // End of a device entry, save it
                if let (Some(vid), Some(pid)) = (&current_vendor_id, &current_product_id) {
                    devices.push(crate::models::ConnectedDevice {
                        id: format!("usb:{}:{}", vid, pid),
                        name: current_name.clone(),
                        device_type: crate::models::DeviceType::Usb,
                        vendor: None,
                        product_id: Some(pid.clone()),
                        vendor_id: Some(vid.clone()),
                        serial_number: current_serial.clone(),
                        driver: None,
                        bus_location: None,
                        entry_id: None,
                        is_hub: false,
                        connected_at: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs(),
                        last_seen: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs(),
                        is_connected: true,
                    });
                }
                current_name.clear();
                current_vendor_id = None;
                current_product_id = None;
                current_serial = None;
            }
        }
        
        devices
    }

    /// Enumerate USB devices — tries system_profiler first, falls back to ioreg
    pub fn enumerate_usb_devices(&self) -> Vec<crate::models::ConnectedDevice> {
        let devices = self.enumerate_usb_devices_sp();
        if devices.is_empty() {
            self.enumerate_usb_devices_ioreg()
        } else {
            devices
        }
    }

    /// Enumerate Bluetooth devices using system_profiler
    /// Devices are listed as {"Device Name": {properties}} under device_connected and device_not_connected
    /// BLE devices are detected via device_services containing "BLE"
    pub fn enumerate_bluetooth_devices(&self) -> Vec<crate::models::ConnectedDevice> {
        let mut devices = Vec::new();
        
        let output = match std::process::Command::new("system_profiler")
            .args(["SPBluetoothDataType", "-json"])
            .output()
        {
            Ok(o) => o,
            Err(_) => return devices,
        };
        
        let stdout = String::from_utf8_lossy(&output.stdout);
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
            if let Some(items) = json.get("SPBluetoothDataType").and_then(|v| v.as_array()) {
                for item in items {
                    // Process connected devices
                    Self::extract_bluetooth_devices_from_list(
                        item.get("device_connected").and_then(|v| v.as_array()),
                        true,
                        &mut devices,
                    );
                    // Process not-connected devices (for history)
                    Self::extract_bluetooth_devices_from_list(
                        item.get("device_not_connected").and_then(|v| v.as_array()),
                        false,
                        &mut devices,
                    );
                }
            }
        }
        
        devices
    }

    /// Extract Bluetooth devices from a list of {"name": {props}} dicts
    fn extract_bluetooth_devices_from_list(
        list: Option<&Vec<serde_json::Value>>,
        is_connected: bool,
        devices: &mut Vec<crate::models::ConnectedDevice>,
    ) {
        if let Some(list) = list {
            for dev_entry in list {
                // Each entry is {"Device Name": {properties}}
                for (dev_name, dev_props) in dev_entry.as_object().unwrap_or(&serde_json::Map::new()) {
                    let name = dev_name.clone();
                    let address = dev_props.get("device_address").and_then(|v| v.as_str()).map(|s| s.to_string());
                    let vendor_id = dev_props.get("device_vendorID").and_then(|v| v.as_str()).map(|s| s.to_string());
                    let product_id = dev_props.get("device_productID").and_then(|v| v.as_str()).map(|s| s.to_string());
                    let serial = dev_props.get("device_serialNumber").and_then(|v| v.as_str()).map(|s| s.to_string());
                    
                    // Detect BLE via device_services containing "BLE"
                    let is_ble = dev_props.get("device_services")
                        .and_then(|v| v.as_str())
                        .map(|s| s.contains("BLE"))
                        .unwrap_or(false);
                    
                    let device_type = if is_ble {
                        crate::models::DeviceType::BluetoothLe
                    } else {
                        crate::models::DeviceType::Bluetooth
                    };
                    
                    devices.push(crate::models::ConnectedDevice {
                        id: format!("bt:{}", address.as_deref().unwrap_or("unknown")),
                        name,
                        device_type,
                        vendor: None,
                        product_id,
                        vendor_id,
                        serial_number: serial.or_else(|| address.clone()),
                        driver: None,
                        bus_location: None,
                        entry_id: None,
                        is_hub: false,
                        connected_at: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs(),
                        last_seen: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs(),
                        is_connected,
                    });
                }
            }
        }
    }

    /// Enumerate all connected devices (USB + Bluetooth)
    pub fn enumerate_all_devices(&self) -> Vec<crate::models::ConnectedDevice> {
        let mut devices = self.enumerate_usb_devices();
        devices.extend(self.enumerate_bluetooth_devices());
        devices
    }

    /// Detect virtual machine environments on macOS
    pub fn detect_virtual_machine(&self) -> Option<String> {
        // Check system_profiler for VM indicators
        if let Ok(output) = std::process::Command::new("system_profiler").args(["SPHardwareDataType"]).output() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if stdout.contains("VMware") || stdout.contains("VirtualBox") || stdout.contains("Parallels") || stdout.contains("QEMU") {
                return Some("VM detected via system_profiler".to_string());
            }
        }

        // Check for VM guest tools
        if std::path::Path::new("/Library/Application Support/VMware Tools").exists() {
            return Some("VM detected: VMware Tools".to_string());
        }
        if std::path::Path::new("/Library/Application Support/VirtualBox").exists() {
            return Some("VM detected: VirtualBox".to_string());
        }
        if std::path::Path::new("/Library/Parallels").exists() {
            return Some("VM detected: Parallels".to_string());
        }

        // Check sysctl for hypervisor
        if let Ok(output) = std::process::Command::new("sysctl").args(["kern.hv_vmm_present"]).output() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if stdout.contains("1") {
                return Some("VM detected: hypervisor present via sysctl".to_string());
            }
        }

        None
    }
}
