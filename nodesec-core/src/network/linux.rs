//! Linux network monitoring using /proc/net/tcp and netlink sockets

use crate::models::{MonitorMode, NetworkProtocol, Platform, ExclusionList};
use crate::network::common::{NetworkConnection, NetworkMonitor};
use anyhow::Result;
use std::collections::VecDeque;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;
use tokio::time::{interval, Duration};

pub struct LinuxNetworkMonitor {
    events: Arc<Mutex<VecDeque<NetworkConnection>>>,
    running: Arc<Mutex<bool>>,
    pid_cache: Arc<Mutex<std::collections::HashMap<u32, (u32, String, Option<String>, Option<String>, Option<String>)>>>,
    exclusion_list: Arc<StdMutex<ExclusionList>>,
}

impl LinuxNetworkMonitor {
    pub fn new() -> Self {
        Self {
            events: Arc::new(Mutex::new(VecDeque::with_capacity(10000))),
            running: Arc::new(Mutex::new(false)),
            pid_cache: Arc::new(Mutex::new(std::collections::HashMap::new())),
            exclusion_list: Arc::new(StdMutex::new(ExclusionList::default())),
        }
    }

    /// Static helper for fuzzing /proc/net/tcp line parsing
    pub fn parse_proc_net_line_static(line: &str, is_ipv6: bool) -> Result<Option<(IpAddr, u16, IpAddr, u16)>> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 10 {
            return Ok(None);
        }

        let local = parts[1];
        let remote = parts[2];

        let (src_ip, src_port) = Self::parse_addr_port_static(local, is_ipv6)?;
        let (dst_ip, dst_port) = Self::parse_addr_port_static(remote, is_ipv6)?;

        if dst_port == 0 {
            return Ok(None);
        }

        Ok(Some((src_ip, src_port, dst_ip, dst_port)))
    }

    /// Static helper for fuzzing /proc/net/tcp content
    pub fn parse_proc_net_tcp_static(content: &str) -> Result<Vec<(IpAddr, u16, IpAddr, u16)>> {
        let mut results = Vec::new();
        for line in content.lines().skip(1) {
            if let Some((src_ip, src_port, dst_ip, dst_port)) = Self::parse_proc_net_line_static(line, false)? {
                results.push((src_ip, src_port, dst_ip, dst_port));
            }
        }
        Ok(results)
    }

    /// Static helper for fuzzing /proc/net/udp content
    pub fn parse_proc_net_udp_static(content: &str) -> Result<Vec<(IpAddr, u16, IpAddr, u16)>> {
        let mut results = Vec::new();
        for line in content.lines().skip(1) {
            if let Some((src_ip, src_port, dst_ip, dst_port)) = Self::parse_proc_net_line_static(line, false)? {
                results.push((src_ip, src_port, dst_ip, dst_port));
            }
        }
        Ok(results)
    }

    /// Static helper for fuzzing address:port parsing from /proc/net format
    pub fn parse_addr_port_static(addr_port: &str, is_ipv6: bool) -> Result<(IpAddr, u16)> {
        let parts: Vec<&str> = addr_port.split(':').collect();
        if parts.len() != 2 {
            return Err(anyhow::anyhow!("Invalid addr:port format"));
        }

        let ip_hex = parts[0];
        let port_hex = parts[1];
        let port = u16::from_str_radix(port_hex, 16)?;

        let ip = if is_ipv6 {
            let bytes: Vec<u8> = (0..ip_hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&ip_hex[i..i+2], 16).unwrap_or(0))
                .collect();
            if bytes.len() == 16 {
                IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(bytes).unwrap()))
            } else {
                return Err(anyhow::anyhow!("Invalid IPv6 address length"));
            }
        } else {
            let ip_val = u32::from_str_radix(ip_hex, 16)?;
            IpAddr::V4(Ipv4Addr::from(ip_val.to_le_bytes()))
        };

        Ok((ip, port))
    }

    async fn scan_connections(&self) -> Result<()> {
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

        // Scan TCP connections
        self.scan_tcp_connections(timestamp).await?;
        // Scan UDP connections
        self.scan_udp_connections(timestamp).await?;

        Ok(())
    }

    async fn scan_tcp_connections(&self, timestamp: u64) -> Result<()> {
        // IPv4 TCP
        if let Ok(content) = fs::read_to_string("/proc/net/tcp") {
            for line in content.lines().skip(1) {
                if let Some(event) = self.parse_proc_net_line(line, timestamp, NetworkProtocol::Tcp, false).await? {
                    if self.is_excluded(&event) {
                        continue;
                    }
                    self.add_event(event).await;
                }
            }
        }

        // IPv6 TCP
        if let Ok(content) = fs::read_to_string("/proc/net/tcp6") {
            for line in content.lines().skip(1) {
                if let Some(event) = self.parse_proc_net_line(line, timestamp, NetworkProtocol::Tcp, true).await? {
                    if self.is_excluded(&event) {
                        continue;
                    }
                    self.add_event(event).await;
                }
            }
        }

        Ok(())
    }

    async fn scan_udp_connections(&self, timestamp: u64) -> Result<()> {
        // IPv4 UDP
        if let Ok(content) = fs::read_to_string("/proc/net/udp") {
            for line in content.lines().skip(1) {
                if let Some(event) = self.parse_proc_net_line(line, timestamp, NetworkProtocol::Udp, false).await? {
                    if self.is_excluded(&event) {
                        continue;
                    }
                    self.add_event(event).await;
                }
            }
        }

        // IPv6 UDP
        if let Ok(content) = fs::read_to_string("/proc/net/udp6") {
            for line in content.lines().skip(1) {
                if let Some(event) = self.parse_proc_net_line(line, timestamp, NetworkProtocol::Udp, true).await? {
                    if self.is_excluded(&event) {
                        continue;
                    }
                    self.add_event(event).await;
                }
            }
        }

        Ok(())
    }

    async fn parse_proc_net_line(
        &self,
        line: &str,
        timestamp: u64,
        protocol: NetworkProtocol,
        is_ipv6: bool,
    ) -> Result<Option<NetworkConnection>> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 10 {
            return Ok(None);
        }

        // parts[1] = local_address:port (hex)
        // parts[2] = remote_address:port (hex)
        // parts[9] = inode

        let local = parts[1];
        let remote = parts[2];
        let inode = parts[9].parse::<u64>().unwrap_or(0);

        let (src_ip, src_port) = self.parse_addr_port(local, is_ipv6)?;
        let (dst_ip, dst_port) = self.parse_addr_port(remote, is_ipv6)?;

        // Skip listening ports (remote port 0)
        if dst_port == 0 {
            return Ok(None);
        }

        // Find PID from inode
        let (pid, process_name, process_path, command_line, user) = self.find_process_by_inode(inode).await;

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

    fn parse_addr_port(&self, addr_port: &str, is_ipv6: bool) -> Result<(IpAddr, u16)> {
        let parts: Vec<&str> = addr_port.split(':').collect();
        if parts.len() != 2 {
            return Err(anyhow::anyhow!("Invalid addr:port format"));
        }

        let ip_hex = parts[0];
        let port_hex = parts[1];
        let port = u16::from_str_radix(port_hex, 16)?;

        let ip = if is_ipv6 {
            // IPv6 address in hex (32 chars)
            let bytes: Vec<u8> = (0..ip_hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&ip_hex[i..i+2], 16).unwrap_or(0))
                .collect();
            if bytes.len() == 16 {
                IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(bytes).unwrap()))
            } else {
                return Err(anyhow::anyhow!("Invalid IPv6 address length"));
            }
        } else {
            // IPv4 address in hex (8 chars, little-endian)
            let ip_val = u32::from_str_radix(ip_hex, 16)?;
            IpAddr::V4(Ipv4Addr::from(ip_val.to_le_bytes()))
        };

        Ok((ip, port))
    }

    async fn find_process_by_inode(&self, inode: u64) -> (u32, String, Option<String>, Option<String>, Option<String>) {
        // Check cache first
        {
            let cache = self.pid_cache.lock().await;
            if let Some(cached) = cache.get(&(inode as u32)) {
                return (cached.0, cached.1.clone(), cached.2.clone(), cached.3.clone(), cached.4.clone());
            }
        }

        // Search /proc/*/fd/ for socket inode
        let mut pid = 0;
        let mut process_name = "unknown".to_string();
        let mut process_path = None;
        let mut command_line = None;
        let mut user = None;

        if let Ok(entries) = fs::read_dir("/proc") {
            for entry in entries.flatten() {
                if let Ok(pid_str) = entry.file_name().to_string_lossy().parse::<u32>() {
                    let fd_path = format!("/proc/{}/fd", pid_str);
                    if let Ok(fd_entries) = fs::read_dir(&fd_path) {
                        for fd_entry in fd_entries.flatten() {
                            if let Ok(target) = fs::read_link(fd_entry.path()) {
                                let target_str = target.to_string_lossy();
                                if target_str.contains(&format!("socket:[{}]", inode)) {
                                    pid = pid_str;
                                    // Get process info
                                    if let Ok(comm) = fs::read_to_string(format!("/proc/{}/comm", pid_str)) {
                                        process_name = comm.trim().to_string();
                                    }
                                    if let Ok(exe) = fs::read_link(format!("/proc/{}/exe", pid_str)) {
                                        process_path = Some(exe.to_string_lossy().to_string());
                                    }
                                    if let Ok(cmdline) = fs::read_to_string(format!("/proc/{}/cmdline", pid_str)) {
                                        command_line = Some(cmdline.replace('\0', " ").trim().to_string());
                                    }
                                    // Get user from /proc/<pid>/status
                                    if let Ok(status) = fs::read_to_string(format!("/proc/{}/status", pid_str)) {
                                        for line in status.lines() {
                                            if line.starts_with("Uid:") {
                                                let parts: Vec<&str> = line.split_whitespace().collect();
                                                if parts.len() >= 2 {
                                                    if let Ok(uid) = parts[1].parse::<u32>() {
                                                        user = Some(uid.to_string());
                                                    }
                                                }
                                                break;
                                            }
                                        }
                                    }
                                    break;
                                }
                            }
                        }
                    }
                    if pid != 0 {
                        break;
                    }
                }
            }
        }

        // Cache the result
        {
            let mut cache = self.pid_cache.lock().await;
            cache.insert(inode as u32, (pid, process_name.clone(), process_path.clone(), command_line.clone(), user.clone()));
            // Limit cache size
            if cache.len() > 1000 {
                let keys_to_remove: Vec<u32> = cache.keys().take(100).cloned().collect();
                for k in keys_to_remove {
                    cache.remove(&k);
                }
            }
        }

        (pid, process_name, process_path, command_line, user)
    }

    async fn add_event(&self, event: NetworkConnection) {
        let mut events = self.events.lock().await;
        events.push_back(event);
        // Keep only last 10000 events
        while events.len() > 10000 {
            events.pop_front();
        }
    }
}

impl Default for LinuxNetworkMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl NetworkMonitor for LinuxNetworkMonitor {
    async fn start(&mut self) -> Result<()> {
        *self.running.lock().await = true;
        let _events = self.events.clone();
        let running = self.running.clone();

        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(1));
            while *running.lock().await {
                interval.tick().await;
                // The actual scanning will be triggered by the connection handler
                // This is a placeholder for periodic tasks
            }
        });

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
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let rt = tokio::runtime::Runtime::new()?;
        rt.block_on(self.scan_connections_blocking(timestamp))
    }

    fn events(&self) -> Arc<Mutex<VecDeque<NetworkConnection>>> {
        self.events.clone()
    }

    fn platform(&self) -> Platform {
        Platform::Linux
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

impl LinuxNetworkMonitor {
    /// Blocking scan for connections (for use in background threads)
    pub fn scan_once_blocking(&mut self) -> Result<()> {
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let rt = tokio::runtime::Runtime::new()?;
        rt.block_on(self.scan_connections_blocking(timestamp))
    }

    /// Internal blocking scan implementation
    async fn scan_connections_blocking(&self, timestamp: u64) -> Result<()> {
        // Scan TCP connections
        self.scan_tcp_connections(timestamp).await?;
        // Scan UDP connections
        self.scan_udp_connections(timestamp).await?;
        Ok(())
    }

    /// Scan connections once (called by ConnectionHandler)
    pub async fn scan_once(&self) -> Result<()> {
        self.scan_connections().await
    }

    /// Enumerate USB devices using lsusb
    pub fn enumerate_usb_devices(&self) -> Vec<crate::models::ConnectedDevice> {
        let mut devices = Vec::new();
        
        let output = match std::process::Command::new("lsusb").output() {
            Ok(o) => o,
            Err(_) => return devices,
        };
        
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            // lsusb format: Bus 001 Device 003: ID 046d:c52b Logitech, Inc. Unifying Receiver
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 6 {
                continue;
            }
            
            // Find the ID field (format: xxxx:yyyy)
            let id_field = parts.iter().find(|p| p.contains(':') && p.len() == 7 && p.chars().nth(4) == Some(':'));
            if let Some(id) = id_field {
                let id_parts: Vec<&str> = id.split(':').collect();
                if id_parts.len() == 2 {
                    let vendor_id = id_parts[0].to_string();
                    let product_id = id_parts[1].to_string();
                    
                    // Everything after the ID is the device name
                    let id_index = parts.iter().position(|p| *p == *id).unwrap_or(0);
                    let name = parts[id_index + 1..].join(" ");
                    
                    devices.push(crate::models::ConnectedDevice {
                        id: format!("usb:{}:{}", vendor_id, product_id),
                        name,
                        device_type: crate::models::DeviceType::Usb,
                        vendor: None,
                        product_id: Some(product_id),
                        vendor_id: Some(vendor_id),
                        serial_number: None,
                        connected_at: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs(),
                        last_seen: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs(),
                        is_connected: true,
                    });
                }
            }
        }
        
        devices
    }

    /// Enumerate Bluetooth devices using bluetoothctl
    pub fn enumerate_bluetooth_devices(&self) -> Vec<crate::models::ConnectedDevice> {
        let mut devices = Vec::new();
        
        let output = match std::process::Command::new("bluetoothctl").args(["devices"]).output() {
            Ok(o) => o,
            Err(_) => return devices,
        };
        
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            // bluetoothctl devices format: Device XX:XX:XX:XX:XX:XX Device Name
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 3 {
                continue;
            }
            
            if parts[0] == "Device" {
                let address = parts[1].to_string();
                let name = parts[2..].join(" ");
                
                devices.push(crate::models::ConnectedDevice {
                    id: format!("bt:{}", address),
                    name,
                    device_type: crate::models::DeviceType::Bluetooth,
                    vendor: None,
                    product_id: None,
                    vendor_id: None,
                    serial_number: Some(address),
                    connected_at: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs(),
                    last_seen: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs(),
                    is_connected: true,
                });
            }
        }
        
        devices
    }

    /// Detect virtual machine environments on Linux
    pub fn detect_virtual_machine(&self) -> Option<String> {
        // Check /sys/class/dmi/id/sys_vendor
        if let Ok(vendor) = std::fs::read_to_string("/sys/class/dmi/id/sys_vendor") {
            let vendor = vendor.trim();
            if vendor.contains("VMware") || vendor.contains("QEMU") || vendor.contains("Xen") || vendor.contains("KVM") || vendor.contains("Microsoft") {
                return Some(format!("VM detected: {}", vendor));
            }
        }
        
        // Check /sys/class/dmi/id/product_name
        if let Ok(product) = std::fs::read_to_string("/sys/class/dmi/id/product_name") {
            let product = product.trim();
            if product.contains("VirtualBox") || product.contains("VMware") || product.contains("QEMU") {
                return Some(format!("VM detected: {}", product));
            }
        }
        
        // Check /proc/cpuinfo for hypervisor flag
        if let Ok(cpuinfo) = std::fs::read_to_string("/proc/cpuinfo") {
            if cpuinfo.contains("hypervisor") {
                return Some("VM detected: hypervisor flag in /proc/cpuinfo".to_string());
            }
        }
        
        // Check for VM kernel modules
        if let Ok(modules) = std::fs::read_to_string("/proc/modules") {
            if modules.contains("vboxguest") || modules.contains("vmw_balloon") || modules.contains("vmwgfx") {
                return Some("VM detected: VM guest kernel modules loaded".to_string());
            }
        }
        
        None
    }
}