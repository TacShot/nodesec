//! Windows network monitoring using GetExtendedTcpTable and ETW

use crate::models::{MonitorMode, NetworkProtocol, Platform};
use crate::network::common::{NetworkConnection, NetworkMonitor};
use anyhow::{Context, Result};
use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;

#[cfg(target_os = "windows")]
use windows::Win32::NetworkManagement::IpHelper::*;
#[cfg(target_os = "windows")]
use windows::Win32::Foundation::*;
#[cfg(target_os = "windows")]
use windows::Win32::Networking::WinSock::*;

pub struct WindowsNetworkMonitor {
    events: Arc<Mutex<VecDeque<NetworkConnection>>>,
    running: Arc<Mutex<bool>>,
}

impl WindowsNetworkMonitor {
    pub fn new() -> Self {
        Self {
            events: Arc::new(Mutex::new(VecDeque::with_capacity(10000))),
            running: Arc::new(Mutex::new(false)),
        }
    }

    async fn scan_connections(&self) -> Result<()> {
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

        #[cfg(target_os = "windows")]
        {
            self.scan_tcp_table(timestamp).await?;
            self.scan_udp_table(timestamp).await?;
        }

        #[cfg(not(target_os = "windows"))]
        {
            // Stub for non-Windows compilation
        }

        Ok(())
    }

    #[cfg(target_os = "windows")]
    async fn scan_tcp_table(&self, timestamp: u64) -> Result<()> {
        unsafe {
            // Get TCP table for IPv4
            let mut size = 0u32;
            let result = GetExtendedTcpTable(
                std::ptr::null_mut(),
                &mut size,
                true,
                AF_INET as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            );

            if result != 0 && size > 0 {
                let mut buffer = vec![0u8; size as usize];
                let result = GetExtendedTcpTable(
                    buffer.as_mut_ptr() as *mut _,
                    &mut size,
                    true,
                    AF_INET as u32,
                    TCP_TABLE_OWNER_PID_ALL,
                    0,
                );

                if result == 0 {
                    let table = &*(buffer.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
                    for i in 0..table.dwNumEntries as usize {
                        let row = &table.table[i];
                        let event = self.parse_tcp_row(row, timestamp, false)?;
                        self.add_event(event).await;
                    }
                }
            }

            // Get TCP table for IPv6
            let mut size = 0u32;
            let result = GetExtendedTcpTable(
                std::ptr::null_mut(),
                &mut size,
                true,
                AF_INET6 as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            );

            if result != 0 && size > 0 {
                let mut buffer = vec![0u8; size as usize];
                let result = GetExtendedTcpTable(
                    buffer.as_mut_ptr() as *mut _,
                    &mut size,
                    true,
                    AF_INET6 as u32,
                    TCP_TABLE_OWNER_PID_ALL,
                    0,
                );

                if result == 0 {
                    let table = &*(buffer.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID);
                    for i in 0..table.dwNumEntries as usize {
                        let row = &table.table[i];
                        let event = self.parse_tcp_row_v6(row, timestamp)?;
                        self.add_event(event).await;
                    }
                }
            }
        }

        Ok(())
    }

    #[cfg(target_os = "windows")]
    async fn scan_udp_table(&self, timestamp: u64) -> Result<()> {
        unsafe {
            // Get UDP table for IPv4
            let mut size = 0u32;
            let result = GetExtendedUdpTable(
                std::ptr::null_mut(),
                &mut size,
                true,
                AF_INET as u32,
                UDP_TABLE_OWNER_PID,
                0,
            );

            if result != 0 && size > 0 {
                let mut buffer = vec![0u8; size as usize];
                let result = GetExtendedUdpTable(
                    buffer.as_mut_ptr() as *mut _,
                    &mut size,
                    true,
                    AF_INET as u32,
                    UDP_TABLE_OWNER_PID,
                    0,
                );

                if result == 0 {
                    let table = &*(buffer.as_ptr() as *const MIB_UDPTABLE_OWNER_PID);
                    for i in 0..table.dwNumEntries as usize {
                        let row = &table.table[i];
                        let event = self.parse_udp_row(row, timestamp, false)?;
                        self.add_event(event).await;
                    }
                }
            }

            // Get UDP table for IPv6
            let mut size = 0u32;
            let result = GetExtendedUdpTable(
                std::ptr::null_mut(),
                &mut size,
                true,
                AF_INET6 as u32,
                UDP_TABLE_OWNER_PID,
                0,
            );

            if result != 0 && size > 0 {
                let mut buffer = vec![0u8; size as usize];
                let result = GetExtendedUdpTable(
                    buffer.as_mut_ptr() as *mut _,
                    &mut size,
                    true,
                    AF_INET6 as u32,
                    UDP_TABLE_OWNER_PID,
                    0,
                );

                if result == 0 {
                    let table = &*(buffer.as_ptr() as *const MIB_UDP6TABLE_OWNER_PID);
                    for i in 0..table.dwNumEntries as usize {
                        let row = &table.table[i];
                        let event = self.parse_udp_row_v6(row, timestamp)?;
                        self.add_event(event).await;
                    }
                }
            }
        }

        Ok(())
    }

    #[cfg(target_os = "windows")]
    fn parse_tcp_row(&self, row: &MIB_TCPROW_OWNER_PID, timestamp: u64, _is_v6: bool) -> Result<NetworkConnection> {
        let src_ip = IpAddr::V4(Ipv4Addr::from(row.dwLocalAddr.to_le_bytes()));
        let dst_ip = IpAddr::V4(Ipv4Addr::from(row.dwRemoteAddr.to_le_bytes()));
        let src_port = u16::from_be(row.dwLocalPort as u16);
        let dst_port = u16::from_be(row.dwRemotePort as u16);
        let pid = row.dwOwningPid;

        // Skip listening ports
        if dst_port == 0 {
            return Err(anyhow::anyhow!("Listening port"));
        }

        let (process_name, process_path, command_line, user) = self.get_process_info(pid).await;

        Ok(NetworkConnection {
            timestamp,
            pid,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol: NetworkProtocol::Tcp,
            process_name,
            process_path,
            command_line,
            user,
            threat_score: 0,
            is_suspicious: false,
        })
    }

    #[cfg(target_os = "windows")]
    fn parse_tcp_row_v6(&self, row: &MIB_TCP6ROW_OWNER_PID, timestamp: u64) -> Result<NetworkConnection> {
        let src_ip = IpAddr::V6(Ipv6Addr::from(row.ucLocalAddr.to_le_bytes()));
        let dst_ip = IpAddr::V6(Ipv6Addr::from(row.ucRemoteAddr.to_le_bytes()));
        let src_port = u16::from_be(row.dwLocalPort as u16);
        let dst_port = u16::from_be(row.dwRemotePort as u16);
        let pid = row.dwOwningPid;

        if dst_port == 0 {
            return Err(anyhow::anyhow!("Listening port"));
        }

        let (process_name, process_path, command_line, user) = self.get_process_info(pid).await;

        Ok(NetworkConnection {
            timestamp,
            pid,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol: NetworkProtocol::Tcp,
            process_name,
            process_path,
            command_line,
            user,
            threat_score: 0,
            is_suspicious: false,
        })
    }

    #[cfg(target_os = "windows")]
    fn parse_udp_row(&self, row: &MIB_UDPROW_OWNER_PID, timestamp: u64, _is_v6: bool) -> Result<NetworkConnection> {
        let src_ip = IpAddr::V4(Ipv4Addr::from(row.dwLocalAddr.to_le_bytes()));
        let dst_ip = IpAddr::V4(Ipv4Addr::from(row.dwRemoteAddr.to_le_bytes()));
        let src_port = u16::from_be(row.dwLocalPort as u16);
        let dst_port = u16::from_be(row.dwRemotePort as u16);
        let pid = row.dwOwningPid;

        let (process_name, process_path, command_line, user) = self.get_process_info(pid).await;

        Ok(NetworkConnection {
            timestamp,
            pid,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol: NetworkProtocol::Udp,
            process_name,
            process_path,
            command_line,
            user,
            threat_score: 0,
            is_suspicious: false,
        })
    }

    #[cfg(target_os = "windows")]
    fn parse_udp_row_v6(&self, row: &MIB_UDP6ROW_OWNER_PID, timestamp: u64) -> Result<NetworkConnection> {
        let src_ip = IpAddr::V6(Ipv6Addr::from(row.ucLocalAddr.to_le_bytes()));
        let dst_ip = IpAddr::V6(Ipv6Addr::from(row.ucRemoteAddr.to_le_bytes()));
        let src_port = u16::from_be(row.dwLocalPort as u16);
        let dst_port = u16::from_be(row.dwRemotePort as u16);
        let pid = row.dwOwningPid;

        let (process_name, process_path, command_line, user) = self.get_process_info(pid).await;

        Ok(NetworkConnection {
            timestamp,
            pid,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol: NetworkProtocol::Udp,
            process_name,
            process_path,
            command_line,
            user,
            threat_score: 0,
            is_suspicious: false,
        })
    }

    #[cfg(target_os = "windows")]
    async fn get_process_info(&self, pid: u32) -> (String, Option<String>, Option<String>, Option<String>) {
        use windows::Win32::System::Diagnostics::ToolHelp::*;
        use windows::Win32::System::Threading::*;

        let mut process_name = "unknown".to_string();
        let mut process_path = None;
        let mut command_line = None;
        let mut user = None;

        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).ok();
            if let Ok(snapshot) = snapshot {
                let mut entry = PROCESSENTRY32W {
                    dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
                    ..Default::default()
                };

                if Process32FirstW(snapshot, &mut entry).is_ok() {
                    loop {
                        if entry.th32ProcessID == pid {
                            // Convert process name from wide string
                            let name_end = entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(entry.szExeFile.len());
                            process_name = String::from_utf16_lossy(&entry.szExeFile[..name_end]);
                            break;
                        }
                        if Process32NextW(snapshot, &mut entry).is_err() {
                            break;
                        }
                    }
                }
            }
        }

        // Get executable path and command line using WMI or ps
        if let Ok(output) = tokio::process::Command::new("wmic")
            .args(["process", "where", &format!("ProcessId={}", pid), "get", "ExecutablePath,CommandLine", "/format:csv"])
            .output()
            .await
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines().skip(1) {
                let parts: Vec<&str> = line.split(',').collect();
                if parts.len() >= 3 {
                    process_path = Some(parts[1].to_string());
                    command_line = Some(parts[2].to_string());
                    break;
                }
            }
        }

        // Get user via WMI
        if let Ok(output) = tokio::process::Command::new("wmic")
            .args(["process", "where", &format!("ProcessId={}", pid), "get", "GetOwner", "/format:list"])
            .output()
            .await
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                if line.starts_with("User=") {
                    user = Some(line[5..].to_string());
                    break;
                }
            }
        }

        (process_name, process_path, command_line, user)
    }

    async fn add_event(&self, event: NetworkConnection) {
        let mut events = self.events.lock().await;
        events.push_back(event);
        while events.len() > 10000 {
            events.pop_front();
        }
    }
}

impl Default for WindowsNetworkMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl NetworkMonitor for WindowsNetworkMonitor {
    async fn start(&mut self) -> Result<()> {
        *self.running.lock().await = true;
        Ok(())
    }

    async fn stop(&mut self) -> Result<()> {
        *self.running.lock().await = false;
        Ok(())
    }

    fn events(&self) -> Arc<Mutex<VecDeque<NetworkConnection>>> {
        self.events.clone()
    }

    fn platform(&self) -> Platform {
        Platform::Windows
    }

    fn mode(&self) -> MonitorMode {
        MonitorMode::OnDevice
    }
}

impl WindowsNetworkMonitor {
    /// Scan connections once (called by ConnectionHandler)
    pub async fn scan_once(&self) -> Result<()> {
        self.scan_connections().await
    }
}