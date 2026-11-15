use std::sync::{Arc, Mutex};
use nodesec_core::{
    models::Platform,
    network::{linux::LinuxNetworkMonitor, macos::MacOSNetworkMonitor, windows::WindowsNetworkMonitor, common::NetworkMonitor},
    threat::ThreatDetector,
};
use tokio::task::spawn_blocking;

pub fn start_monitoring(
    monitor_state: Arc<crate::state::MonitorState>,
) {
    // Check if already monitoring
    if *monitor_state.monitoring.lock().unwrap() {
        return;
    }
    *monitor_state.monitoring.lock().unwrap() = true;

    let platform = monitor_state.platform;
    let connections = monitor_state.connections.clone();
    let alerts = monitor_state.alerts.clone();
    let stats = monitor_state.stats.clone();
    let monitor = monitor_state.monitor.clone();
    let monitoring_flag = monitor_state.monitoring.clone();

    tokio::spawn(async move {
        // Create platform-specific monitor
        let monitor_impl: Box<dyn nodesec_core::network::common::NetworkMonitor + Send> = match platform {
            Platform::Linux => Box::new(LinuxNetworkMonitor::new()),
            Platform::MacOS => Box::new(MacOSNetworkMonitor::new()),
            Platform::Windows => Box::new(WindowsNetworkMonitor::new()),
            Platform::Unknown => Box::new(LinuxNetworkMonitor::new()),
        };

        // Store monitor
        {
            let mut m = monitor.lock().await;
            *m = Some(monitor_impl);
        }

        // Set exclusion list on the monitor
        {
            let exclusion_list = monitor_state.exclusion_list.clone();
            let mut m = monitor.lock().await;
            if let Some(mon) = m.as_mut() {
                mon.set_exclusion_list(exclusion_list);
            }
        }

        // Start the monitor
        {
            let mut m = monitor.lock().await;
            if let Some(mon) = m.as_mut() {
                let _ = mon.start().await;
            }
        }

        let scan_interval = monitor_state.scan_settings.lock().unwrap().scan_interval_seconds;

        loop {
            // Check if still monitoring
            if !*monitoring_flag.lock().unwrap() {
                break;
            }

            tokio::time::sleep(std::time::Duration::from_secs(scan_interval)).await;

            // Check if still monitoring
            if !*monitoring_flag.lock().unwrap() {
                break;
            }

            // Scan for connections using spawn_blocking to avoid blocking the runtime
            let monitor_clone = monitor.clone();
            let scan_result = spawn_blocking(move || {
                let mut monitor_guard = monitor_clone.blocking_lock();
                if let Some(mon) = monitor_guard.as_mut() {
                    mon.scan_once_blocking()
                } else {
                    Ok(())
                }
            }).await;

            if let Err(e) = scan_result {
                eprintln!("Scan task error: {}", e);
            } else if let Err(e) = scan_result.unwrap() {
                eprintln!("Scan error: {}", e);
            }

            // Drain events from monitor and push to shared state
            let events = {
                let mut monitor_guard = monitor.lock().await;
                if let Some(mon) = monitor_guard.as_mut() {
                    mon.drain_events().await
                } else {
                    Vec::new()
                }
            };

            for event in events {
                // Apply threat detection
                let threat_score = {
                    let mut detector = monitor_state.threat_detector.lock().unwrap();
                    detector.analyze(&mut event.clone())
                };
                let threat_level = crate::state::threat_level_from_score(threat_score);
                let is_suspicious = threat_score >= 50;

                // Add to connections
                {
                    let mut conns = connections.lock().unwrap();
                    conns.insert(0, crate::state::ConnectionItem {
                        connection: event.clone(),
                        threat_level,
                    });
                    if conns.len() > 1000 {
                        conns.truncate(1000);
                    }
                }

                // Add alert if suspicious
                if is_suspicious {
                    let alert = crate::state::AlertEntry {
                        timestamp: chrono::Local::now().format("%H:%M:%S").to_string(),
                        process_name: event.process_name.clone(),
                        dst_ip: event.dst_ip.to_string(),
                        dst_port: event.dst_port,
                        pid: event.pid,
                        threat_score,
                        is_suspicious: true,
                        dismissed: false,
                    };
                    monitor_state.add_alert(alert);
                }

                // Update stats
                {
                    let mut st = stats.lock().unwrap();
                    st.total += 1;
                    if is_suspicious {
                        st.suspicious += 1;
                    }
                    if threat_level == crate::state::ThreatLevel::Critical {
                        st.critical += 1;
                    }
                }
            }
        }
    });
}

pub fn stop_monitoring(monitoring: Arc<Mutex<bool>>) {
    *monitoring.lock().unwrap() = false;
}

/// Terminate a process by PID
pub fn terminate_process(pid: u32, process_name: &str, monitor_state: &crate::state::MonitorState) {
    #[cfg(target_os = "macos")]
    {
        let result = std::process::Command::new("kill").args(["-9", &pid.to_string()]).status();
        let success = result.map(|s| s.success()).unwrap_or(false);
        monitor_state.add_action_log(crate::state::ActionLogEntry {
            timestamp: chrono::Local::now().format("%H:%M:%S").to_string(),
            action: crate::state::ActionType::Terminate,
            pid,
            process_name: process_name.to_string(),
            port: None,
            ip: None,
            rule: format!("kill -9 {}", pid),
            success,
            details: if success { "Process terminated".to_string() } else { "Failed to terminate".to_string() },
        });
        // Add to terminated_pids so cells disappear from process tree
        if success {
            monitor_state.terminated_pids.lock().unwrap().insert(pid);
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (pid, process_name, monitor_state);
    }
}

/// Block connections to an IP address
pub fn block_ip(ip: &str, pid: u32, process_name: &str, monitor_state: &crate::state::MonitorState) {
    #[cfg(target_os = "macos")]
    {
        // Use pfctl to block the IP
        let result = std::process::Command::new("pfctl")
            .args(["-t", "blocklist", "-T", "add", ip])
            .status();
        let success = result.map(|s| s.success()).unwrap_or(false);
        monitor_state.add_action_log(crate::state::ActionLogEntry {
            timestamp: chrono::Local::now().format("%H:%M:%S").to_string(),
            action: crate::state::ActionType::BlockIP,
            pid,
            process_name: process_name.to_string(),
            port: None,
            ip: Some(ip.to_string()),
            rule: format!("pfctl block {}", ip),
            success,
            details: if success { "IP blocked".to_string() } else { "Failed to block IP".to_string() },
        });
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (ip, pid, process_name, monitor_state);
    }
}

/// Block connections on a port
pub fn block_port(port: u16, pid: u32, process_name: &str, monitor_state: &crate::state::MonitorState) {
    #[cfg(target_os = "macos")]
    {
        // Use pfctl to block the port
        let result = std::process::Command::new("pfctl")
            .args(["-t", "blocklist", "-T", "add", &format!("port {}", port)])
            .status();
        let success = result.map(|s| s.success()).unwrap_or(false);
        monitor_state.add_action_log(crate::state::ActionLogEntry {
            timestamp: chrono::Local::now().format("%H:%M:%S").to_string(),
            action: crate::state::ActionType::BlockPort,
            pid,
            process_name: process_name.to_string(),
            port: Some(port),
            ip: None,
            rule: format!("pfctl block port {}", port),
            success,
            details: if success { "Port blocked".to_string() } else { "Failed to block port".to_string() },
        });
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (port, pid, process_name, monitor_state);
    }
}