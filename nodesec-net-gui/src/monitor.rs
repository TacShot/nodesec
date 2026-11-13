use std::sync::{Arc, Mutex};
use std::time::Duration;
use nodesec_core::{
    models::{NetworkConnection, Platform},
    network::{linux::LinuxNetworkMonitor, macos::MacOSNetworkMonitor, windows::WindowsNetworkMonitor, common::NetworkMonitor},
};
use tokio::time::sleep;

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
        
        // Start the monitor
        {
            let mut m = monitor.lock().await;
            if let Some(mon) = m.as_mut() {
                let _ = mon.start().await;
            }
        }
        
        loop {
            // Check if still monitoring
            if !*monitoring_flag.lock().unwrap() {
                break;
            }
            
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            
            // Check if still monitoring
            if !*monitoring_flag.lock().unwrap() {
                break;
            }
            
            // Scan for connections
            {
                let mut monitor_guard = monitor.lock().await;
                if let Some(mon) = monitor_guard.as_mut() {
                    if let Err(e) = mon.scan_once().await {
                        eprintln!("Scan error: {}", e);
                    }
                }
            }
            
            // Drain events from monitor and push to shared state
            {
                let monitor_guard = monitor.lock().await;
                if let Some(mon) = monitor_guard.as_ref() {
                    let events = mon.drain_events().await;
                    for event in events {
                        let threat_level = crate::state::threat_level_from_score(event.threat_score);
                        let is_suspicious = event.is_suspicious;
                        
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
                            let mut alts = alerts.lock().unwrap();
                            alts.insert(0, format!(
                                "[{}] {} -> {}:{} (PID: {}, Score: {})",
                                chrono::Local::now().format("%H:%M:%S"),
                                event.process_name,
                                event.dst_ip,
                                event.dst_port,
                                event.pid,
                                event.threat_score
                            ));
                            if alts.len() > 100 {
                                alts.truncate(100);
                            }
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
            }
        }
    });
}

pub fn stop_monitoring(monitoring: Arc<Mutex<bool>>) {
    *monitoring.lock().unwrap() = false;
}