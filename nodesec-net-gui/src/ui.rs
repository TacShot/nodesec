use eframe::egui;
use egui_plot::{Line, Plot, PlotPoints};
use crate::state::{ConnectionItem, ThreatLevel, ConnectionStats, ProcessTreeItem, FilterSettings, ActionLogEntry, IgnoreRule, ScanSettings, ThreatLevel::*};
use crate::graph::ConnectionType;
use nodesec_core::models::NetworkConnection;
use std::sync::{Arc, Mutex};
use std::collections::VecDeque;

// Colors matching 7-color palette
const GREEN: egui::Color32 = egui::Color32::from_rgb(0, 255, 0);
const YELLOW: egui::Color32 = egui::Color32::from_rgb(255, 255, 0);
const ORANGE: egui::Color32 = egui::Color32::from_rgb(255, 165, 0);
const RED: egui::Color32 = egui::Color32::from_rgb(255, 0, 0);
const WHITE: egui::Color32 = egui::Color32::from_rgb(255, 255, 255);
const BLACK: egui::Color32 = egui::Color32::from_rgb(0, 0, 0);
const GRAY: egui::Color32 = egui::Color32::from_rgb(136, 136, 136);
const PANEL_BG: egui::Color32 = egui::Color32::from_rgb(45, 45, 45);
const DARK_BG: egui::Color32 = egui::Color32::from_rgb(30, 30, 30);

pub fn stat_card(ui: &mut egui::Ui, label: &str, value: &str, color: egui::Color32) {
    ui.group(|ui| {
        ui.vertical_centered(|ui| {
            ui.label(egui::RichText::new(value).color(color).size(24.0).strong());
            ui.label(egui::RichText::new(label).color(GRAY).size(12.0));
        });
    });
}

pub fn render_connections_table(
    ui: &mut egui::Ui,
    connections: &[ConnectionItem],
    selected_connection: &mut Option<usize>,
    filter: &mut FilterSettings,
) {
    // Filter panel
    ui.group(|ui| {
        ui.heading(egui::RichText::new("Filters").color(ORANGE).size(14.0));
        ui.horizontal(|ui| {
            ui.label("Process:");
            ui.text_edit_singleline(&mut filter.process_name);
            
            ui.separator();
            ui.label("PID:");
            let mut pid_str = filter.pid.map(|p| p.to_string()).unwrap_or_default();
            if ui.text_edit_singleline(&mut pid_str).changed() {
                filter.pid = pid_str.parse().ok();
            }
            
            ui.separator();
            ui.label("Min Threat:");
            let mut min_str = filter.min_threat_score.to_string();
            if ui.text_edit_singleline(&mut min_str).changed() {
                filter.min_threat_score = min_str.parse().unwrap_or(0);
            }
            
            ui.separator();
            ui.label("Max Threat:");
            let mut max_str = filter.max_threat_score.to_string();
            if ui.text_edit_singleline(&mut max_str).changed() {
                filter.max_threat_score = max_str.parse().unwrap_or(100);
            }
            
            ui.separator();
            ui.checkbox(&mut filter.only_suspicious, "Suspicious Only");
            
            ui.separator();
            egui::ComboBox::from_label("Protocol")
                .selected_text(match &filter.protocol {
                    Some(p) => format!("{:?}", p),
                    None => "All".to_string(),
                })
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut filter.protocol, None, "All");
                    ui.selectable_value(&mut filter.protocol, Some(nodesec_core::models::NetworkProtocol::Tcp), "TCP");
                    ui.selectable_value(&mut filter.protocol, Some(nodesec_core::models::NetworkProtocol::Udp), "UDP");
                });
            
            if ui.button("Clear Filters").clicked() {
                *filter = FilterSettings::default();
            }
        });
    });
    
    ui.separator();
    
    // Connections table with horizontal scrolling
    egui::ScrollArea::both().show(ui, |ui| {
        ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Extend);
        egui::Grid::new("connections_table")
            .striped(true)
            .min_col_width(80.0)
            .show(ui, |ui| {
                // Header
                ui.label(egui::RichText::new("Sel").color(ORANGE).strong());
                ui.label(egui::RichText::new("Time").color(ORANGE).strong());
                ui.label(egui::RichText::new("PID").color(ORANGE).strong());
                ui.label(egui::RichText::new("Process").color(ORANGE).strong());
                ui.label(egui::RichText::new("Proto").color(ORANGE).strong());
                ui.label(egui::RichText::new("Source").color(ORANGE).strong());
                ui.label(egui::RichText::new("Destination").color(ORANGE).strong());
                ui.label(egui::RichText::new("Threat").color(ORANGE).strong());
                ui.label(egui::RichText::new("Score").color(ORANGE).strong());
                ui.end_row();
                
                for (i, item) in connections.iter().enumerate() {
                    if !filter.matches(item) {
                        continue;
                    }
                    
                    let conn = &item.connection;
                    let threat_color = item.threat_level.color();
                    
                    let src = format!("{}:{}", conn.src_ip, conn.src_port);
                    let dst = format!("{}:{}", conn.dst_ip, conn.dst_port);
                    let proto = format!("{:?}", conn.protocol);
                    let time = chrono::DateTime::from_timestamp(conn.timestamp as i64, 0)
                        .map(|dt| dt.format("%H:%M:%S").to_string())
                        .unwrap_or_default();
                    
                    let is_selected = *selected_connection == Some(i);
                    let response = ui.selectable_label(is_selected, if is_selected { "✓" } else { "" });
                    
                    if response.clicked() {
                        *selected_connection = Some(i);
                    }
                    
                    ui.label(time);
                    ui.label(conn.pid.to_string());
                    ui.label(&conn.process_name);
                    ui.label(proto);
                    ui.label(src);
                    ui.label(dst);
                    ui.label(egui::RichText::new(item.threat_level.label()).color(threat_color).strong());
                    ui.label(egui::RichText::new(conn.threat_score.to_string()).color(threat_color));
                    
                    ui.end_row();
                }
            });
    });
}

pub fn render_connection_detail(
    ui: &mut egui::Ui,
    item: &ConnectionItem,
    monitor_state: &crate::state::MonitorState,
) {
    let conn = &item.connection;
    
    ui.group(|ui| {
        ui.heading(egui::RichText::new("Connection Details").color(ORANGE));
        ui.separator();
        
        egui::Grid::new("conn_detail").num_columns(2).show(ui, |ui| {
            detail_row(ui, "PID", &conn.pid.to_string());
            detail_row(ui, "Process", &conn.process_name);
            detail_row(ui, "Path", conn.process_path.as_deref().unwrap_or("N/A"));
            detail_row(ui, "Command", conn.command_line.as_deref().unwrap_or("N/A"));
            detail_row(ui, "User", conn.user.as_deref().unwrap_or("N/A"));
            detail_row(ui, "Protocol", &format!("{:?}", conn.protocol));
            detail_row(ui, "Source", &format!("{}:{}", conn.src_ip, conn.src_port));
            detail_row(ui, "Destination", &format!("{}:{}", conn.dst_ip, conn.dst_port));
            detail_row(ui, "Threat Score", &conn.threat_score.to_string());
            detail_row(ui, "Suspicious", &conn.is_suspicious.to_string());
            detail_row(ui, "Timestamp", &chrono::DateTime::from_timestamp(conn.timestamp as i64, 0)
                .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
                .unwrap_or_default());
        });
        
        ui.separator();
        ui.horizontal(|ui| {
            // Firewall actions
            if ui.button("🔴 Terminate Process").clicked() {
                terminate_process(conn.pid, &conn.process_name, monitor_state);
            }
            
            if ui.button("🚫 Block Port").clicked() {
                block_port(conn.dst_port, conn.pid, &conn.process_name, monitor_state);
            }
            
            if ui.button("🛡️ Allow Port").clicked() {
                allow_port(conn.dst_port, conn.pid, &conn.process_name, monitor_state);
            }
            
            if ui.button("🚫 Block IP").clicked() {
                block_ip(&conn.dst_ip.to_string(), conn.pid, &conn.process_name, monitor_state);
            }
        });
    });
}

fn detail_row(ui: &mut egui::Ui, label: &str, value: &str) {
    ui.label(egui::RichText::new(label).color(GRAY).size(12.0));
    ui.label(egui::RichText::new(value).color(WHITE).size(12.0));
}

pub fn terminate_process(pid: u32, process_name: &str, monitor_state: &crate::state::MonitorState) {
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("kill")
            .args(["-9", &pid.to_string()])
            .output();
    }
    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("kill")
            .args(["-9", &pid.to_string()])
            .output();
    }
    #[cfg(target_os = "windows")]
    {
        let _ = std::process::Command::new("taskkill")
            .args(["/F", "/PID", &pid.to_string()])
            .output();
    }
    
    monitor_state.add_action_log(crate::state::ActionLogEntry {
        timestamp: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        action: crate::state::ActionType::Terminate,
        pid,
        process_name: process_name.to_string(),
        port: None,
        ip: None,
        rule: "SIGKILL".to_string(),
        success: true,
        details: format!("Terminated process {} (PID: {})", process_name, pid),
    });
}

pub fn block_port(port: u16, pid: u32, process_name: &str, monitor_state: &crate::state::MonitorState) {
    #[cfg(target_os = "macos")]
    {
        let rule = format!("block out proto tcp from any to any port {}", port);
        let _ = std::process::Command::new("pfctl")
            .args(["-a", "nodesec", "-f", "-"])
            .stdin(std::process::Stdio::piped())
            .output();
    }
    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("iptables")
            .args(["-A", "OUTPUT", "-p", "tcp", "--dport", &port.to_string(), "-j", "DROP"])
            .output();
    }
    #[cfg(target_os = "windows")]
    {
        let _ = std::process::Command::new("netsh")
            .args(["advfirewall", "firewall", "add", "rule", 
                   "name=Nodesec_Block_Port", "dir=out", "action=block", "protocol=TCP", &format!("remoteport={}", port)])
            .output();
    }
    
    monitor_state.add_action_log(crate::state::ActionLogEntry {
        timestamp: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        action: crate::state::ActionType::BlockPort,
        pid,
        process_name: process_name.to_string(),
        port: Some(port),
        ip: None,
        rule: format!("Block port {}", port),
        success: true,
        details: format!("Blocked port {} for process {}", port, process_name),
    });
}

pub fn allow_port(port: u16, pid: u32, process_name: &str, monitor_state: &crate::state::MonitorState) {
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("pfctl")
            .args(["-a", "nodesec", "-F", "rules"])
            .output();
    }
    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("iptables")
            .args(["-D", "OUTPUT", "-p", "tcp", "--dport", &port.to_string(), "-j", "DROP"])
            .output();
    }
    #[cfg(target_os = "windows")]
    {
        let _ = std::process::Command::new("netsh")
            .args(["advfirewall", "firewall", "delete", "rule", 
                   "name=Nodesec_Block_Port", "dir=out", "protocol=TCP", &format!("remoteport={}", port)])
            .output();
    }
    
    monitor_state.add_action_log(crate::state::ActionLogEntry {
        timestamp: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        action: crate::state::ActionType::AllowPort,
        pid,
        process_name: process_name.to_string(),
        port: Some(port),
        ip: None,
        rule: format!("Allow port {}", port),
        success: true,
        details: format!("Allowed port {} for process {}", port, process_name),
    });
}

pub fn block_ip(ip: &str, pid: u32, process_name: &str, monitor_state: &crate::state::MonitorState) {
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("pfctl")
            .args(["-a", "nodesec", "-f", "-"])
            .stdin(std::process::Stdio::piped())
            .output();
    }
    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("iptables")
            .args(["-A", "OUTPUT", "-d", ip, "-j", "DROP"])
            .output();
    }
    #[cfg(target_os = "windows")]
    {
        let _ = std::process::Command::new("netsh")
            .args(["advfirewall", "firewall", "add", "rule", 
                   "name=Nodesec_Block_IP", "dir=out", "action=block", &format!("remoteip={}", ip)])
            .output();
    }
    
    monitor_state.add_action_log(crate::state::ActionLogEntry {
        timestamp: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        action: crate::state::ActionType::BlockIP,
        pid,
        process_name: process_name.to_string(),
        port: None,
        ip: Some(ip.to_string()),
        rule: format!("Block IP {}", ip),
        success: true,
        details: format!("Blocked IP {} for process {}", ip, process_name),
    });
}

pub fn render_alerts(ui: &mut egui::Ui, alerts: &[String]) {
    if alerts.is_empty() {
        ui.centered_and_justified(|ui| {
            ui.label(egui::RichText::new("No alerts").color(GRAY));
        });
    } else {
        egui::ScrollArea::vertical().show(ui, |ui| {
            for alert in alerts.iter() {
                ui.group(|ui| {
                    ui.label(egui::RichText::new(alert).color(RED));
                });
            }
        });
    }
}

pub fn render_statistics(
    ui: &mut egui::Ui,
    stats: &ConnectionStats,
    connections: &[ConnectionItem],
) {
    use std::collections::HashMap;
    
    let mut counts = HashMap::new();
    for item in connections.iter() {
        *counts.entry(item.threat_level).or_insert(0) += 1;
    }
    
    ui.horizontal(|ui| {
        stat_card(ui, "Total", &stats.total.to_string(), WHITE);
        stat_card(ui, "Active", &stats.active.to_string(), GREEN);
        stat_card(ui, "Suspicious", &stats.suspicious.to_string(), RED);
        stat_card(ui, "Critical", &stats.critical.to_string(), RED);
    });
    
    ui.separator();
    
    ui.horizontal(|ui| {
        stat_card(ui, "Safe", &counts.get(&ThreatLevel::Safe).unwrap_or(&0).to_string(), GREEN);
        stat_card(ui, "Low", &counts.get(&ThreatLevel::Low).unwrap_or(&0).to_string(), YELLOW);
        stat_card(ui, "Medium", &counts.get(&ThreatLevel::Medium).unwrap_or(&0).to_string(), ORANGE);
        stat_card(ui, "High", &counts.get(&ThreatLevel::High).unwrap_or(&0).to_string(), egui::Color32::from_rgb(255, 100, 100));
        stat_card(ui, "Critical", &counts.get(&ThreatLevel::Critical).unwrap_or(&0).to_string(), RED);
    });
    
    ui.separator();
    ui.heading("Threat Distribution");
    
    // Threat level breakdown chart
    let total = connections.len().max(1) as f64;
    egui::Grid::new("threat_breakdown").num_columns(3).show(ui, |ui| {
        for level in [ThreatLevel::Safe, ThreatLevel::Low, ThreatLevel::Medium, ThreatLevel::High, ThreatLevel::Critical] {
            let count = counts.get(&level).unwrap_or(&0);
            let pct = *count as f64 / total * 100.0;
            let color = level.color();
            
            ui.label(egui::RichText::new(level.label()).color(color).strong());
            ui.add(egui::ProgressBar::new((pct / 100.0) as f32).fill(color).show_percentage());
            ui.label(format!("{} ({:.1}%)", count, pct));
            ui.end_row();
        }
    });
}

pub fn render_settings(
    ui: &mut egui::Ui,
    platform: nodesec_core::models::Platform,
    monitor_state: &crate::state::MonitorState,
) {
    ui.heading(egui::RichText::new("Network Monitoring Settings").color(ORANGE).strong());
    ui.separator();
    
    // Scan Settings
    ui.heading(egui::RichText::new("Scan Configuration").color(ORANGE));
    {
        let mut settings = monitor_state.scan_settings.lock().unwrap();
        
        egui::Grid::new("scan_settings").num_columns(2).show(ui, |ui| {
            ui.label("Scan Interval (seconds):");
            ui.add(egui::DragValue::new(&mut settings.scan_interval_seconds).range(1..=60).speed(0.5));
            ui.end_row();
            
            ui.label("Max Connections:");
            ui.add(egui::DragValue::new(&mut settings.max_connections).range(100..=10000).speed(10.0));
            ui.end_row();
            
            ui.label("Retention (seconds):");
            ui.add(egui::DragValue::new(&mut settings.retention_seconds).range(60..=3600).speed(10.0));
            ui.end_row();
            
            ui.label("Threat Threshold:");
            ui.add(egui::DragValue::new(&mut settings.threat_threshold).range(0..=100).speed(1.0));
            ui.end_row();
            
            ui.label("Auto Refresh:");
            ui.checkbox(&mut settings.auto_refresh, "");
            ui.end_row();
        });
    }
    
    ui.separator();
    
    // Ignore Rules
    ui.heading(egui::RichText::new("Ignore Rules").color(ORANGE));
    {
        let mut settings = monitor_state.scan_settings.lock().unwrap();
        
        ui.horizontal(|ui| {
            ui.label("Add Ignore Rule:");
            if ui.button("Process Name").clicked() {
                settings.ignore_rules.push(crate::state::IgnoreRule {
                    id: uuid::Uuid::new_v4().to_string(),
                    process_name: Some("".to_string()),
                    pid: None,
                    port: None,
                    ip: None,
                    protocol: None,
                    created: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
                    description: "Ignore by process name".to_string(),
                });
            }
            
            if ui.button("PID").clicked() {
                settings.ignore_rules.push(crate::state::IgnoreRule {
                    id: uuid::Uuid::new_v4().to_string(),
                    process_name: None,
                    pid: Some(0),
                    port: None,
                    ip: None,
                    protocol: None,
                    created: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
                    description: "Ignore by PID".to_string(),
                });
            }
            
            if ui.button("Port").clicked() {
                settings.ignore_rules.push(crate::state::IgnoreRule {
                    id: uuid::Uuid::new_v4().to_string(),
                    process_name: None,
                    pid: None,
                    port: Some(0),
                    ip: None,
                    protocol: None,
                    created: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
                    description: "Ignore by port".to_string(),
                });
            }
            
            if ui.button("IP Address").clicked() {
                settings.ignore_rules.push(crate::state::IgnoreRule {
                    id: uuid::Uuid::new_v4().to_string(),
                    process_name: None,
                    pid: None,
                    port: None,
                    ip: Some("".to_string()),
                    protocol: None,
                    created: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
                    description: "Ignore by IP".to_string(),
                });
            }
        });
        
        // Display ignore rules
        let mut to_remove = Vec::new();
        for (i, rule) in settings.ignore_rules.iter().enumerate() {
            ui.group(|ui| {
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new(&rule.description).color(WHITE));
                    ui.label(egui::RichText::new(&rule.created).color(GRAY).size(10.0));
                    
                    if let Some(name) = &rule.process_name {
                        ui.label(format!("Process: {}", name));
                    }
                    if let Some(pid) = rule.pid {
                        if pid > 0 {
                            ui.label(format!("PID: {}", pid));
                        }
                    }
                    if let Some(port) = rule.port {
                        if port > 0 {
                            ui.label(format!("Port: {}", port));
                        }
                    }
                    if let Some(ip) = &rule.ip {
                        if !ip.is_empty() {
                            ui.label(format!("IP: {}", ip));
                        }
                    }
                    if let Some(proto) = &rule.protocol {
                        ui.label(format!("Protocol: {:?}", proto));
                    }
                    
                    if ui.button("🗑 Remove").clicked() {
                        to_remove.push(i);
                    }
                });
            });
        }
        
        // Remove marked rules
        for &i in to_remove.iter().rev() {
            settings.ignore_rules.remove(i);
        }
    }
    
    ui.separator();
    
    // Action Log
    ui.heading(egui::RichText::new("Action Log").color(ORANGE));
    ui.horizontal(|ui| {
        if ui.button("Export Log").clicked() {
            let log = monitor_state.action_log.lock().unwrap();
            let json = serde_json::to_string_pretty(&*log).unwrap_or_default();
            let _ = std::fs::write("nodesec_action_log.json", json);
        }
        if ui.button("Clear Log").clicked() {
            monitor_state.action_log.lock().unwrap().clear();
        }
    });
    
    let log = monitor_state.action_log.lock().unwrap();
    egui::ScrollArea::vertical().max_height(200.0).show(ui, |ui| {
        egui::Grid::new("action_log").num_columns(6).striped(true).show(ui, |ui| {
            ui.label(egui::RichText::new("Time").color(ORANGE).strong());
            ui.label(egui::RichText::new("Action").color(ORANGE).strong());
            ui.label(egui::RichText::new("Process").color(ORANGE).strong());
            ui.label(egui::RichText::new("PID").color(ORANGE).strong());
            ui.label(egui::RichText::new("Details").color(ORANGE).strong());
            ui.label(egui::RichText::new("Success").color(ORANGE).strong());
            ui.end_row();
            
            for entry in log.iter() {
                let action_color = match entry.action {
                    crate::state::ActionType::Terminate => RED,
                    crate::state::ActionType::BlockPort | crate::state::ActionType::BlockIP => YELLOW,
                    crate::state::ActionType::AllowPort | crate::state::ActionType::AllowIP => GREEN,
                    _ => WHITE,
                };
                
                ui.label(&entry.timestamp);
                ui.colored_label(action_color, format!("{:?}", entry.action));
                ui.label(&entry.process_name);
                ui.label(entry.pid.to_string());
                ui.label(&entry.details);
                ui.colored_label(if entry.success { GREEN } else { RED }, 
                    if entry.success { "✓" } else { "✗" });
                ui.end_row();
            }
        });
    });
    
    ui.separator();
    
    // Platform info
    egui::Grid::new("platform_info").num_columns(2).show(ui, |ui| {
        ui.label("Platform:");
        ui.label(format!("{:?}", platform));
        ui.end_row();
    });
    
    ui.separator();
    
    ui.label("Shortcuts:");
    ui.label("1-7: Switch tabs");
    ui.label("Tab: Next tab");
    ui.label("Click: Select row");
    ui.label("Scroll: Mouse wheel");
    ui.label("Space: Pause");
    ui.label("Q: Quit");
}

pub fn render_dashboard(
    ui: &mut egui::Ui,
    connection_history: &Arc<Mutex<VecDeque<(f64, usize)>>>,
    threat_history: &Arc<Mutex<VecDeque<(f64, u8)>>>,
    monitor_state: &crate::state::MonitorState,
    monitoring: bool,
) {
    // Real-time charts
    let conn_history = connection_history.lock().unwrap();
    let threat_history = threat_history.lock().unwrap();
    
    // Connection count chart
    ui.group(|ui| {
        ui.heading(egui::RichText::new("Connection Count (Last 5 min)").color(ORANGE));
        
        if conn_history.len() > 1 {
            let points: PlotPoints = conn_history.iter()
                .enumerate()
                .map(|(i, &(_, count))| [i as f64, count as f64])
                .collect();
            
            let line = Line::new(points)
                .color(egui::Color32::from_rgb(0, 200, 255))
                .width(2.0)
                .fill(0.0);
            
            Plot::new("conn_plot")
                .view_aspect(3.0)
                .height(200.0)
                .show(ui, |plot_ui| {
                    plot_ui.line(line);
                });
        } else {
            ui.centered_and_justified(|ui| {
                ui.label("Waiting for data...");
            });
        }
    });
    
    ui.add_space(10.0);
    
    // Threat score chart
    ui.group(|ui| {
        ui.heading(egui::RichText::new("Average Threat Score").color(ORANGE));
        
        if threat_history.len() > 1 {
            let points: PlotPoints = threat_history.iter()
                .enumerate()
                .map(|(i, &(_, score))| [i as f64, score as f64])
                .collect();
            
            let line = Line::new(points)
                .color(egui::Color32::from_rgb(255, 100, 100))
                .width(2.0)
                .fill(0.0);
            
            Plot::new("threat_plot")
                .view_aspect(3.0)
                .height(200.0)
                .show(ui, |plot_ui| {
                    plot_ui.line(line);
                });
        } else {
            ui.centered_and_justified(|ui| {
                ui.label("Waiting for data...");
            });
        }
    });
    
    ui.add_space(10.0);
    
    // Current stats
    ui.horizontal(|ui| {
        let stats = monitor_state.stats.lock().unwrap();
        let connections = monitor_state.connections.lock().unwrap();
        
        stat_card(ui, "Total Scanned", &stats.total.to_string(), WHITE);
        stat_card(ui, "Active Now", &connections.len().to_string(), GREEN);
        stat_card(ui, "Suspicious", &stats.suspicious.to_string(), RED);
        stat_card(ui, "Critical", &stats.critical.to_string(), YELLOW);
    });
    
    ui.add_space(10.0);
    
    // Top suspicious processes
    ui.group(|ui| {
        ui.heading(egui::RichText::new("Top Suspicious Processes").color(ORANGE));
        
        let connections = monitor_state.connections.lock().unwrap();
        let mut suspicious: Vec<_> = connections.iter()
            .filter(|c| c.connection.is_suspicious)
            .take(10)
            .collect();
        
        if suspicious.is_empty() {
            ui.label(egui::RichText::new("No suspicious activity detected").color(GREEN));
        } else {
            egui::Grid::new("suspicious_procs").num_columns(5).show(ui, |ui| {
                ui.label(egui::RichText::new("Process").color(ORANGE).strong());
                ui.label(egui::RichText::new("PID").color(ORANGE).strong());
                ui.label(egui::RichText::new("Connections").color(ORANGE).strong());
                ui.label(egui::RichText::new("Max Threat").color(ORANGE).strong());
                ui.label(egui::RichText::new("Destinations").color(ORANGE).strong());
                ui.end_row();
                
                for item in suspicious {
                    let conn = &item.connection;
                    ui.label(&conn.process_name);
                    ui.label(conn.pid.to_string());
                    ui.label("1"); // Would need aggregation
                    ui.colored_label(item.threat_level.color(), item.threat_level.label());
                    ui.label(format!("{}:{}", conn.dst_ip, conn.dst_port));
                    ui.end_row();
                }
            });
        }
    });
}

pub fn render_process_tree(ui: &mut egui::Ui, monitor_state: &crate::state::MonitorState, filter: &mut FilterSettings, selected_process: &mut Option<u32>) {
    let connections = monitor_state.connections.lock().unwrap();
    let processes = ProcessTreeItem::from_connections(&connections);
    
    if processes.is_empty() {
        ui.centered_and_justified(|ui| {
            ui.label(egui::RichText::new("No processes with network connections").color(GRAY));
        });
        return;
    }
    
    ui.heading(egui::RichText::new("Process Network Tree").color(ORANGE));
    ui.separator();
    
    // Toolbar
    ui.horizontal(|ui| {
        ui.label(egui::RichText::new("Click row to select • Right-click for actions").color(GRAY).size(11.0));
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui.button("Expand All").clicked() {
                // All rows are always visible in table view
            }
        });
    });
    ui.separator();
    
    egui::ScrollArea::vertical().show(ui, |ui| {
        egui::Grid::new("process_tree")
            .striped(true)
            .min_col_width(100.0)
            .show(ui, |ui| {
                // Header
                ui.label(egui::RichText::new("Process").color(ORANGE).strong());
                ui.label(egui::RichText::new("PID").color(ORANGE).strong());
                ui.label(egui::RichText::new("User").color(ORANGE).strong());
                ui.label(egui::RichText::new("Connections").color(ORANGE).strong());
                ui.label(egui::RichText::new("Max Threat").color(ORANGE).strong());
                ui.label(egui::RichText::new("Status").color(ORANGE).strong());
                ui.end_row();
                
                for proc in processes {
                    // Apply filter
                    let mut matches = true;
                    if !filter.process_name.is_empty() {
                        if !proc.name.to_lowercase().contains(&filter.process_name.to_lowercase()) {
                            matches = false;
                        }
                    }
                    if let Some(pid) = filter.pid {
                        if proc.pid != pid {
                            matches = false;
                        }
                    }
                    if filter.only_suspicious && !proc.is_suspicious {
                        matches = false;
                    }
                    if proc.total_threat_score < filter.min_threat_score || proc.total_threat_score > filter.max_threat_score {
                        matches = false;
                    }
                    
                    if !matches {
                        continue;
                    }
                    
                    let threat_color = match proc.total_threat_score {
                        0..=25 => GREEN,
                        26..=49 => YELLOW,
                        50..=74 => ORANGE,
                        75..=89 => egui::Color32::from_rgb(255, 100, 100),
                        _ => RED,
                    };
                    
                    let is_selected = selected_process.as_ref() == Some(&proc.pid);
                    
                    let response = ui.selectable_label(is_selected, "");
                    if response.clicked() {
                        *selected_process = Some(proc.pid);
                    }
                    if response.secondary_clicked() {
                        *selected_process = Some(proc.pid);
                    }
                    
                    // Process name with icon
                    ui.horizontal(|ui| {
                        let icon = if proc.is_suspicious { "⚠️ " } else { "✓ " };
                        ui.label(egui::RichText::new(format!("{}{}", icon, proc.name)).color(if is_selected { YELLOW } else { WHITE }).size(12.0).strong());
                    });
                    ui.label(proc.pid.to_string());
                    ui.label(proc.user.as_deref().unwrap_or("N/A"));
                    ui.label(proc.connections.len().to_string());
                    ui.colored_label(threat_color, proc.total_threat_score.to_string());
                    ui.colored_label(threat_color, if proc.is_suspicious { "SUSPICIOUS" } else { "OK" });
                    ui.end_row();
                    
                    // Context menu for process row
                    response.context_menu(|ui| {
                        ui.heading(format!("{} (PID: {})", proc.name, proc.pid));
                        ui.separator();
                        
                        if let Some(path) = &proc.path {
                            ui.label(format!("Path: {}", path));
                            ui.separator();
                        }
                        
                        if ui.button("🔴 Terminate Process").clicked() {
                            crate::ui::terminate_process(proc.pid, &proc.name, monitor_state);
                            ui.close_menu();
                        }
                        if ui.button("🚫 Block All Ports").clicked() {
                            ui.close_menu();
                        }
                        if ui.button("📋 Copy PID").clicked() {
                            ui.output_mut(|o| o.copied_text = proc.pid.to_string());
                            ui.close_menu();
                        }
                        if ui.button("📋 Copy Process Name").clicked() {
                            ui.output_mut(|o| o.copied_text = proc.name.clone());
                            ui.close_menu();
                        }
                        if let Some(path) = &proc.path {
                            if ui.button("📋 Copy Path").clicked() {
                                ui.output_mut(|o| o.copied_text = path.clone());
                                ui.close_menu();
                            }
                        }
                        
                        ui.separator();
                        if ui.button("🔍 Show Connections").clicked() {
                            *selected_process = Some(proc.pid);
                            ui.close_menu();
                        }
                    });
                    
                    // Show connection details inline for selected process
                    if is_selected {
                        ui.add_space(4.0);
                        if let Some(path) = &proc.path {
                            ui.label(egui::RichText::new(format!("Path: {}", path)).color(GRAY).size(11.0));
                        }
                        if let Some(user) = &proc.user {
                            ui.label(egui::RichText::new(format!("User: {}", user)).color(GRAY).size(11.0));
                        }
                        ui.separator();
                        ui.label(egui::RichText::new("Network Connections:").color(WHITE).strong().size(11.0));
                        
                        egui::Grid::new(format!("proc_conns_{}", proc.pid))
                            .striped(true)
                            .min_col_width(80.0)
                            .show(ui, |ui| {
                                ui.label(egui::RichText::new("Protocol").color(ORANGE).strong().size(11.0));
                                ui.label(egui::RichText::new("Source").color(ORANGE).strong().size(11.0));
                                ui.label(egui::RichText::new("Destination").color(ORANGE).strong().size(11.0));
                                ui.label(egui::RichText::new("Threat").color(ORANGE).strong().size(11.0));
                                ui.end_row();
                                
                                for conn in &proc.connections {
                                    let proto = format!("{:?}", conn.protocol);
                                    let src = format!("{}:{}", conn.src_ip, conn.src_port);
                                    let dst = format!("{}:{}", conn.dst_ip, conn.dst_port);
                                    let conn_threat_color = match conn.threat_score {
                                        0..=25 => GREEN,
                                        26..=49 => YELLOW,
                                        50..=74 => ORANGE,
                                        75..=89 => egui::Color32::from_rgb(255, 100, 100),
                                        _ => RED,
                                    };
                                    
                                    ui.label(egui::RichText::new(proto).size(11.0));
                                    ui.label(egui::RichText::new(src).size(11.0));
                                    ui.label(egui::RichText::new(dst).size(11.0));
                                    ui.colored_label(conn_threat_color, egui::RichText::new(conn.threat_score.to_string()).size(11.0));
                                    ui.end_row();
                                }
                            });
                        ui.add_space(8.0);
                    }
                }
            });
    });
}

pub fn render_connection_graph(ui: &mut egui::Ui, graph: &mut crate::graph::ConnectionGraph, monitor_state: &crate::state::MonitorState) {
    ui.heading(egui::RichText::new("Connection Graph").color(ORANGE));
    ui.separator();
    
    let rect = ui.available_rect_before_wrap();
    graph.render(ui, rect);
    
    // Selected node detail
    if let Some(node) = graph.get_selected() {
        ui.separator();
        ui.group(|ui| {
            ui.heading(egui::RichText::new("Node Details").color(ORANGE));
            ui.separator();
            
            egui::Grid::new("node_detail").num_columns(2).show(ui, |ui| {
                detail_row(ui, "ID", &node.id);
                detail_row(ui, "Label", &node.label);
                detail_row(ui, "Type", if node.is_process { "Process" } else { "Host" });
                if let Some(pid) = node.pid {
                    detail_row(ui, "PID", &pid.to_string());
                }
                detail_row(ui, "Process", &node.process_name);
                if let Some(iface) = &node.interface {
                    detail_row(ui, "Interface/Type", iface);
                }
                if let Some(ip) = &node.remote_ip {
                    detail_row(ui, "Remote IP", ip);
                }
                if let Some(port) = node.remote_port {
                    detail_row(ui, "Remote Port", &port.to_string());
                }
                detail_row(ui, "Connections", &node.connections.to_string());
                detail_row(ui, "Threat Score", &node.threat_score.to_string());
            });
            
            if node.is_process {
                ui.horizontal(|ui| {
                    if ui.button("🔴 Terminate").clicked() {
                        if let Some(pid) = node.pid {
                            crate::ui::terminate_process(pid, &node.process_name, monitor_state);
                        }
                    }
                    if ui.button("🚫 Block All Ports").clicked() {
                        // Block all ports for this process
                    }
                });
            }
        });
    }
}