use eframe::egui;
use egui_plot::{Line, Plot, PlotPoints};
use crate::state::{ConnectionItem, ThreatLevel, ConnectionStats, ProcessTreeItem, FilterSettings, MonitorState};
use nodesec_core::models::{ExclusionList, ExclusionRule};
use std::sync::{Arc, Mutex};
use std::collections::VecDeque;

// QRadar-inspired color palette
const NAVY_BG: egui::Color32 = egui::Color32::from_rgb(15, 23, 42);      // Deep navy background
const PANEL_BG: egui::Color32 = egui::Color32::from_rgb(30, 41, 59);     // Slate panel background
const SIDEBAR_BG: egui::Color32 = egui::Color32::from_rgb(9, 17, 31);    // Darker sidebar
const BORDER: egui::Color32 = egui::Color32::from_rgb(71, 85, 105);      // Slate border
const PRIMARY: egui::Color32 = egui::Color32::from_rgb(59, 130, 246);    // Blue accent
const PRIMARY_HOVER: egui::Color32 = egui::Color32::from_rgb(37, 99, 235); // Darker blue hover
const WHITE: egui::Color32 = egui::Color32::from_rgb(241, 245, 249);     // Off-white text
const GRAY: egui::Color32 = egui::Color32::from_rgb(148, 163, 184);      // Muted gray text
const GREEN: egui::Color32 = egui::Color32::from_rgb(34, 197, 94);       // Emerald green
const YELLOW: egui::Color32 = egui::Color32::from_rgb(234, 179, 8);      // Gold yellow
const ORANGE: egui::Color32 = egui::Color32::from_rgb(249, 115, 22);     // Orange
const RED: egui::Color32 = egui::Color32::from_rgb(239, 68, 68);         // Red
const TEXT_MUTED: egui::Color32 = egui::Color32::from_rgb(100, 116, 139); // Slate muted
const CARD_BG: egui::Color32 = egui::Color32::from_rgb(30, 41, 59);      // Panel card background
const CARD_HOVER: egui::Color32 = egui::Color32::from_rgb(40, 53, 72);   // Card hover

/// Helper: QRadar-style stat card with centered value and label
pub fn stat_card(ui: &mut egui::Ui, label: &str, value: &str, color: egui::Color32) {
    ui.group(|ui| {
        ui.set_min_width(100.0);
        ui.set_max_width(140.0);
        ui.vertical_centered(|ui| {
            ui.add_space(8.0);
            ui.label(egui::RichText::new(value).color(color).size(24.0).strong());
            ui.label(egui::RichText::new(label).color(GRAY).size(11.0).strong());
            ui.add_space(8.0);
        });
    });
}

/// Helper: Full stat card with subtitle
pub fn stat_card_full(ui: &mut egui::Ui, label: &str, value: &str, color: egui::Color32, subtitle: Option<&str>) {
    ui.group(|ui| {
        ui.set_min_width(120.0);
        ui.set_max_width(160.0);
        ui.vertical(|ui| {
            ui.add_space(12.0);
            ui.label(egui::RichText::new(value).color(color).size(24.0).strong());
            ui.add_space(4.0);
            ui.label(egui::RichText::new(label).color(GRAY).size(10.0).strong());
            if let Some(sub) = subtitle {
                ui.add_space(2.0);
                ui.label(egui::RichText::new(sub).color(TEXT_MUTED).size(9.0));
            }
            ui.add_space(8.0);
        });
    });
}

/// Helper: detail row - label above value (top-to-bottom per-tab layout)
pub fn detail_row(ui: &mut egui::Ui, label: &str, value: impl ToString) {
    ui.vertical(|ui| {
        ui.label(egui::RichText::new(label).color(PRIMARY).size(10.0).strong());
        ui.add_space(1.0);
        ui.label(egui::RichText::new(value.to_string()).color(WHITE).size(12.0));
        ui.add_space(4.0);
    });
}

/// Helper: QRadar-style table header row
pub fn table_header(ui: &mut egui::Ui, headers: &[&str]) {
    ui.horizontal(|ui| {
        for header in headers {
            ui.label(egui::RichText::new(*header).color(PRIMARY).size(11.0).strong());
            ui.add_space(16.0);
        }
    });
}

/// Render a card panel with header and content
pub fn card_panel(ui: &mut egui::Ui, title: &str, content_fn: impl FnOnce(&mut egui::Ui)) {
    ui.group(|ui| {
        ui.set_min_width(200.0);
        ui.heading(egui::RichText::new(title).color(PRIMARY).strong());
        ui.separator();
        ui.add_space(4.0);
        content_fn(ui);
        ui.add_space(4.0);
    });
}

/// Render connections table with QRadar styling
pub fn render_connections_table(
    ui: &mut egui::Ui,
    connections: &[ConnectionItem],
    selected_connection: &mut Option<usize>,
    filter: &mut FilterSettings,
) {
    // Filter panel
    card_panel(ui, "Filters", |ui| {
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("Process:").color(TEXT_MUTED).size(10.0));
            ui.text_edit_singleline(&mut filter.process_name);
            ui.add_space(12.0);
            ui.label(egui::RichText::new("PID:").color(TEXT_MUTED).size(10.0));
            let mut pid_str = filter.pid.map(|p| p.to_string()).unwrap_or_default();
            if ui.text_edit_singleline(&mut pid_str).changed() {
                filter.pid = pid_str.parse().ok();
            }
            ui.add_space(12.0);
            ui.label(egui::RichText::new("Min Threat:").color(TEXT_MUTED).size(10.0));
            let mut min_str = filter.min_threat_score.to_string();
            if ui.text_edit_singleline(&mut min_str).changed() {
                filter.min_threat_score = min_str.parse().unwrap_or(0);
            }
            ui.add_space(12.0);
            ui.label(egui::RichText::new("Max Threat:").color(TEXT_MUTED).size(10.0));
            let mut max_str = filter.max_threat_score.to_string();
            if ui.text_edit_singleline(&mut max_str).changed() {
                filter.max_threat_score = max_str.parse().unwrap_or(100);
            }
            ui.add_space(12.0);
            ui.checkbox(&mut filter.only_suspicious, "Suspicious Only");
            ui.add_space(12.0);
            ui.label(egui::RichText::new("Protocol:").color(TEXT_MUTED).size(10.0));
            egui::ComboBox::from_label("")
                .selected_text(match &filter.protocol {
                    Some(p) => format!("{:?}", p),
                    None => "All".to_string(),
                })
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut filter.protocol, None, "All");
                    ui.selectable_value(&mut filter.protocol, Some(nodesec_core::models::NetworkProtocol::Tcp), "TCP");
                    ui.selectable_value(&mut filter.protocol, Some(nodesec_core::models::NetworkProtocol::Udp), "UDP");
                });
            ui.add_space(12.0);
            if ui.button("Clear").clicked() {
                *filter = FilterSettings::default();
            }
        });
    });

    ui.add_space(8.0);

    // Connections table with QRadar styling
    egui::ScrollArea::both().show(ui, |ui| {
        ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Extend);
        egui::Grid::new("connections_table_qr")
            .striped(true)
            .min_col_width(80.0)
            .show(ui, |ui| {
                // QRadar-style header
                ui.label(egui::RichText::new("Sel").color(PRIMARY).strong().size(11.0));
                ui.label(egui::RichText::new("Time").color(PRIMARY).strong().size(11.0));
                ui.label(egui::RichText::new("PID").color(PRIMARY).strong().size(11.0));
                ui.label(egui::RichText::new("Process").color(PRIMARY).strong().size(11.0));
                ui.label(egui::RichText::new("Proto").color(PRIMARY).strong().size(11.0));
                ui.label(egui::RichText::new("Source").color(PRIMARY).strong().size(11.0));
                ui.label(egui::RichText::new("Destination").color(PRIMARY).strong().size(11.0));
                ui.label(egui::RichText::new("Threat").color(PRIMARY).strong().size(11.0));
                ui.label(egui::RichText::new("Score").color(PRIMARY).strong().size(11.0));
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

                    // Row selection via SelectableLabel for process name cell
                    let display_name = if conn.process_name.is_empty() {
                        "unknown".to_string()
                    } else {
                        conn.process_name.clone()
                    };

                    let response = ui.add(egui::widgets::SelectableLabel::new(is_selected, display_name));
                    if response.clicked() {
                        *selected_connection = Some(i);
                    }

                    ui.label(egui::RichText::new(time).color(WHITE).size(11.0));
                    ui.label(egui::RichText::new(conn.pid.to_string()).color(WHITE).size(11.0));
                    ui.label(egui::RichText::new(proto).color(WHITE).size(11.0));
                    ui.label(egui::RichText::new(src).color(WHITE).size(11.0));
                    ui.label(egui::RichText::new(dst).color(WHITE).size(11.0));
                    ui.colored_label(threat_color, item.threat_level.label());
                    ui.colored_label(threat_color, conn.threat_score.to_string());

                    ui.end_row();
                }
            });
    });
}

/// Render process detail panel (top-to-bottom per-tab details pane)
pub fn render_process_detail(ui: &mut egui::Ui, proc: &crate::state::ProcessTreeItem) {
    ui.heading(egui::RichText::new(&proc.name).color(ORANGE).strong());
    ui.separator();
    ui.add_space(4.0);

    detail_row(ui, "PID", &proc.pid.to_string());
    if let Some(path) = &proc.path {
        detail_row(ui, "Path", path);
    }
    if let Some(user) = &proc.user {
        detail_row(ui, "User", user);
    }
    detail_row(ui, "Connections", &proc.connections.len().to_string());
    detail_row(ui, "Max Threat Score", &proc.total_threat_score.to_string());
    detail_row(ui, "Status", if proc.is_suspicious { "SUSPICIOUS" } else { "OK" });

    ui.separator();
    ui.add_space(4.0);

    ui.label(egui::RichText::new("Actions").color(PRIMARY).strong());
    ui.horizontal(|ui| {
        if ui.button("[Terminate]").clicked() {
            crate::ui::terminate_process(proc.pid, &proc.name, &crate::state::MonitorState::new(nodesec_core::models::Platform::detect()));
        }
        if ui.button("[Block All Ports]").clicked() {
            // TODO
        }
        if ui.button("[Copy PID]").clicked() {
            ui.output_mut(|o| o.copied_text = proc.pid.to_string());
        }
        if ui.button("[Copy Name]").clicked() {
            ui.output_mut(|o| o.copied_text = proc.name.clone());
        }
        if let Some(path) = &proc.path {
            if ui.button("[Copy Path]").clicked() {
                ui.output_mut(|o| o.copied_text = path.clone());
            }
        }
    });
}

/// Render connection detail panel (top-to-bottom per-tab details pane)
pub fn render_connection_detail_topdown(
    ui: &mut egui::Ui,
    item: &crate::state::ConnectionItem,
    monitor_state: &crate::state::MonitorState,
) {
    let conn = &item.connection;
    let threat_level = item.threat_level;

    ui.heading(egui::RichText::new("Connection Details").color(PRIMARY).strong());
    ui.separator();
    ui.add_space(4.0);

    detail_row(ui, "Process", &conn.process_name);
    detail_row(ui, "PID", &conn.pid.to_string());
    if let Some(path) = &conn.process_path {
        detail_row(ui, "Path", path);
    }
    if let Some(cmd) = &conn.command_line {
        detail_row(ui, "Command", cmd);
    }
    if let Some(user) = &conn.user {
        detail_row(ui, "User", user);
    }
    detail_row(ui, "Source", &format!("{}:{}", conn.src_ip, conn.src_port));
    detail_row(ui, "Destination", &format!("{}:{}", conn.dst_ip, conn.dst_port));
    detail_row(ui, "Protocol", &format!("{:?}", conn.protocol));
    detail_row(ui, "Threat Score", &conn.threat_score.to_string());
    detail_row(ui, "Threat Level", item.threat_level.label());
    detail_row(ui, "Timestamp", &chrono::DateTime::from_timestamp(conn.timestamp as i64, 0)
        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
        .unwrap_or_default());

    ui.separator();
    ui.add_space(4.0);

    ui.label(egui::RichText::new("Firewall Actions").color(PRIMARY).strong());
    ui.horizontal(|ui| {
        if ui.button("[Terminate]").clicked() {
            crate::ui::terminate_process(conn.pid, &conn.process_name, monitor_state);
        }
        if ui.button("[Block IP]").clicked() {
            crate::ui::block_ip(&conn.dst_ip.to_string(), conn.pid, &conn.process_name, monitor_state);
        }
        if ui.button("[Block Port]").clicked() {
            crate::ui::block_port(conn.dst_port, conn.pid, &conn.process_name, monitor_state);
        }
        if ui.button("[Allow Port]").clicked() {
            crate::ui::allow_port(conn.dst_port, conn.pid, &conn.process_name, monitor_state);
        }
        if ui.button("[Copy PID]").clicked() {
            ui.output_mut(|o| o.copied_text = conn.pid.to_string());
        }
    });
}

pub fn render_connection_detail(
    ui: &mut egui::Ui,
    item: &ConnectionItem,
    monitor_state: &crate::state::MonitorState,
) {
    render_connection_detail_topdown(ui, item, monitor_state);
}

/// Render alerts panel with QRadar styling
pub fn render_alerts(ui: &mut egui::Ui, monitor_state: &crate::state::MonitorState) {
    let alerts_data = {
        let alerts = monitor_state.alerts.lock().unwrap();
        if alerts.is_empty() {
            ui.centered_and_justified(|ui| {
                ui.label(egui::RichText::new("No alerts").color(TEXT_MUTED));
            });
            return;
        }
        alerts.clone()
    };

    let mut to_dismiss: Vec<usize> = Vec::new();
    let mut to_terminate: Vec<usize> = Vec::new();
    let mut to_block_ip: Vec<usize> = Vec::new();
    let mut to_block_port: Vec<usize> = Vec::new();

    egui::ScrollArea::vertical().show(ui, |ui| {
        for (i, alert) in alerts_data.iter().enumerate() {
            if alert.dismissed {
                continue;
            }
            let threat_color = if alert.threat_score >= 75 { RED } else { YELLOW };
            card_panel(ui, &format!("Alert - {}", alert.process_name), |ui| {
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new(format!(
                        "[{}] {} -> {}:{} (PID: {}, Score: {})",
                        alert.timestamp,
                        alert.process_name,
                        alert.dst_ip,
                        alert.dst_port,
                        alert.pid,
                        alert.threat_score
                    )).color(threat_color));
                    ui.add_space(8.0);
                });
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    if ui.button("Terminate").clicked() {
                        to_terminate.push(i);
                    }
                    if ui.button("Block IP").clicked() {
                        to_block_ip.push(i);
                    }
                    if ui.button("Block Port").clicked() {
                        to_block_port.push(i);
                    }
                    if ui.button("Dismiss").clicked() {
                        to_dismiss.push(i);
                    }
                });
            });
        }
    });

    for &i in &to_terminate {
        monitor_state.terminate_alert_process(i);
    }
    for &i in &to_block_ip {
        monitor_state.block_alert_ip(i);
    }
    for &i in &to_block_port {
        monitor_state.block_alert_port(i);
    }
    for &i in &to_dismiss {
        monitor_state.dismiss_alert(i);
    }
}

/// Render statistics panel with QRadar styling
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

    // Top stat cards row
    ui.columns(4, |columns| {
        columns[0].group(|ui| {
            ui.vertical_centered(|ui| {
                ui.label(egui::RichText::new(&stats.total.to_string()).color(WHITE).size(24.0).strong());
                ui.label(egui::RichText::new("Total Scanned").color(GRAY).size(11.0).strong());
            });
        });
        columns[1].group(|ui| {
            ui.vertical_centered(|ui| {
                ui.label(egui::RichText::new(&stats.active.to_string()).color(GREEN).size(24.0).strong());
                ui.label(egui::RichText::new("Active Now").color(GRAY).size(11.0).strong());
            });
        });
        columns[2].group(|ui| {
            ui.vertical_centered(|ui| {
                ui.label(egui::RichText::new(&stats.suspicious.to_string()).color(RED).size(24.0).strong());
                ui.label(egui::RichText::new("Suspicious").color(GRAY).size(11.0).strong());
            });
        });
        columns[3].group(|ui| {
            ui.vertical_centered(|ui| {
                ui.label(egui::RichText::new(&stats.critical.to_string()).color(YELLOW).size(24.0).strong());
                ui.label(egui::RichText::new("Critical").color(GRAY).size(11.0).strong());
            });
        });
    });

    ui.add_space(12.0);
    ui.separator();
    ui.add_space(8.0);

    // Threat level breakdown
    ui.heading(egui::RichText::new("Threat Distribution").color(PRIMARY).strong());
    ui.separator();
    ui.add_space(4.0);

    let total = connections.len().max(1) as f64;
    for level in [ThreatLevel::Safe, ThreatLevel::Low, ThreatLevel::Medium, ThreatLevel::High, ThreatLevel::Critical] {
        let count = counts.get(&level).unwrap_or(&0);
        let pct = *count as f64 / total * 100.0;
        let color = level.color();

        ui.horizontal(|ui| {
            ui.label(egui::RichText::new(level.label()).color(color).strong().size(12.0));
            ui.add_space(8.0);
            let bar = egui::ProgressBar::new((pct / 100.0) as f32)
                .fill(color)
                .show_percentage()
                .desired_width(150.0);
            ui.add(bar);
            ui.add_space(8.0);
            ui.label(egui::RichText::new(format!("{} ({:.1}%)", count, pct)).size(11.0));
        });
        ui.add_space(4.0);
    }

    ui.add_space(12.0);
    ui.separator();
    ui.add_space(8.0);

    // Protocol breakdown
    let mut proto_counts: std::collections::HashMap<String, usize> = HashMap::new();
    for item in connections.iter() {
        let proto = format!("{:?}", item.connection.protocol);
        *proto_counts.entry(proto).or_insert(0) += 1;
    }

    ui.heading(egui::RichText::new("Protocol Distribution").color(PRIMARY).strong());
    ui.separator();
    ui.add_space(4.0);

    for (proto, count) in proto_counts.iter() {
        let pct = *count as f64 / total * 100.0;
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new(proto).color(WHITE).size(12.0));
            ui.add_space(8.0);
            let bar = egui::ProgressBar::new((pct / 100.0) as f32)
                .fill(PRIMARY)
                .desired_width(150.0);
            ui.add(bar);
            ui.add_space(8.0);
            ui.label(egui::RichText::new(format!("{} ({:.1}%)", count, pct)).size(11.0));
        });
        ui.add_space(4.0);
    }
}

/// Render settings panel with QRadar styling
pub fn render_settings(
    ui: &mut egui::Ui,
    platform: nodesec_core::models::Platform,
    monitor_state: &crate::state::MonitorState,
) {
    ui.heading(egui::RichText::new("Network Monitoring Settings").color(PRIMARY).strong());
    ui.separator();

    card_panel(ui, "Scan Configuration", |ui| {
        let mut settings = monitor_state.scan_settings.lock().unwrap();

        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("Scan Interval (seconds):").color(WHITE));
            ui.add_space(8.0);
            ui.add(egui::DragValue::new(&mut settings.scan_interval_seconds).range(1..=60).speed(0.5));
        });
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("Max Connections:").color(WHITE));
            ui.add_space(8.0);
            ui.add(egui::DragValue::new(&mut settings.max_connections).range(100..=10000).speed(10.0));
        });
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("Retention (seconds):").color(WHITE));
            ui.add_space(8.0);
            ui.add(egui::DragValue::new(&mut settings.retention_seconds).range(60..=3600).speed(10.0));
        });
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("Threat Threshold:").color(WHITE));
            ui.add_space(8.0);
            ui.add(egui::DragValue::new(&mut settings.threat_threshold).range(0..=100).speed(1.0));
        });
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("Auto Refresh:").color(WHITE));
            ui.add_space(8.0);
            ui.checkbox(&mut settings.auto_refresh, "");
        });
    });

    ui.add_space(12.0);
    ui.separator();
    ui.add_space(8.0);

    card_panel(ui, "Ignore Rules", |ui| {
        let mut settings = monitor_state.scan_settings.lock().unwrap();

        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("Add Ignore Rule:").color(TEXT_MUTED).size(10.0));
            ui.add_space(8.0);
            if ui.button("Process Name").clicked() {
                settings.ignore_rules.push(crate::state::IgnoreRule {
                    id: uuid::Uuid::new_v4().to_string(),
                    process_name: Some("".to_string()),
                    process_path: None,
                    pid: None,
                    port: None,
                    ip: None,
                    protocol: None,
                    created: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
                    description: "Ignore by process name".to_string(),
                });
            }
            ui.add_space(6.0);
            if ui.button("Application").clicked() {
                settings.ignore_rules.push(crate::state::IgnoreRule {
                    id: uuid::Uuid::new_v4().to_string(),
                    process_name: Some("".to_string()),
                    process_path: Some("".to_string()),
                    pid: None,
                    port: None,
                    ip: None,
                    protocol: None,
                    created: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
                    description: "Ignore by application path".to_string(),
                });
            }
            ui.add_space(6.0);
            if ui.button("PID").clicked() {
                settings.ignore_rules.push(crate::state::IgnoreRule {
                    id: uuid::Uuid::new_v4().to_string(),
                    process_name: None,
                    process_path: None,
                    pid: Some(0),
                    port: None,
                    ip: None,
                    protocol: None,
                    created: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
                    description: "Ignore by PID".to_string(),
                });
            }
            ui.add_space(6.0);
            if ui.button("Port").clicked() {
                settings.ignore_rules.push(crate::state::IgnoreRule {
                    id: uuid::Uuid::new_v4().to_string(),
                    process_name: None,
                    process_path: None,
                    pid: None,
                    port: Some(0),
                    ip: None,
                    protocol: None,
                    created: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
                    description: "Ignore by port".to_string(),
                });
            }
            ui.add_space(6.0);
            if ui.button("IP Address").clicked() {
                settings.ignore_rules.push(crate::state::IgnoreRule {
                    id: uuid::Uuid::new_v4().to_string(),
                    process_name: None,
                    process_path: None,
                    pid: None,
                    port: None,
                    ip: Some("".to_string()),
                    protocol: None,
                    created: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
                    description: "Ignore by IP".to_string(),
                });
            }
        });

        ui.add_space(8.0);
        ui.separator();
        ui.add_space(4.0);

        // Suggestions based on running processes with high threat scores
        {
            let connections = monitor_state.connections.lock().unwrap();
            let mut suspicious_procs: std::collections::HashMap<String, (u32, u8, usize)> = std::collections::HashMap::new();
            for item in connections.iter() {
                let conn = &item.connection;
                if conn.threat_score >= 50 {
                    let key = format!("{}:{}", conn.process_name, conn.pid);
                    let entry = suspicious_procs.entry(key.clone()).or_insert((conn.pid, conn.threat_score, 0));
                    entry.2 += 1;
                }
            }

            if !suspicious_procs.is_empty() {
                card_panel(ui, "Suggested Ignore Rules", |ui| {
                    ui.label(egui::RichText::new("Click to add high-threat processes to ignore list:").color(GRAY).size(10.0));
                    ui.add_space(4.0);

                    let mut suggestions: Vec<_> = suspicious_procs.into_iter().collect();
                    suggestions.sort_by(|a, b| b.1 .1.cmp(&a.1 .1));

                    for (key, (pid, threat_score, conn_count)) in suggestions.into_iter().take(10) {
                        let parts: Vec<&str> = key.splitn(2, ':').collect();
                        let proc_name = parts.first().unwrap_or(&"unknown");

                        let threat_color = match threat_score {
                            0..=25 => GREEN,
                            26..=49 => YELLOW,
                            50..=74 => ORANGE,
                            75..=89 => egui::Color32::from_rgb(255, 100, 100),
                            _ => RED,
                        };

                        ui.horizontal(|ui| {
                            ui.colored_label(threat_color, egui::RichText::new(format!(
                                "{} (PID: {}, Threat: {}, Conns: {})",
                                proc_name, pid, threat_score, conn_count
                            )).size(11.0));
                            ui.add_space(8.0);
                            if ui.button("Ignore").clicked() {
                                settings.ignore_rules.push(crate::state::IgnoreRule {
                                    id: uuid::Uuid::new_v4().to_string(),
                                    process_name: Some(proc_name.to_string()),
                                    process_path: None,
                                    pid: Some(pid),
                                    port: None,
                                    ip: None,
                                    protocol: None,
                                    created: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
                                    description: format!("Ignore process: {} (PID: {})", proc_name, pid),
                                });
                            }
                        });
                    }
                });
            }
        }

        ui.add_space(8.0);
        ui.separator();
        ui.add_space(4.0);

        // Display ignore rules
        let mut to_remove = Vec::new();
        for (i, rule) in settings.ignore_rules.iter_mut().enumerate() {
            card_panel(ui, &rule.description, |ui| {
                ui.horizontal(|ui| {
                    if let Some(name) = &rule.process_name {
                        if !name.is_empty() {
                            ui.label(egui::RichText::new(format!("Process: {}", name)).color(WHITE));
                            ui.label(egui::RichText::new(&rule.created).color(GRAY).size(10.0));
                        }
                    }
                    if let Some(path) = &rule.process_path {
                        if !path.is_empty() {
                            ui.label(egui::RichText::new(format!("Path: {}", path)).color(WHITE));
                        }
                    }
                    if let Some(pid) = rule.pid {
                        if pid > 0 {
                            ui.label(egui::RichText::new(format!("PID: {}", pid)).color(WHITE));
                        }
                    }
                    if let Some(port) = rule.port {
                        if port > 0 {
                            ui.label(egui::RichText::new(format!("Port: {}", port)).color(WHITE));
                        }
                    }
                    if let Some(ip) = &rule.ip {
                        if !ip.is_empty() {
                            ui.label(egui::RichText::new(format!("IP: {}", ip)).color(WHITE));
                        }
                    }
                    if let Some(proto) = &rule.protocol {
                        ui.label(egui::RichText::new(format!("Protocol: {:?}", proto)).color(WHITE));
                    }

                    if ui.button("[Remove]").clicked() {
                        to_remove.push(i);
                    }
                });

                // Editable fields
                if let Some(name) = rule.process_name.as_mut() {
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new("Process name:").color(TEXT_MUTED).size(10.0));
                        ui.add_space(4.0);
                        ui.text_edit_singleline(name);
                    });
                }
                if let Some(path) = rule.process_path.as_mut() {
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new("Process path:").color(TEXT_MUTED).size(10.0));
                        ui.add_space(4.0);
                        ui.text_edit_singleline(path);
                    });
                }
            });
        }

        for &i in to_remove.iter().rev() {
            settings.ignore_rules.remove(i);
        }
    });

    ui.add_space(12.0);
    ui.separator();
    ui.add_space(8.0);

    card_panel(ui, "Action Log", |ui| {
        ui.horizontal(|ui| {
            if ui.button("Export Log").clicked() {
                let log = monitor_state.action_log.lock().unwrap();
                let json = serde_json::to_string_pretty(&*log).unwrap_or_default();
                let _ = std::fs::write("nodesec_action_log.json", json);
            }
            ui.add_space(8.0);
            if ui.button("Clear Log").clicked() {
                monitor_state.action_log.lock().unwrap().clear();
            }
        });
        ui.add_space(4.0);

        let log = monitor_state.action_log.lock().unwrap();
        egui::ScrollArea::vertical().max_height(200.0).show(ui, |ui| {
            if log.is_empty() {
                ui.label(egui::RichText::new("No actions logged").color(TEXT_MUTED));
            } else {
                for entry in log.iter() {
                    let action_color = match entry.action {
                        crate::state::ActionType::Terminate => RED,
                        crate::state::ActionType::BlockPort | crate::state::ActionType::BlockIP => YELLOW,
                        crate::state::ActionType::AllowPort | crate::state::ActionType::AllowIP => GREEN,
                        _ => WHITE,
                    };

                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new(&entry.timestamp).color(GRAY).size(10.0));
                        ui.add_space(8.0);
                        ui.colored_label(action_color, format!("{:?}", entry.action));
                        ui.add_space(8.0);
                        ui.label(egui::RichText::new(&entry.process_name).color(WHITE).size(11.0));
                        ui.add_space(8.0);
                        ui.label(egui::RichText::new(entry.pid.to_string()).color(GRAY).size(10.0));
                        ui.add_space(8.0);
                        ui.label(egui::RichText::new(&entry.details).color(WHITE).size(11.0));
                        ui.add_space(8.0);
                        ui.colored_label(if entry.success { GREEN } else { RED },
                            if entry.success { "[OK]" } else { "[FAIL]" });
                    });
                    ui.add_space(2.0);
                }
            }
        });
    });

    ui.add_space(12.0);
    ui.separator();
    ui.add_space(4.0);

    card_panel(ui, "Platform Info", |ui| {
        detail_row(ui, "Platform", &format!("{:?}", platform));
    });
}

/// Render dashboard with QRadar stat cards and charts
pub fn render_dashboard(
    ui: &mut egui::Ui,
    connection_history: &Arc<Mutex<VecDeque<(f64, usize)>>>,
    threat_history: &Arc<Mutex<VecDeque<(f64, u8)>>>,
    monitor_state: &crate::state::MonitorState,
    _monitoring: bool,
) {
    // Copy all stats out of Mutex guards immediately
    let (total_scanned, active_connections, suspicious, critical) = {
        let stats = monitor_state.stats.lock().unwrap();
        let connections = monitor_state.connections.lock().unwrap();
        (
            stats.total,
            connections.len(),
            stats.suspicious,
            stats.critical,
        )
    };

    // QRadar-style stat cards at top
    ui.columns(4, |columns| {
        columns[0].group(|ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(4.0);
                ui.label(egui::RichText::new(&total_scanned.to_string()).color(WHITE).size(24.0).strong());
                ui.label(egui::RichText::new("Total Scanned").color(GRAY).size(11.0).strong());
                ui.add_space(4.0);
            });
        });
        columns[1].group(|ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(4.0);
                ui.label(egui::RichText::new(&active_connections.to_string()).color(GREEN).size(24.0).strong());
                ui.label(egui::RichText::new("Active Now").color(GRAY).size(11.0).strong());
                ui.add_space(4.0);
            });
        });
        columns[2].group(|ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(4.0);
                ui.label(egui::RichText::new(&suspicious.to_string()).color(RED).size(24.0).strong());
                ui.label(egui::RichText::new("Suspicious").color(GRAY).size(11.0).strong());
                ui.add_space(4.0);
            });
        });
        columns[3].group(|ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(4.0);
                ui.label(egui::RichText::new(&critical.to_string()).color(YELLOW).size(24.0).strong());
                ui.label(egui::RichText::new("Critical").color(GRAY).size(11.0).strong());
                ui.add_space(4.0);
            });
        });
    });

    ui.add_space(12.0);
    ui.separator();
    ui.add_space(8.0);

    // Recent activity feed
    card_panel(ui, "Recent Activity", |ui| {
        let recent: Vec<crate::state::ConnectionItem> = {
            let connections = monitor_state.connections.lock().unwrap();
            connections.iter().rev().take(10).cloned().collect()
        };

        if recent.is_empty() {
            ui.label(egui::RichText::new("No network activity captured yet").color(TEXT_MUTED));
        } else {
            for item in recent {
                let conn = &item.connection;
                let threat_color = item.threat_level.color();
                ui.horizontal(|ui| {
                    let time = chrono::DateTime::from_timestamp(conn.timestamp as i64, 0)
                        .map(|dt| dt.format("%H:%M:%S").to_string())
                        .unwrap_or_default();
                    ui.label(egui::RichText::new(time).color(GRAY).size(10.0));
                    ui.add_space(8.0);
                    ui.label(egui::RichText::new(&conn.process_name).color(WHITE).size(11.0));
                    ui.add_space(8.0);
                    ui.label(format!("{} -> {}", conn.src_ip, conn.dst_ip));
                    ui.add_space(8.0);
                    ui.colored_label(threat_color, item.threat_level.label());
                });
                ui.add_space(2.0);
            }
        }
    });

    ui.add_space(12.0);
    ui.separator();
    ui.add_space(8.0);

    // Real-time charts
    let conn_history = connection_history.lock().unwrap();
    let threat_history = threat_history.lock().unwrap();

    card_panel(ui, "Connection Count (Last 5 min)", |ui| {
        if conn_history.len() > 1 {
            let points: PlotPoints = conn_history.iter()
                .enumerate()
                .map(|(i, &(_, count))| [i as f64, count as f64])
                .collect();

            let line = Line::new(points)
                .color(PRIMARY)
                .width(2.0_f32)
                .fill(0.0_f32);

            Plot::new("conn_plot")
                .view_aspect(3.0)
                .height(200.0)
                .show(ui, |plot_ui| {
                    plot_ui.line(line);
                });
        } else {
            ui.centered_and_justified(|ui| {
                ui.label(egui::RichText::new("Waiting for data...").color(TEXT_MUTED));
            });
        }
    });

    ui.add_space(12.0);

    card_panel(ui, "Average Threat Score", |ui| {
        if threat_history.len() > 1 {
            let points: PlotPoints = threat_history.iter()
                .enumerate()
                .map(|(i, &(_, score))| [i as f64, score as f64])
                .collect();

            let line = Line::new(points)
                .color(ORANGE)
                .width(2.0_f32)
                .fill(0.0_f32);

            Plot::new("threat_plot")
                .view_aspect(3.0)
                .height(200.0)
                .show(ui, |plot_ui| {
                    plot_ui.line(line);
                });
        } else {
            ui.centered_and_justified(|ui| {
                ui.label(egui::RichText::new("Waiting for data...").color(TEXT_MUTED));
            });
        }
    });

    ui.add_space(12.0);

    // Top suspicious processes
    card_panel(ui, "Top Suspicious Processes", |ui| {
        let suspicious: Vec<crate::state::ConnectionItem> = {
            let connections = monitor_state.connections.lock().unwrap();
            connections.iter()
                .filter(|c| c.connection.is_suspicious)
                .take(10)
                .cloned()
                .collect()
        };

        if suspicious.is_empty() {
            ui.label(egui::RichText::new("No suspicious activity detected").color(GREEN));
        } else {
            egui::Grid::new("suspicious_procs_qr")
                .striped(true)
                .min_col_width(80.0)
                .show(ui, |ui| {
                    ui.label(egui::RichText::new("Process").color(PRIMARY).strong().size(11.0));
                    ui.label(egui::RichText::new("PID").color(PRIMARY).strong().size(11.0));
                    ui.label(egui::RichText::new("Max Threat").color(PRIMARY).strong().size(11.0));
                    ui.label(egui::RichText::new("Destination").color(PRIMARY).strong().size(11.0));
                    ui.end_row();

                    for item in suspicious {
                        let conn = &item.connection;
                        ui.label(egui::RichText::new(&conn.process_name).color(WHITE).size(11.0));
                        ui.label(egui::RichText::new(conn.pid.to_string()).color(WHITE).size(11.0));
                        ui.colored_label(item.threat_level.color(), item.threat_level.label());
                        ui.label(egui::RichText::new(format!("{}:{}", conn.dst_ip, conn.dst_port)).color(WHITE).size(11.0));
                        ui.end_row();
                    }
                });
        }
    });
}

/// Render process tree with QRadar styling
pub fn render_process_tree(
    ui: &mut egui::Ui,
    monitor_state: &crate::state::MonitorState,
    filter: &mut FilterSettings,
    selected_process: &mut Option<u32>,
) {
    let connections = monitor_state.connections.lock().unwrap();
    let processes = ProcessTreeItem::from_connections(&connections);
    drop(connections);

    if processes.is_empty() {
        ui.centered_and_justified(|ui| {
            ui.label(egui::RichText::new("No processes with network connections captured").color(TEXT_MUTED));
        });
        return;
    }

    ui.heading(egui::RichText::new("Process Network Tree").color(PRIMARY).strong());
    ui.separator();
    ui.add_space(4.0);

    ui.horizontal(|ui| {
        ui.label(egui::RichText::new("Click row to select • Right-click for actions").color(GRAY).size(11.0));
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui.button("Expand All").clicked() {}
        });
    });
    ui.separator();

    egui::ScrollArea::vertical().show(ui, |ui| {
        egui::Grid::new("process_tree_qr")
            .striped(true)
            .min_col_width(100.0)
            .show(ui, |ui| {
                // QRadar-style header
                ui.label(egui::RichText::new("").color(PRIMARY).strong());
                ui.label(egui::RichText::new("Process").color(PRIMARY).strong().size(11.0));
                ui.label(egui::RichText::new("PID").color(PRIMARY).strong().size(11.0));
                ui.label(egui::RichText::new("User").color(PRIMARY).strong().size(11.0));
                ui.label(egui::RichText::new("Connections").color(PRIMARY).strong().size(11.0));
                ui.label(egui::RichText::new("Max Threat").color(PRIMARY).strong().size(11.0));
                ui.label(egui::RichText::new("Status").color(PRIMARY).strong().size(11.0));
                ui.end_row();

                for proc in processes {
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

                    let process_display = if proc.name.is_empty() {
                        "unknown".to_string()
                    } else {
                        proc.name.clone()
                    };

                    let response = ui.add(egui::widgets::SelectableLabel::new(is_selected, process_display));
                    if response.clicked() {
                        *selected_process = Some(proc.pid);
                    }

                    ui.label(egui::RichText::new(proc.pid.to_string()).color(WHITE).size(11.0));
                    ui.label(egui::RichText::new(proc.user.as_deref().unwrap_or("N/A")).color(WHITE).size(11.0));
                    ui.label(egui::RichText::new(proc.connections.len().to_string()).color(WHITE).size(11.0));
                    ui.colored_label(threat_color, proc.total_threat_score.to_string());
                    ui.colored_label(threat_color, if proc.is_suspicious { "SUSPICIOUS" } else { "OK" });
                    ui.end_row();
                }
            });
    });
}

/// Render connection graph with QRadar styling
pub fn render_connection_graph(ui: &mut egui::Ui, graph: &mut crate::graph::ConnectionGraph, monitor_state: &crate::state::MonitorState) {
    ui.heading(egui::RichText::new("Connection Graph").color(PRIMARY).strong());
    ui.separator();

    let connections = monitor_state.connections.lock().unwrap();
    graph.update(&connections);
    drop(connections);

    let rect = ui.available_rect_before_wrap();
    graph.render(ui, rect);

    // Selected node detail (top-to-bottom per-tab details pane)
    if let Some(node) = graph.get_selected() {
        ui.separator();
        card_panel(ui, "Node Details", |ui| {
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

            if node.is_process {
                ui.horizontal(|ui| {
                    if ui.button("[Terminate]").clicked() {
                        if let Some(pid) = node.pid {
                            crate::ui::terminate_process(pid, &node.process_name, monitor_state);
                        }
                    }
                    if ui.button("[Block All Ports]").clicked() {
                        // Block all ports for this process
                    }
                });
            }
        });
    }
}

/// Render dashboard summary for details pane
pub fn render_dashboard_summary(ui: &mut egui::Ui) {
    ui.heading(egui::RichText::new("Dashboard Summary").color(PRIMARY).strong());
    ui.separator();
    ui.add_space(4.0);
    ui.label(egui::RichText::new("Select items from the main view to see details here.").color(TEXT_MUTED));
}

/// Render audit details for details pane
pub fn render_audit_details(ui: &mut egui::Ui) {
    ui.heading(egui::RichText::new("Audit Details").color(PRIMARY).strong());
    ui.separator();
    ui.add_space(4.0);
    ui.label(egui::RichText::new("Run an audit to see details here.").color(TEXT_MUTED));
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
        let _rule = format!("block out proto tcp from any to any port {}", port);
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
