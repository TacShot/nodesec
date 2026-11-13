use eframe::egui;
use egui_plot::{Line, Plot, PlotPoints};
use crate::state::{ConnectionItem, ThreatLevel, ConnectionStats, ProcessTreeItem, ThreatLevel::*};
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
) {
    egui::ScrollArea::vertical().show(ui, |ui| {
        egui::Grid::new("connections_table")
            .striped(true)
            .min_col_width(60.0)
            .show(ui, |ui| {
                // Header
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
                    let conn = &item.connection;
                    let threat_color = item.threat_level.color();
                    
                    let src = format!("{}:{}", conn.src_ip, conn.src_port);
                    let dst = format!("{}:{}", conn.dst_ip, conn.dst_port);
                    let proto = format!("{:?}", conn.protocol);
                    let time = chrono::DateTime::from_timestamp(conn.timestamp as i64, 0)
                        .map(|dt| dt.format("%H:%M:%S").to_string())
                        .unwrap_or_default();
                    
                    let response = ui.selectable_label(
                        *selected_connection == Some(i),
                        ""
                    );
                    
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
) {
    ui.heading(egui::RichText::new("Network Monitoring Settings").color(ORANGE).strong());
    ui.separator();
    
    egui::Grid::new("settings_grid").num_columns(2).show(ui, |ui| {
        ui.label("Platform:");
        ui.label(format!("{:?}", platform));
        ui.end_row();
        
        ui.label("Update Interval:");
        ui.label("2 seconds");
        ui.end_row();
        
        ui.label("Threat Threshold:");
        ui.label("50");
        ui.end_row();
        
        ui.label("Max Connections:");
        ui.label("1000");
        ui.end_row();
        
        ui.label("Retention:");
        ui.label("5 minutes");
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

pub fn render_process_tree(ui: &mut egui::Ui, monitor_state: &crate::state::MonitorState) {
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
    
    egui::ScrollArea::vertical().show(ui, |ui| {
        for proc in processes {
            let threat_color = match proc.total_threat_score {
                0..=25 => GREEN,
                26..=49 => YELLOW,
                50..=74 => ORANGE,
                75..=89 => egui::Color32::from_rgb(255, 100, 100),
                _ => RED,
            };
            
            ui.collapsing(
                egui::RichText::new(format!(
                    "{} (PID: {}) - {} connections - {}",
                    proc.name, proc.pid, proc.connections.len(),
                    if proc.is_suspicious { "⚠️ SUSPICIOUS" } else { "✓" }
                )).color(threat_color).size(13.0).strong(),
                |ui| {
                    ui.add_space(5.0);
                    
                    if let Some(path) = &proc.path {
                        ui.label(egui::RichText::new(format!("Path: {}", path)).color(GRAY));
                    }
                    if let Some(user) = &proc.user {
                        ui.label(egui::RichText::new(format!("User: {}", user)).color(GRAY));
                    }
                    
                    ui.separator();
                    ui.label(egui::RichText::new("Network Connections:").color(WHITE).strong());
                    
                    egui::Grid::new(format!("proc_conns_{}", proc.pid))
                        .striped(true)
                        .min_col_width(80.0)
                        .show(ui, |ui| {
                            ui.label(egui::RichText::new("Protocol").color(ORANGE).strong());
                            ui.label(egui::RichText::new("Source").color(ORANGE).strong());
                            ui.label(egui::RichText::new("Destination").color(ORANGE).strong());
                            ui.label(egui::RichText::new("Threat").color(ORANGE).strong());
                            ui.end_row();
                            
                            for conn in &proc.connections {
                                let proto = format!("{:?}", conn.protocol);
                                let src = format!("{}:{}", conn.src_ip, conn.src_port);
                                let dst = format!("{}:{}", conn.dst_ip, conn.dst_port);
                                let threat_color = match conn.threat_score {
                                    0..=25 => GREEN,
                                    26..=49 => YELLOW,
                                    50..=74 => ORANGE,
                                    75..=89 => egui::Color32::from_rgb(255, 100, 100),
                                    _ => RED,
                                };
                                
                                ui.label(proto);
                                ui.label(src);
                                ui.label(dst);
                                ui.colored_label(threat_color, conn.threat_score.to_string());
                                ui.end_row();
                            }
                        });
                }
            );
        }
    });
}

pub fn render_connection_graph(ui: &mut egui::Ui, graph: &mut crate::graph::ConnectionGraph) {
    ui.heading(egui::RichText::new("Connection Graph").color(ORANGE));
    ui.separator();
    
    let rect = ui.available_rect_before_wrap();
    graph.render(ui, rect);
}