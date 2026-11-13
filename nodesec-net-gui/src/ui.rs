use eframe::egui;
use crate::state::{ConnectionItem, ThreatLevel, ConnectionStats, ThreatLevel::*};
use nodesec_core::models::NetworkConnection;

// Colors matching 7-color palette
const GREEN: egui::Color32 = egui::Color32::from_rgb(0, 255, 0);
const YELLOW: egui::Color32 = egui::Color32::from_rgb(255, 255, 0);
const ORANGE: egui::Color32 = egui::Color32::from_rgb(255, 165, 0);
const RED: egui::Color32 = egui::Color32::from_rgb(255, 0, 0);
const WHITE: egui::Color32 = egui::Color32::from_rgb(255, 255, 255);
const BLACK: egui::Color32 = egui::Color32::from_rgb(0, 0, 0);
const GRAY: egui::Color32 = egui::Color32::from_rgb(136, 136, 136);

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
    connections: &[crate::state::ConnectionItem],
    _selected_connection: &mut usize,
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
    stats: &crate::state::ConnectionStats,
    connections: &[crate::state::ConnectionItem],
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
    
    ui.label("Press 'Q' to quit, Tab to switch tabs");
}