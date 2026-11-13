use eframe::egui;
use egui_plot::{Line, Plot, PlotPoints};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use std::collections::VecDeque;
use tokio::runtime;
use nodesec_core::{
    models::{NetworkConnection, Platform},
    network::{common::NetworkMonitor},
};

mod state;
mod monitor;
mod ui;
mod graph;

use crate::state::{MonitorState, ThreatLevel, ConnectionItem, ProcessTreeItem, FilterSettings};
use crate::monitor::{start_monitoring, stop_monitoring};
use crate::ui::{render_connections_table, render_alerts, render_statistics, render_settings, render_dashboard, render_process_tree, render_connection_graph, render_connection_detail, stat_card};
use crate::graph::ConnectionGraph;

// Colors matching 7-color palette
const GREEN: egui::Color32 = egui::Color32::from_rgb(0, 255, 0);
const YELLOW: egui::Color32 = egui::Color32::from_rgb(255, 255, 0);
const ORANGE: egui::Color32 = egui::Color32::from_rgb(255, 165, 0);
const RED: egui::Color32 = egui::Color32::from_rgb(255, 0, 0);
const WHITE: egui::Color32 = egui::Color32::from_rgb(255, 255, 255);
const BLACK: egui::Color32 = egui::Color32::from_rgb(0, 0, 0);
const GRAY: egui::Color32 = egui::Color32::from_rgb(136, 136, 136);
const DARK_BG: egui::Color32 = egui::Color32::from_rgb(30, 30, 30);
const PANEL_BG: egui::Color32 = egui::Color32::from_rgb(45, 45, 45);
const BORDER: egui::Color32 = egui::Color32::from_rgb(80, 80, 80);

#[derive(Clone, Copy, PartialEq)]
enum Tab {
    Dashboard,
    Connections,
    ProcessTree,
    ConnectionGraph,
    Alerts,
    Statistics,
    Settings,
}

impl Tab {
    fn label(&self) -> &'static str {
        match self {
            Tab::Dashboard => "📊 Dashboard",
            Tab::Connections => "🔗 Connections",
            Tab::ProcessTree => "🌳 Process Tree",
            Tab::ConnectionGraph => "🕸️ Graph",
            Tab::Alerts => "⚠️ Alerts",
            Tab::Statistics => "📈 Statistics",
            Tab::Settings => "⚙️ Settings",
        }
    }
}

struct App {
    selected_tab: Tab,
    monitor_state: Arc<state::MonitorState>,
    last_update: Instant,
    monitoring: bool,
    // Dashboard data
    connection_history: Arc<Mutex<VecDeque<(f64, usize)>>>, // (timestamp, count)
    threat_history: Arc<Mutex<VecDeque<(f64, u8)>>>, // (timestamp, avg threat)
    selected_connection: Option<usize>,
    graph: ConnectionGraph,
    filter: FilterSettings,
}

impl App {
    fn new(monitor_state: Arc<state::MonitorState>) -> Self {
        Self {
            selected_tab: Tab::Dashboard,
            monitor_state,
            last_update: Instant::now(),
            monitoring: false,
            connection_history: Arc::new(Mutex::new(VecDeque::with_capacity(300))),
            threat_history: Arc::new(Mutex::new(VecDeque::with_capacity(300))),
            selected_connection: None,
            graph: ConnectionGraph::new(),
            filter: FilterSettings::default(),
        }
    }
    
    fn start_monitoring(&mut self) {
        if self.monitoring {
            return;
        }
        self.monitoring = true;
        crate::monitor::start_monitoring(self.monitor_state.clone());
    }
    
    fn stop_monitoring(&mut self) {
        if !self.monitoring {
            return;
        }
        self.monitoring = false;
        crate::monitor::stop_monitoring(self.monitor_state.monitoring.clone());
    }
    
    fn update_history(&mut self) {
        let connections = self.monitor_state.connections.lock().unwrap();
        let now = Instant::now().elapsed().as_secs_f64();
        
        // Update connection count history
        {
            let mut history = self.connection_history.lock().unwrap();
            history.push_back((now, connections.len()));
            while history.len() > 300 {
                history.pop_front();
            }
        }
        
        // Update threat score history
        {
            let mut history = self.threat_history.lock().unwrap();
            let avg_threat = if connections.is_empty() {
                0
            } else {
                connections.iter().map(|c| c.connection.threat_score as u32).sum::<u32>() / connections.len() as u32
            } as u8;
            history.push_back((now, avg_threat));
            while history.len() > 300 {
                history.pop_front();
            }
        }
        
        // Update graph
        self.graph.update(&connections);
    }
    
    fn render_dashboard(&mut self, ui: &mut egui::Ui) {
        crate::ui::render_dashboard(
            ui, 
            &self.connection_history, 
            &self.threat_history,
            &self.monitor_state,
            self.monitoring
        );
    }
    
    fn render_connections(&mut self, ui: &mut egui::Ui) {
        // Toolbar
        ui.horizontal(|ui| {
            if ui.button(if self.monitoring { "⏹ Stop Monitoring" } else { "▶ Start Monitoring" }).clicked() {
                if self.monitoring {
                    self.stop_monitoring();
                } else {
                    self.start_monitoring();
                }
            }
            
            if ui.button("⏸ Pause").clicked() {
                // TODO: implement pause
            }
            
            if ui.button("🗑 Clear").clicked() {
                self.monitor_state.connections.lock().unwrap().clear();
                self.monitor_state.alerts.lock().unwrap().clear();
                self.connection_history.lock().unwrap().clear();
                self.threat_history.lock().unwrap().clear();
            }
            
            ui.separator();
            
            // Filter status
            if !self.filter.process_name.is_empty() || self.filter.pid.is_some() || self.filter.only_suspicious {
                ui.label(egui::RichText::new("Filters Active").color(YELLOW));
            }
            
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("💾 Export").clicked() {
                    // TODO: export
                }
            });
        });
        
        ui.separator();
        
        // Connections table with filter
        let connections = self.monitor_state.connections.lock().unwrap();
        
        egui::ScrollArea::vertical().show(ui, |ui| {
            crate::ui::render_connections_table(ui, &connections, &mut self.selected_connection, &mut self.filter);
        });
        
        // Detail panel for selected connection
        if let Some(idx) = self.selected_connection {
            if idx < connections.len() {
                ui.separator();
                crate::ui::render_connection_detail(ui, &connections[idx], &self.monitor_state);
            }
        }
    }
    
    fn render_process_tree(&mut self, ui: &mut egui::Ui) {
        crate::ui::render_process_tree(ui, &self.monitor_state, &mut self.filter);
    }
    
    fn render_connection_graph(&mut self, ui: &mut egui::Ui) {
        crate::ui::render_connection_graph(ui, &mut self.graph);
    }
    
    fn render_alerts(&mut self, ui: &mut egui::Ui) {
        let alerts = self.monitor_state.alerts.lock().unwrap();
        crate::ui::render_alerts(ui, &alerts);
    }
    
    fn render_statistics(&mut self, ui: &mut egui::Ui) {
        let stats = self.monitor_state.stats.lock().unwrap().clone();
        let connections = self.monitor_state.connections.lock().unwrap().clone();
        crate::ui::render_statistics(ui, &stats, &connections);
    }
    
    fn render_settings(&mut self, ui: &mut egui::Ui) {
        crate::ui::render_settings(ui, self.monitor_state.platform, &self.monitor_state);
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Request repaint for live updates
        ctx.request_repaint_after(Duration::from_millis(500));
        
        // Update history data
        self.update_history();
        
        // Apply dark theme
        ctx.set_visuals(egui::Visuals {
            dark_mode: true,
            override_text_color: Some(WHITE),
            window_fill: DARK_BG,
            panel_fill: PANEL_BG,
            window_stroke: egui::Stroke::new(1.0, BORDER),
            ..Default::default()
        });
        
        // Top header bar
        egui::TopBottomPanel::top("header").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.add_space(10.0);
                ui.label(egui::RichText::new("NODESEC NETWORK MONITOR").color(ORANGE).size(20.0).strong());
                ui.add_space(20.0);
                
                let monitoring = *self.monitor_state.monitoring.lock().unwrap();
                let status = if monitoring { "● LIVE" } else { "○ STOPPED" };
                let status_color = if monitoring { GREEN } else { YELLOW };
                ui.label(egui::RichText::new(status).color(status_color).size(16.0).strong());
                
                ui.separator();
                
                ui.label(egui::RichText::new(format!("Platform: {:?}", self.monitor_state.platform)).color(GRAY).size(13.0));
                
                let stats = self.monitor_state.stats.lock().unwrap();
                ui.label(egui::RichText::new(format!("Connections: {}", stats.total)).color(GRAY).size(13.0));
                ui.label(egui::RichText::new(format!("Suspicious: {}", stats.suspicious)).color(RED).size(13.0));
                
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.add_space(20.0);
                    if ui.button("❌ Quit").clicked() {
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                });
            });
        });
        
        // Tab bar
        egui::TopBottomPanel::top("tabs").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.add_space(10.0);
                for tab in [
                    Tab::Dashboard, Tab::Connections, Tab::ProcessTree, 
                    Tab::ConnectionGraph, Tab::Alerts, Tab::Statistics, Tab::Settings
                ] {
                    let selected = self.selected_tab == tab;
                    let response = ui.selectable_label(selected, tab.label());
                    if response.clicked() {
                        self.selected_tab = tab;
                    }
                }
            });
        });
        
        // Bottom status bar
        egui::TopBottomPanel::bottom("footer").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.add_space(10.0);
                ui.label(egui::RichText::new("Shortcuts: ").color(GRAY));
                ui.label(egui::RichText::new("1-7 ").color(ORANGE).strong()).on_hover_text("Switch tabs");
                ui.label(egui::RichText::new("Tab ").color(ORANGE).strong()).on_hover_text("Next tab");
                ui.label(egui::RichText::new("Click ").color(ORANGE).strong()).on_hover_text("Select row");
                ui.label(egui::RichText::new("Scroll ").color(ORANGE).strong()).on_hover_text("Mouse wheel");
                ui.label(egui::RichText::new("Space ").color(ORANGE).strong()).on_hover_text("Pause");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(egui::RichText::new("Nodesec v0.1.0").color(GRAY));
                });
            });
        });
        
        // Side panel for quick info
        egui::SidePanel::right("side_panel")
            .min_width(280.0)
            .max_width(350.0)
            .show(ctx, |ui| {
                ui.heading("Quick Stats");
                ui.separator();
                
                let connections = self.monitor_state.connections.lock().unwrap();
                let stats = self.monitor_state.stats.lock().unwrap();
                
                crate::ui::stat_card(ui, "Total", &stats.total.to_string(), GREEN);
                crate::ui::stat_card(ui, "Active", &connections.len().to_string(), ORANGE);
                crate::ui::stat_card(ui, "Suspicious", &stats.suspicious.to_string(), RED);
                crate::ui::stat_card(ui, "Critical", &stats.critical.to_string(), YELLOW);
                
                ui.separator();
                ui.heading("Top Processes");
                for item in connections.iter().take(10) {
                    let conn = &item.connection;
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new(&conn.process_name).size(11.0));
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            let color = item.threat_level.color();
                            ui.colored_label(color, item.threat_level.label());
                        });
                    });
                }
            });
        
        // Main content area
        egui::CentralPanel::default().show(ctx, |ui| {
            match self.selected_tab {
                Tab::Dashboard => self.render_dashboard(ui),
                Tab::Connections => self.render_connections(ui),
                Tab::ProcessTree => self.render_process_tree(ui),
                Tab::ConnectionGraph => self.render_connection_graph(ui),
                Tab::Alerts => self.render_alerts(ui),
                Tab::Statistics => self.render_statistics(ui),
                Tab::Settings => self.render_settings(ui),
            }
        });
    }
}

fn detail_row(ui: &mut egui::Ui, label: &str, value: &str) {
    ui.label(egui::RichText::new(label).color(GRAY).size(12.0));
    ui.label(egui::RichText::new(value).color(WHITE).size(12.0));
}

pub fn run_net_gui() -> Result<(), Box<dyn std::error::Error>> {
    // Create a multi-threaded tokio runtime for async network monitoring
    let rt = runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("Failed to create tokio runtime");
    
    let handle = rt.handle().clone();
    
    // Run the GUI within the tokio runtime context
    rt.block_on(async {
        let _guard = handle.enter();
        
        let options = eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default()
                .with_inner_size([1400.0, 900.0])
                .with_min_inner_size([1000.0, 700.0])
                .with_title("Nodesec Network Monitor"),
            ..Default::default()
        };
        
        let monitor_state = Arc::new(state::MonitorState::new(Platform::detect()));
        
        let app = App {
            selected_tab: Tab::Dashboard,
            monitor_state,
            last_update: Instant::now(),
            monitoring: false,
            connection_history: Arc::new(Mutex::new(VecDeque::with_capacity(300))),
            threat_history: Arc::new(Mutex::new(VecDeque::with_capacity(300))),
            selected_connection: None,
            graph: ConnectionGraph::new(),
            filter: FilterSettings::default(),
        };
        
        eframe::run_native(
            "Nodesec Network Monitor",
            options,
            Box::new(|_cc| Ok(Box::new(app))),
        ).map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
    })
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    run_net_gui()
}