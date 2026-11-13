use eframe::egui;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::runtime;
use nodesec_core::{
    models::{NetworkConnection, Platform},
    network::{common::NetworkMonitor},
};

mod state;
mod monitor;
mod ui;

use crate::state::{MonitorState, ThreatLevel};
use crate::monitor::{start_monitoring, stop_monitoring};
use crate::ui::{render_connections_table, render_alerts, render_statistics, render_settings, stat_card};

// Colors matching 7-color palette
const GREEN: egui::Color32 = egui::Color32::from_rgb(0, 255, 0);
const YELLOW: egui::Color32 = egui::Color32::from_rgb(255, 255, 0);
const ORANGE: egui::Color32 = egui::Color32::from_rgb(255, 165, 0);
const RED: egui::Color32 = egui::Color32::from_rgb(255, 0, 0);
const WHITE: egui::Color32 = egui::Color32::from_rgb(255, 255, 255);
const BLACK: egui::Color32 = egui::Color32::from_rgb(0, 0, 0);
const GRAY: egui::Color32 = egui::Color32::from_rgb(136, 136, 136);

#[derive(Clone, Copy, PartialEq)]
enum Tab {
    Connections,
    Alerts,
    Statistics,
    Settings,
}

impl Tab {
    fn label(&self) -> &'static str {
        match self {
            Tab::Connections => "Connections",
            Tab::Alerts => "Alerts",
            Tab::Statistics => "Statistics",
            Tab::Settings => "Settings",
        }
    }
}

struct App {
    selected_tab: Tab,
    monitor_state: Arc<state::MonitorState>,
    last_update: Instant,
    monitoring: bool,
}

impl App {
    fn new(monitor_state: Arc<state::MonitorState>) -> Self {
        Self {
            selected_tab: Tab::Connections,
            monitor_state,
            last_update: Instant::now(),
            monitoring: false,
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
    
    fn render_connections(&mut self, ui: &mut egui::Ui) {
        // Toolbar
        ui.horizontal(|ui| {
            if ui.button(if self.monitoring { "Stop Monitoring" } else { "Start Monitoring" }).clicked() {
                if self.monitoring {
                    self.stop_monitoring();
                } else {
                    self.start_monitoring();
                }
            }
            
            if ui.button("Pause").clicked() {
                // TODO: implement pause
            }
            
            if ui.button("Clear").clicked() {
                self.monitor_state.connections.lock().unwrap().clear();
                self.monitor_state.alerts.lock().unwrap().clear();
            }
            
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("Export").clicked() {
                    // TODO: export
                }
            });
        });
        
        ui.separator();
        
        // Connections table
        let connections = self.monitor_state.connections.lock().unwrap();
        
        egui::ScrollArea::vertical().show(ui, |ui| {
            crate::ui::render_connections_table(ui, &connections, &mut 0);
        });
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
        crate::ui::render_settings(ui, self.monitor_state.platform);
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Request repaint for live updates
        ctx.request_repaint_after(Duration::from_millis(500));
        
        // Header
        egui::TopBottomPanel::top("header").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("NODESEC NETWORK").color(ORANGE).size(18.0).strong());
                ui.separator();
                
                let monitoring = *self.monitor_state.monitoring.lock().unwrap();
                let status = if monitoring { "LIVE" } else { "STOPPED" };
                let status_color = if monitoring { GREEN } else { YELLOW };
                ui.label(egui::RichText::new(format!("[{}]", status)).color(status_color).size(14.0).strong());
                
                ui.label(egui::RichText::new(format!("Platform: {:?}", self.monitor_state.platform)).color(GRAY).size(12.0));
                
                let stats = self.monitor_state.stats.lock().unwrap();
                ui.label(egui::RichText::new(format!("Connections: {}", stats.total)).color(GRAY).size(12.0));
            });
        });
        
        // Tab bar
        egui::TopBottomPanel::top("tabs").show(ctx, |ui| {
            ui.horizontal(|ui| {
                for tab in [Tab::Connections, Tab::Alerts, Tab::Statistics, Tab::Settings] {
                    let selected = self.selected_tab == tab;
                    let response = ui.selectable_label(selected, tab.label());
                    if response.clicked() {
                        self.selected_tab = tab;
                    }
                }
            });
        });
        
        // Footer
        egui::TopBottomPanel::bottom("footer").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("Tab/Shift+Tab: Switch tabs  ").color(GRAY));
                ui.label(egui::RichText::new("↑/↓: Scroll  ").color(GRAY));
                ui.label(egui::RichText::new("Space: Pause  ").color(GRAY));
                ui.label(egui::RichText::new("A: Alerts  ").color(GRAY));
                ui.label(egui::RichText::new("Q: Quit").color(GRAY));
            });
        });
        
        // Main content
        egui::CentralPanel::default().show(ctx, |ui| {
            match self.selected_tab {
                Tab::Connections => self.render_connections(ui),
                Tab::Alerts => self.render_alerts(ui),
                Tab::Statistics => self.render_statistics(ui),
                Tab::Settings => self.render_settings(ui),
            }
        });
    }
}

pub fn run_net_gui() -> Result<(), Box<dyn std::error::Error>> {
    // Create a multi-threaded tokio runtime for async network monitoring
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("Failed to create tokio runtime");
    
    let runtime_handle = runtime.handle().clone();
    
    // Run the GUI within the tokio runtime context
    runtime.block_on(async {
        let _guard = runtime_handle.enter();
        
        let options = eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default()
                .with_inner_size([1200.0, 800.0])
                .with_min_inner_size([900.0, 600.0])
                .with_title("Nodesec Network Monitor"),
            ..Default::default()
        };

        let monitor_state = Arc::new(state::MonitorState::new(Platform::detect()));

        let app = App {
            selected_tab: Tab::Connections,
            monitor_state,
            last_update: Instant::now(),
            monitoring: false,
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
