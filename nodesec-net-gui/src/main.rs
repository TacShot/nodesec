use eframe::egui;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use std::collections::VecDeque;
use tokio::runtime;
use nodesec_core::{
    models::Platform,
    network::{common::NetworkMonitor},
};

mod state;
mod monitor;
mod ui;
mod graph;

use crate::state::FilterSettings;
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
    selected_process: Option<u32>,
    selected_graph_node: Option<String>,
    graph: ConnectionGraph,
    filter: FilterSettings,
}

impl App {
    fn new(monitor_state: Arc<state::MonitorState>) -> Self {
        let monitor_state_for_graph = monitor_state.clone();
        Self {
            selected_tab: Tab::Dashboard,
            monitor_state,
            last_update: Instant::now(),
            monitoring: false,
            connection_history: Arc::new(Mutex::new(VecDeque::with_capacity(300))),
            threat_history: Arc::new(Mutex::new(VecDeque::with_capacity(300))),
            selected_connection: None,
            selected_process: None,
            selected_graph_node: None,
            graph: ConnectionGraph::new(monitor_state_for_graph),
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
        crate::ui::render_process_tree(ui, &self.monitor_state, &mut self.filter, &mut self.selected_process);
    }
    
    fn render_connection_graph(&mut self, ui: &mut egui::Ui) {
        crate::ui::render_connection_graph(ui, &mut self.graph, &self.monitor_state);
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
    
    fn render_process_detail(&mut self, ui: &mut egui::Ui, proc: &crate::state::ProcessTreeItem) {
        let threat_color = match proc.total_threat_score {
            0..=25 => GREEN,
            26..=49 => YELLOW,
            50..=74 => ORANGE,
            75..=89 => egui::Color32::from_rgb(255, 100, 100),
            _ => RED,
        };
        
        ui.heading(egui::RichText::new(format!("{} (PID: {})", proc.name, proc.pid)).color(threat_color).strong());
        ui.separator();
        
        egui::Grid::new("proc_detail").num_columns(2).show(ui, |ui| {
            detail_row(ui, "Process", &proc.name);
            detail_row(ui, "PID", &proc.pid.to_string());
            if let Some(path) = &proc.path {
                detail_row(ui, "Path", path);
            }
            if let Some(user) = &proc.user {
                detail_row(ui, "User", user);
            }
            detail_row(ui, "Connections", &proc.connections.len().to_string());
            detail_row(ui, "Max Threat Score", &proc.total_threat_score.to_string());
            detail_row(ui, "Status", if proc.is_suspicious { "⚠️ SUSPICIOUS" } else { "✓ OK" });
        });
        
        ui.separator();
        
        // Actions
        ui.horizontal(|ui| {
            if ui.button("🔴 Terminate").clicked() {
                crate::ui::terminate_process(proc.pid, &proc.name, &self.monitor_state);
            }
            if ui.button("🚫 Block All Ports").clicked() {
                // TODO
            }
            if ui.button("📋 Copy PID").clicked() {
                ui.output_mut(|o| o.copied_text = proc.pid.to_string());
            }
            if ui.button("📋 Copy Name").clicked() {
                ui.output_mut(|o| o.copied_text = proc.name.clone());
            }
            if let Some(path) = &proc.path {
                if ui.button("📋 Copy Path").clicked() {
                    ui.output_mut(|o| o.copied_text = path.clone());
                }
            }
        });
        
        ui.separator();
        ui.label(egui::RichText::new("Network Connections:").color(WHITE).strong());
        
        egui::ScrollArea::vertical().max_height(300.0).show(ui, |ui| {
            egui::Grid::new("proc_detail_conns")
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
        });
    }
    
    fn render_graph_node_detail(&mut self, ui: &mut egui::Ui, node: &crate::graph::GraphNode) {
        ui.heading(egui::RichText::new(&node.label).color(node.color).strong());
        ui.separator();
        
        egui::Grid::new("node_detail").num_columns(2).show(ui, |ui| {
            detail_row(ui, "Type", if node.is_process { "Process" } else { "Remote Host" });
            if let Some(pid) = node.pid {
                detail_row(ui, "PID", &pid.to_string());
            }
            detail_row(ui, "Process", &node.process_name);
            if let Some(iface) = &node.interface {
                detail_row(ui, "Interface", iface);
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
        
        ui.separator();
        
        // Actions
        ui.horizontal(|ui| {
            if node.is_process {
                if let Some(pid) = node.pid {
                    if ui.button("🔴 Terminate").clicked() {
                                    crate::ui::terminate_process(pid, &node.process_name, &self.monitor_state);
                                }
                    if ui.button("🚫 Block All Ports").clicked() {
                        // TODO
                    }
                    if ui.button("📋 Copy PID").clicked() {
                        ui.output_mut(|o| o.copied_text = pid.to_string());
                    }
                    if ui.button("📋 Copy Name").clicked() {
                        ui.output_mut(|o| o.copied_text = node.process_name.clone());
                    }
                }
            } else {
                if let Some(ip) = &node.remote_ip {
                    if ui.button("🚫 Block IP").clicked() {
                        crate::ui::block_ip(ip, node.pid.unwrap_or(0), &node.label, &self.monitor_state);
                    }
                }
                if let Some(port) = node.remote_port {
                    if ui.button("🚫 Block Port").clicked() {
                        crate::ui::block_port(port, node.pid.unwrap_or(0), &node.label, &self.monitor_state);
                    }
                }
                if ui.button("📋 Copy IP:Port").clicked() {
                    ui.output_mut(|o| o.copied_text = node.label.clone());
                }
            }
            if ui.button("🔍 Focus on Graph").clicked() {
                // Center graph on this node
                self.selected_graph_node = Some(node.id.clone());
            }
        });
    }
    
    fn render_dashboard_summary(&mut self, ui: &mut egui::Ui) {
        let stats = self.monitor_state.stats.lock().unwrap();
        let connections = self.monitor_state.connections.lock().unwrap();
        
        ui.horizontal(|ui| {
            crate::ui::stat_card(ui, "Total Scanned", &stats.total.to_string(), WHITE);
            crate::ui::stat_card(ui, "Active Now", &connections.len().to_string(), GREEN);
        });
        
        ui.separator();
        
        // Top suspicious
        let suspicious: Vec<_> = connections.iter()
            .filter(|c| c.connection.is_suspicious)
            .take(5)
            .collect();
        
        if !suspicious.is_empty() {
            ui.label(egui::RichText::new("Top Suspicious:").color(RED).strong());
            for item in suspicious {
                let conn = &item.connection;
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new(&conn.process_name).size(11.0));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.colored_label(item.threat_level.color(), item.threat_level.label());
                    });
                });
            }
        } else {
            ui.label(egui::RichText::new("No suspicious activity").color(GREEN));
        }
        
        ui.separator();
        
        // Connection types breakdown
        use std::collections::HashMap;
        let mut type_counts: HashMap<String, usize> = HashMap::new();
        for item in connections.iter() {
            let proto = format!("{:?}", item.connection.protocol);
            *type_counts.entry(proto).or_insert(0) += 1;
        }
        
        ui.label(egui::RichText::new("By Protocol:").color(ORANGE).strong());
        for (proto, count) in type_counts {
            ui.horizontal(|ui| {
                ui.label(proto);
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(count.to_string());
                });
            });
        }
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
            window_stroke: egui::Stroke::new(1.0_f32, BORDER),
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
        
        // Details pane on right side - shows details based on selected item and tab
        egui::SidePanel::right("details_pane")
            .min_width(320.0)
            .max_width(450.0)
            .resizable(true)
            .show(ctx, |ui| {
                ui.heading(egui::RichText::new("Details").color(ORANGE).strong());
                ui.separator();
                
                match self.selected_tab {
                    Tab::Connections => {
                        let conn_data = {
                            if let Some(idx) = self.selected_connection {
                                let connections = self.monitor_state.connections.lock().unwrap();
                                if idx < connections.len() {
                                    Some((connections[idx].clone(), self.monitor_state.clone()))
                                } else {
                                    None
                                }
                            } else {
                                None
                            }
                        };
                        
                        if let Some((conn, monitor_state)) = conn_data {
                            crate::ui::render_connection_detail(ui, &conn, &monitor_state);
                        } else {
                            ui.centered_and_justified(|ui| {
                                ui.label(egui::RichText::new("Select a connection to view details").color(GRAY));
                            });
                        }
                    }
                    Tab::ProcessTree => {
                        let proc_data = {
                            if let Some(pid) = self.selected_process {
                                let connections = self.monitor_state.connections.lock().unwrap();
                                let processes = crate::state::ProcessTreeItem::from_connections(&connections);
                                processes.iter().find(|p| p.pid == pid).cloned()
                            } else {
                                None
                            }
                        };
                        
                        if let Some(proc) = proc_data {
                            self.render_process_detail(ui, &proc);
                        } else {
                            ui.centered_and_justified(|ui| {
                                ui.label(egui::RichText::new("Select a process to view details").color(GRAY));
                            });
                        }
                    }
                    Tab::ConnectionGraph => {
                        if let Some(node) = self.graph.get_selected() {
                            self.render_graph_node_detail(ui, &node);
                        } else {
                            ui.centered_and_justified(|ui| {
                                ui.label(egui::RichText::new("Click a node to view details").color(GRAY));
                            });
                        }
                    }
                    Tab::Dashboard => {
                        self.render_dashboard_summary(ui);
                    }
                    _ => {
                        ui.centered_and_justified(|ui| {
                            ui.label(egui::RichText::new("Select an item to view details").color(GRAY));
                        });
                    }
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
                let monitor_state_for_graph = monitor_state.clone();

                let app = App {
                    selected_tab: Tab::Dashboard,
                    monitor_state,
                    last_update: Instant::now(),
                    monitoring: false,
                    connection_history: Arc::new(Mutex::new(VecDeque::with_capacity(300))),
                    threat_history: Arc::new(Mutex::new(VecDeque::with_capacity(300))),
                    selected_connection: None,
                    selected_process: None,
                    selected_graph_node: None,
                    graph: ConnectionGraph::new(monitor_state_for_graph),
                    filter: FilterSettings::default(),
                };
        
        eframe::run_native(
            "Nodesec Network Monitor",
            options,
            Box::new(|cc| {
                // Configure fonts to support Unicode/emoji characters
                let mut fonts = egui::FontDefinitions::default();
                
                // Use system font as fallback for Unicode/emoji
                // On macOS, use SF Pro + Apple Color Emoji
                #[cfg(target_os = "macos")]
                {
                    if let Ok(data) = std::fs::read("/System/Library/Fonts/Supplemental/Apple Color Emoji.ttf") {
                        fonts.font_data.insert("emoji".to_owned(), egui::FontData::from_owned(data));
                        fonts.families
                            .entry(egui::FontFamily::Proportional)
                            .or_default()
                            .insert(0, "emoji".to_owned());
                    }
                }
                
                #[cfg(target_os = "linux")]
                {
                    // Try Noto Color Emoji on Linux
                    for path in [
                        "/usr/share/fonts/truetype/noto/NotoColorEmoji.ttf",
                        "/usr/share/fonts/opentype/noto/NotoColorEmoji.ttf",
                    ] {
                        if let Ok(data) = std::fs::read(path) {
                            fonts.font_data.insert("emoji".to_owned(), egui::FontData::from_owned(data));
                            fonts.families
                                .entry(egui::FontFamily::Proportional)
                                .or_default()
                                .insert(0, "emoji".to_owned());
                            break;
                        }
                    }
                }
                
                #[cfg(target_os = "windows")]
                {
                    // Windows 10+ has Segoe UI Emoji
                    if let Ok(data) = std::fs::read("C:\\Windows\\Fonts\\seguiemj.ttf") {
                        fonts.font_data.insert("emoji".to_owned(), egui::FontData::from_owned(data));
                        fonts.families
                            .entry(egui::FontFamily::Proportional)
                            .or_default()
                            .insert(0, "emoji".to_owned());
                    }
                }
                
                cc.egui_ctx.set_fonts(fonts);
                
                Ok(Box::new(app))
            }),
        ).map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
    })
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    run_net_gui()
}