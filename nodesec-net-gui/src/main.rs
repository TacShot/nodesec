use chrono;
use eframe::egui;
use std::sync::{Arc, Mutex};
use std::env;
use std::time::{Duration, Instant};
use std::collections::VecDeque;
use tokio::runtime;
use nodesec_core::models::Platform;
use serde_json::{Map, Value};
use nodesec_core::audit::AuditEngine;

mod state;
mod monitor;
mod ui;
mod graph;

use crate::state::{FilterSettings, RootStatus};
use nodesec_core::models::{ConnectedDevice, DeviceType};
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
    Audit,
    Reports,
    Devices,
    Settings,
}

impl Tab {
    fn label(&self) -> &'static str {
        match self {
            Tab::Dashboard => "Dashboard",
            Tab::Connections => "Connections",
            Tab::ProcessTree => "Process Tree",
            Tab::ConnectionGraph => "Graph",
            Tab::Alerts => "Alerts",
            Tab::Statistics => "Statistics",
            Tab::Audit => "Audit",
            Tab::Reports => "Reports",
            Tab::Devices => "Devices",
            Tab::Settings => "Settings",
        }
    }
}

// Sort state for tables
#[derive(Clone, Copy, PartialEq, Eq)]
enum SortField {
    Process,
    Pid,
    User,
    Connections,
    ThreatScore,
    Status,
    Time,
    Proto,
    Source,
    Destination,
    Score,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SortDir {
    Asc,
    Desc,
}

impl SortDir {
    fn toggle(&mut self) {
        *self = match self {
            SortDir::Asc => SortDir::Desc,
            SortDir::Desc => SortDir::Asc,
        };
    }

    fn icon(&self) -> &'static str {
        match self {
            SortDir::Asc => "[A]",
            SortDir::Desc => "[D]",
        }
    }
}

struct App {
    selected_tab: Tab,
    monitor_state: Arc<state::MonitorState>,
    last_update: Instant,
    monitoring: bool,
    // Dashboard data
    connection_history: Arc<Mutex<VecDeque<(f64, usize)>>>,
    threat_history: Arc<Mutex<VecDeque<(f64, u8)>>>,
    // Selections
    selected_connection_id: Option<String>,
    selected_process: Option<u32>,
    selected_graph_node: Option<String>,
    graph: ConnectionGraph,
    filter: FilterSettings,
    // Details pane - separate state so it persists across tab switches
    details_selected_tab: Tab,
    details_selected_conn: Option<nodesec_core::models::NetworkConnection>,
    details_selected_pid: Option<u32>,
    details_selected_node: Option<String>,
    // Details pane visibility
    show_details_pane: bool,
    // Sort state
    conn_sort_field: SortField,
    conn_sort_dir: SortDir,
    proc_sort_field: SortField,
    proc_sort_dir: SortDir,
    
    // Sort state tracking
    
    // Graph pan/zoom state
    graph_offset: egui::Vec2,
    graph_zoom: f32,
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
            selected_connection_id: None,
            selected_process: None,
            selected_graph_node: None,
            graph: ConnectionGraph::new(monitor_state_for_graph),
            filter: FilterSettings::default(),
            details_selected_tab: Tab::Dashboard,
            details_selected_conn: None,
            details_selected_pid: None,
            details_selected_node: None,
            show_details_pane: true,
            conn_sort_field: SortField::Time,
            conn_sort_dir: SortDir::Desc,
            proc_sort_field: SortField::Process,
            proc_sort_dir: SortDir::Asc,
    
    
            graph_offset: egui::Vec2::ZERO,
            graph_zoom: 1.0,
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

        {
            let mut history = self.connection_history.lock().unwrap();
            history.push_back((now, connections.len()));
            while history.len() > 300 {
                history.pop_front();
            }
        }

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
                self.connection_history.lock().unwrap().clear();
                self.threat_history.lock().unwrap().clear();
                self.selected_connection_id = None;
                self.details_selected_conn = None;
            }

            ui.separator();

            if !self.filter.process_name.is_empty() || self.filter.pid.is_some() || self.filter.only_suspicious {
                ui.label(egui::RichText::new("Filters Active").color(YELLOW));
            }

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("Export").clicked() {
                    // TODO: export
                }
            });
        });

        ui.separator();

        let terminated = self.monitor_state.terminated_pids.lock().unwrap().clone();
        // Clone connections to avoid borrow issues
        let mut connections: Vec<crate::state::ConnectionItem> = self.monitor_state.connections.lock().unwrap().clone();

        // Apply filter and exclude terminated PIDs
        connections.retain(|item| self.filter.matches(item) && !terminated.contains(&item.connection.pid));

        // Always sort connections
        connections.sort_by(|a, b| {
            let ordering = match self.conn_sort_field {
                SortField::Process => a.connection.process_name.cmp(&b.connection.process_name),
                SortField::Pid => a.connection.pid.cmp(&b.connection.pid),
                SortField::Time => {
                    let ta = chrono::DateTime::from_timestamp(a.connection.timestamp as i64, 0).unwrap_or_default();
                    let tb = chrono::DateTime::from_timestamp(b.connection.timestamp as i64, 0).unwrap_or_default();
                    ta.cmp(&tb)
                }
                SortField::Proto => format!("{:?}", a.connection.protocol).cmp(&format!("{:?}", b.connection.protocol)),
                SortField::Source => format!("{}:{}", a.connection.src_ip, a.connection.src_port).cmp(
                    &format!("{}:{}", b.connection.src_ip, b.connection.src_port)),
                SortField::Destination => format!("{}:{}", a.connection.dst_ip, a.connection.dst_port).cmp(
                    &format!("{}:{}", b.connection.dst_ip, b.connection.dst_port)),
                SortField::Score => a.connection.threat_score.cmp(&b.connection.threat_score),
                _ => std::cmp::Ordering::Equal,
            };
            match self.conn_sort_dir {
                SortDir::Asc => ordering,
                SortDir::Desc => ordering.reverse(),
            }
        });

        egui::ScrollArea::both()
            .id_source("connections_scrollarea")
            .show(ui, |ui| {
            ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Extend);

            // Sortable header row — click to toggle sort
            ui.horizontal(|ui| {
                ui.add_space(2.0);

                // Sel column
                if ui.small_button("conn_sel_btn").clicked() {
                    // No sort for selection column
                }
                ui.add_space(8.0);

                // Time
                if self.conn_sort_field == SortField::Time {
                    ui.label(egui::RichText::new(format!("Time {}", self.conn_sort_dir.icon())).color(ORANGE).strong());
                } else if ui.small_button("Time").clicked() {
                    if self.conn_sort_field == SortField::Time {
                        self.conn_sort_dir = match self.conn_sort_dir {
                            SortDir::Asc => SortDir::Desc,
                            SortDir::Desc => SortDir::Asc,
                        };
                    } else {
                        self.conn_sort_field = SortField::Time;
                        self.conn_sort_dir = SortDir::Asc;
                    }
                }
                ui.add_space(8.0);

                // PID
                if self.conn_sort_field == SortField::Pid {
                    ui.label(egui::RichText::new(format!("PID {}", self.conn_sort_dir.icon())).color(ORANGE).strong());
                } else if ui.small_button("PID").clicked() {
                    if self.conn_sort_field == SortField::Pid {
                        self.conn_sort_dir = match self.conn_sort_dir {
                            SortDir::Asc => SortDir::Desc,
                            SortDir::Desc => SortDir::Asc,
                        };
                    } else {
                        self.conn_sort_field = SortField::Pid;
                        self.conn_sort_dir = SortDir::Asc;
                    }
                }
                ui.add_space(16.0);

                // Process
                if self.conn_sort_field == SortField::Process {
                    ui.label(egui::RichText::new(format!("Process {}", self.conn_sort_dir.icon())).color(ORANGE).strong());
                } else if ui.small_button("Process").clicked() {
                    if self.conn_sort_field == SortField::Process {
                        self.conn_sort_dir = match self.conn_sort_dir {
                            SortDir::Asc => SortDir::Desc,
                            SortDir::Desc => SortDir::Asc,
                        };
                    } else {
                        self.conn_sort_field = SortField::Process;
                        self.conn_sort_dir = SortDir::Asc;
                    }
                }
                ui.add_space(16.0);

                // Proto
                if self.conn_sort_field == SortField::Proto {
                    ui.label(egui::RichText::new(format!("Proto {}", self.conn_sort_dir.icon())).color(ORANGE).strong());
                } else if ui.small_button("Proto").clicked() {
                    if self.conn_sort_field == SortField::Proto {
                        self.conn_sort_dir = match self.conn_sort_dir {
                            SortDir::Asc => SortDir::Desc,
                            SortDir::Desc => SortDir::Asc,
                        };
                    } else {
                        self.conn_sort_field = SortField::Proto;
                        self.conn_sort_dir = SortDir::Asc;
                    }
                }
                ui.add_space(16.0);

                // Source
                if self.conn_sort_field == SortField::Source {
                    ui.label(egui::RichText::new(format!("Source {}", self.conn_sort_dir.icon())).color(ORANGE).strong());
                } else if ui.small_button("Source").clicked() {
                    if self.conn_sort_field == SortField::Source {
                        self.conn_sort_dir = match self.conn_sort_dir {
                            SortDir::Asc => SortDir::Desc,
                            SortDir::Desc => SortDir::Asc,
                        };
                    } else {
                        self.conn_sort_field = SortField::Source;
                        self.conn_sort_dir = SortDir::Asc;
                    }
                }
                ui.add_space(16.0);

                // Destination
                if self.conn_sort_field == SortField::Destination {
                    ui.label(egui::RichText::new(format!("Destination {}", self.conn_sort_dir.icon())).color(ORANGE).strong());
                } else if ui.small_button("Destination").clicked() {
                    if self.conn_sort_field == SortField::Destination {
                        self.conn_sort_dir = match self.conn_sort_dir {
                            SortDir::Asc => SortDir::Desc,
                            SortDir::Desc => SortDir::Asc,
                        };
                    } else {
                        self.conn_sort_field = SortField::Destination;
                        self.conn_sort_dir = SortDir::Asc;
                    }
                }
                ui.add_space(16.0);

                // Threat
                if self.conn_sort_field == SortField::Score {
                    ui.label(egui::RichText::new(format!("Score {}", self.conn_sort_dir.icon())).color(ORANGE).strong());
                } else if ui.small_button("Score").clicked() {
                    if self.conn_sort_field == SortField::Score {
                        self.conn_sort_dir = match self.conn_sort_dir {
                            SortDir::Asc => SortDir::Desc,
                            SortDir::Desc => SortDir::Asc,
                        };
                    } else {
                        self.conn_sort_field = SortField::Score;
                        self.conn_sort_dir = SortDir::Asc;
                    }
                }
                ui.add_space(8.0);

                ui.label(egui::RichText::new("").color(ORANGE)); // spacer
            });
            ui.separator();

            // Data rows using horizontal layout (NOT Grid — Grid crashes with interactive widgets)
            // Wrap each row in a Frame for visual separation
            for item in &connections {
                let conn = &item.connection;
                let threat_color = item.threat_level.color();

                let src = format!("{}:{}", conn.src_ip, conn.src_port);
                let dst = format!("{}:{}", conn.dst_ip, conn.dst_port);
                let proto = format!("{:?}", conn.protocol);
                let time = chrono::DateTime::from_timestamp(conn.timestamp as i64, 0)
                    .map(|dt| dt.format("%H:%M:%S").to_string())
                    .unwrap_or_default();

                // Stable connection ID for widget IDs
                let conn_id = format!("{}:{}->{}:{}", conn.src_ip, conn.src_port, conn.dst_ip, conn.dst_port);
                let is_selected = self.selected_connection_id.as_ref() == Some(&conn_id);

                let display_name = if conn.process_name.is_empty() {
                    "unknown".to_string()
                } else {
                    conn.process_name.clone()
                };

                let bg_color = if is_selected {
                    egui::Color32::from_rgb(60, 60, 60)
                } else {
                    DARK_BG
                };

                egui::Frame::none()
                    .fill(bg_color)
                    .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(40, 40, 40)))
                    .inner_margin(4.0)
                    .show(ui, |ui| {
                        ui.push_id(&conn_id, |ui| {
                            ui.horizontal(|ui| {
                                ui.add_space(2.0);

                                // Select button — full row selection
                                let btn_text = if is_selected { "[Selected]" } else { "[Select]" };
                                if ui.small_button(btn_text).clicked() {
                                    self.selected_connection_id = Some(conn_id.clone());
                                    self.details_selected_conn = Some(conn.clone());
                                    self.details_selected_tab = Tab::Connections;
                                }
                                ui.add_space(8.0);

                                ui.label(time);
                                ui.add_space(8.0);
                                ui.label(conn.pid.to_string());
                                ui.add_space(16.0);
                                ui.label(&display_name);
                                ui.add_space(16.0);
                                ui.label(proto);
                                ui.add_space(16.0);
                                ui.label(src);
                                ui.add_space(16.0);
                                ui.label(dst);
                                ui.add_space(16.0);
                                ui.colored_label(threat_color, item.threat_level.label());
                                ui.add_space(8.0);
                                ui.colored_label(threat_color, conn.threat_score.to_string());
                            });
                        });
                    });

                ui.add_space(2.0);
            }
        });

    }

    fn render_process_tree(&mut self, ui: &mut egui::Ui) {
        // Process Tree: horizontal list of process cells with branch lines to hub
        ui.heading(egui::RichText::new("Connection Processes").color(ORANGE));
        ui.separator();

        // Root privilege warning (macOS)
        #[cfg(target_os = "macos")]
        {
            let is_root = unsafe { libc::geteuid() == 0 };
            if !is_root {
                ui.group(|ui| {
                    ui.set_min_width(ui.available_width());
                    ui.colored_label(RED, egui::RichText::new("[!] Process names require root").strong());
                    ui.label("Click the [Root: OFF] toggle in the header to request root privileges for real PIDs.");
                });
                ui.separator();
            }
        }

        ui.label(egui::RichText::new("Processes • Click cell for details").color(GRAY).size(11.0));

        // Sort toggle buttons
        ui.horizontal(|ui| {
            ui.colored_label(GRAY, "Sort by:");
            ui.add_space(4.0);

            let proc_sort_icon = match self.proc_sort_dir {
                SortDir::Asc => "▲",
                SortDir::Desc => "▼",
            };

            if ui.button(format!("Threat {}", proc_sort_icon)).clicked() {
                if self.proc_sort_field == SortField::Score {
                    self.proc_sort_dir = match self.proc_sort_dir {
                        SortDir::Asc => SortDir::Desc,
                        SortDir::Desc => SortDir::Asc,
                    };
                } else {
                    self.proc_sort_field = SortField::Score;
                    self.proc_sort_dir = SortDir::Desc;
                }
            }
            ui.add_space(4.0);

            if ui.button(format!("Name {}", proc_sort_icon)).clicked() {
                if self.proc_sort_field == SortField::Process {
                    self.proc_sort_dir = match self.proc_sort_dir {
                        SortDir::Asc => SortDir::Desc,
                        SortDir::Desc => SortDir::Asc,
                    };
                } else {
                    self.proc_sort_field = SortField::Process;
                    self.proc_sort_dir = SortDir::Asc;
                }
            }
            ui.add_space(4.0);

            if ui.button(format!("PID {}", proc_sort_icon)).clicked() {
                if self.proc_sort_field == SortField::Pid {
                    self.proc_sort_dir = match self.proc_sort_dir {
                        SortDir::Asc => SortDir::Desc,
                        SortDir::Desc => SortDir::Asc,
                    };
                } else {
                    self.proc_sort_field = SortField::Pid;
                    self.proc_sort_dir = SortDir::Asc;
                }
            }
            ui.add_space(4.0);

            if ui.button(format!("Conns {}", proc_sort_icon)).clicked() {
                if self.proc_sort_field == SortField::Connections {
                    self.proc_sort_dir = match self.proc_sort_dir {
                        SortDir::Asc => SortDir::Desc,
                        SortDir::Desc => SortDir::Asc,
                    };
                } else {
                    self.proc_sort_field = SortField::Connections;
                    self.proc_sort_dir = SortDir::Desc;
                }
            }
        });

        ui.separator();

        let terminated = self.monitor_state.terminated_pids.lock().unwrap().clone();
        let connections: Vec<crate::state::ConnectionItem> = self
            .monitor_state
            .connections
            .lock()
            .unwrap()
            .iter()
            .filter(|item| self.filter.matches(item) && !terminated.contains(&item.connection.pid))
            .cloned()
            .collect();

        if connections.is_empty() {
            ui.centered_and_justified(|ui| {
                ui.label(egui::RichText::new("No connections captured yet.").color(GRAY));
            });
            return;
        }

        // Group by process - unknown PIDs grouped together under single key
        use std::collections::HashMap;
        let mut process_map: HashMap<String, Vec<&crate::state::ConnectionItem>> = HashMap::new();
        for item in &connections {
            let key = if item.connection.pid == 0 || item.connection.process_name == "unknown" {
                "unknown:0".to_string() // All unknown PIDs grouped together
            } else {
                format!("{}:{}", item.connection.pid, item.connection.process_name)
            };
            process_map.entry(key).or_default().push(item);
        }

        let mut processes: Vec<(String, Vec<&crate::state::ConnectionItem>, u8)> = process_map
            .into_iter()
            .map(|(key, conns)| {
                let max_threat = conns.iter().map(|c| c.connection.threat_score).max().unwrap_or(0);
                (key, conns, max_threat)
            })
            .collect();

        // Sort processes
        processes.sort_by(|a, b| {
            let ordering = match self.proc_sort_field {
                SortField::Score => a.2.cmp(&b.2),
                SortField::Process => a.0.cmp(&b.0),
                SortField::Pid => {
                    let pa: u32 = a.0.split(':').next().unwrap_or(&"0").parse().unwrap_or(0);
                    let pb: u32 = b.0.split(':').next().unwrap_or(&"0").parse().unwrap_or(0);
                    pa.cmp(&pb)
                }
                SortField::Connections => a.1.len().cmp(&b.1.len()),
                _ => std::cmp::Ordering::Equal,
            };
            match self.proc_sort_dir {
                SortDir::Asc => ordering,
                SortDir::Desc => ordering.reverse(),
            }
        });

        let available = ui.available_rect_before_wrap();
        let hub_y = available.bottom() - 60.0;
        let hub_x = available.min.x + available.width() / 2.0;

        // Cell dimensions
        let cell_width = 160.0;
        let cell_height = 60.0;
        let cell_spacing = 15.0;
        let num_procs = processes.len();
        let total_width = num_procs as f32 * (cell_width + cell_spacing);
        let start_x = hub_x - total_width / 2.0;

        // Draw branch lines from hub to each process cell
        for (i, (_, _, threat_score)) in processes.iter().enumerate() {
            let cell_x = start_x + i as f32 * (cell_width + cell_spacing) + cell_width / 2.0;
            let cell_y = available.top() + cell_spacing;
            let threat_color = match *threat_score {
                0..=25 => GREEN,
                26..=49 => YELLOW,
                50..=74 => ORANGE,
                75..=89 => egui::Color32::from_rgb(255, 100, 100),
                _ => RED,
            };

            // Line from hub to cell
            ui.painter().line_segment(
                [egui::pos2(hub_x, hub_y), egui::pos2(cell_x, cell_y + cell_height / 2.0)],
                egui::Stroke::new(1.5, threat_color),
            );
            ui.painter().circle_filled(egui::pos2(cell_x, cell_y + cell_height / 2.0), 3.0, threat_color);
        }

        // Hub at bottom center
        let hub_rect = egui::Rect::from_center_size(egui::pos2(hub_x, hub_y), egui::vec2(160.0, 35.0));
        ui.painter().rect_filled(hub_rect, 6.0, egui::Color32::from_rgb(50, 50, 50));
        ui.painter().rect_stroke(hub_rect, 6.0, egui::Stroke::new(1.5, ORANGE));
        ui.painter().text(
            hub_rect.center(),
            egui::Align2::CENTER_CENTER,
            "All Connections",
            egui::FontId::new(12.0, egui::FontFamily::Proportional),
            WHITE,
        );

        // Draw process cells left-to-right
        egui::ScrollArea::horizontal()
            .id_source("process_tree_scroll")
            .show(ui, |ui| {
            ui.set_min_size(egui::vec2(total_width + cell_spacing * 2.0, cell_height + 40.0));

            for (i, (key, conns, threat_score)) in processes.iter().enumerate() {
                let cell_x = start_x + i as f32 * (cell_width + cell_spacing);
                let cell_rect = egui::Rect::from_min_size(
                    egui::pos2(cell_x, available.top() + cell_spacing),
                    egui::vec2(cell_width, cell_height),
                );

                let threat_color = match *threat_score {
                    0..=25 => GREEN,
                    26..=49 => YELLOW,
                    50..=74 => ORANGE,
                    75..=89 => egui::Color32::from_rgb(255, 100, 100),
                    _ => RED,
                };

                let pid: u32 = key.split(':').next().unwrap_or(&"0").parse().unwrap_or(0);
                let is_selected = self.selected_process == Some(pid);

                // Cell frame
                ui.painter().rect_filled(cell_rect, 5.0, egui::Color32::from_rgb(40, 40, 40));
                ui.painter().rect_stroke(cell_rect, 5.0, egui::Stroke::new(1.5, if is_selected { WHITE } else { threat_color }));

                // Cell content - painter text, no clipping
                let cx = cell_rect.center().x;
                let ty = cell_rect.top() + 8.0;

                let display_name = if pid == 0 {
                    "Unknown Process".to_string()
                } else {
                    key.split(':').nth(1).unwrap_or(&key).to_string()
                };

                ui.painter().text(
                    egui::pos2(cx, ty),
                    egui::Align2::CENTER_CENTER,
                    &display_name,
                    egui::FontId::new(10.0, egui::FontFamily::Proportional),
                    WHITE,
                );
                ui.painter().text(
                    egui::pos2(cx, ty + 16.0),
                    egui::Align2::CENTER_CENTER,
                    &format!("PID: {}", pid),
                    egui::FontId::new(9.0, egui::FontFamily::Proportional),
                    GRAY,
                );
                ui.painter().text(
                    egui::pos2(cx, ty + 30.0),
                    egui::Align2::CENTER_CENTER,
                    &format!("{} conns", conns.len()),
                    egui::FontId::new(9.0, egui::FontFamily::Proportional),
                    ORANGE,
                );
                ui.painter().text(
                    egui::pos2(cx, ty + 44.0),
                    egui::Align2::CENTER_CENTER,
                    &format!("Threat: {}", threat_score),
                    egui::FontId::new(8.0, egui::FontFamily::Proportional),
                    threat_color,
                );

                // Clickable cell (left-click selects)
                let response = ui.interact(
                    cell_rect,
                    ui.id().with(format!("pt_cell_{}", key)),
                    egui::Sense::click(),
                );
                if response.clicked() {
                    self.selected_process = Some(pid);
                    self.details_selected_pid = Some(pid);
                    self.details_selected_tab = Tab::ProcessTree;
                }
            }
        });

    }

    fn render_connection_graph(&mut self, ui: &mut egui::Ui) {
        // Cell-based graph: rounded rectangles connected by lines with pan/zoom
        ui.heading(egui::RichText::new("Connection Graph (Cell View)").color(ORANGE));
        ui.separator();

        ui.label(egui::RichText::new("Cells = processes • Lines = shared connections • Right-drag to pan • Click cell for details").color(GRAY).size(11.0));
        ui.separator();

        let terminated = self.monitor_state.terminated_pids.lock().unwrap().clone();
        let connections: Vec<crate::state::ConnectionItem> = self
            .monitor_state
            .connections
            .lock()
            .unwrap()
            .iter()
            .filter(|item| self.filter.matches(item) && !terminated.contains(&item.connection.pid))
            .cloned()
            .collect();

        if connections.is_empty() {
            ui.centered_and_justified(|ui| {
                ui.label(egui::RichText::new("No connections captured yet. Start monitoring to see connections.").color(GRAY));
            });
            return;
        }

        // Group connections by process (pid + name) to create process cells
        use std::collections::HashMap;
        let mut process_cells: HashMap<String, Vec<&crate::state::ConnectionItem>> = HashMap::new();
        for item in &connections {
            // Only show processes with real PIDs (root required for lsof)
            if item.connection.pid == 0 && item.connection.process_name == "unknown" {
                continue;
            }
            let key = format!("{}:{}", item.connection.pid, item.connection.process_name);
            process_cells.entry(key).or_default().push(item);
        }

        let mut cells: Vec<(String, Vec<&crate::state::ConnectionItem>, egui::Color32)> = process_cells
            .into_iter()
            .map(|(key, conns)| {
                let max_threat = conns.iter().map(|c| c.connection.threat_score).max().unwrap_or(0);
                let color = match max_threat {
                    0..=25 => GREEN,
                    26..=49 => YELLOW,
                    50..=74 => ORANGE,
                    75..=89 => egui::Color32::from_rgb(255, 100, 100),
                    _ => RED,
                };
                (key, conns, color)
            })
            .collect();

        // Sort cells by threat score descending
        cells.sort_by(|a, b| b.1.iter().map(|c| c.connection.threat_score).max().unwrap_or(0)
            .cmp(&a.1.iter().map(|c| c.connection.threat_score).max().unwrap_or(0))
            .then_with(|| a.0.cmp(&b.0)));

        // Layout parameters
        let cell_width = 300.0;
        let cell_height = 110.0;
        let cell_spacing = 25.0;
        let total_height = cells.len() as f32 * (cell_height + cell_spacing) + cell_spacing;

        let available = ui.available_rect_before_wrap();

        // Handle pan input - only pan when RIGHT mouse button is held down
        let mut offset = self.graph_offset;

        // Drag to pan: only when right mouse button is held
        if ui.input(|i| i.pointer.button_down(egui::PointerButton::Secondary)) {
            let drag_delta = ui.input(|i| i.pointer.delta());
            if drag_delta.length_sq() > 0.0 {
                offset += drag_delta;
                self.graph_offset = offset;
            }
        }

        // Draw cells using painter (avoids clipping issues with ui.label)
        let mut cell_rects: Vec<(egui::Rect, String)> = Vec::new();

        let mut x = cell_spacing;
        let x_offset = available.min.x + offset.x;
        let center_y = available.top() + cell_height / 2.0 + offset.y;

        for (i, (key, conns, cell_color)) in cells.iter().enumerate() {
            let cell_rect = egui::Rect::from_min_size(
                egui::pos2(x_offset + x, center_y - cell_height / 2.0),
                egui::vec2(cell_width, cell_height),
            );

            // Draw connecting line from previous cell to this cell
            if i > 0 {
                let prev_right = egui::pos2(x_offset + x - cell_spacing / 2.0, center_y);
                let this_left = egui::pos2(x_offset + x, center_y);
                ui.painter().line_segment(
                    [prev_right, this_left],
                    egui::Stroke::new(2.0, GRAY),
                );
            }

            // Cell frame
            let is_selected = self.details_selected_node == Some(key.clone());
            let stroke_color = if is_selected { WHITE } else { *cell_color };

            ui.painter().rect_filled(
                cell_rect,
                8.0,
                egui::Color32::from_rgb(40, 40, 40),
            );
            ui.painter().rect_stroke(
                cell_rect,
                8.0,
                egui::Stroke::new(2.0, stroke_color),
            );

            // Draw text using painter (no clipping issues)
            let cell_pid: u32 = key.split(':').next().unwrap_or(&"0").parse().unwrap_or(0);
            let display_name = if cell_pid == 0 {
                "Unknown Process".to_string()
            } else {
                key.split(':').nth(1).unwrap_or(&key).to_string()
            };

            // Name (vertical center)
            ui.painter().text(
                egui::pos2(x_offset + x + cell_width / 2.0, center_y - 10.0),
                egui::Align2::CENTER_CENTER,
                &display_name,
                egui::FontId::new(13.0, egui::FontFamily::Proportional),
                WHITE,
            );
            // PID
            ui.painter().text(
                egui::pos2(x_offset + x + cell_width / 2.0, center_y + 6.0),
                egui::Align2::CENTER_CENTER,
                &format!("PID: {}", cell_pid),
                egui::FontId::new(10.0, egui::FontFamily::Proportional),
                GRAY,
            );
            // Connections count
            ui.painter().text(
                egui::pos2(x_offset + x + cell_width / 2.0, center_y + 22.0),
                egui::Align2::CENTER_CENTER,
                &format!("Connections: {}", conns.len()),
                egui::FontId::new(11.0, egui::FontFamily::Proportional),
                ORANGE,
            );
            // Max threat
            ui.painter().text(
                egui::pos2(x_offset + x + cell_width / 2.0, center_y + 38.0),
                egui::Align2::CENTER_CENTER,
                &format!("Max Threat: {}", conns.iter().map(|c| c.connection.threat_score).max().unwrap_or(0)),
                egui::FontId::new(10.0, egui::FontFamily::Proportional),
                *cell_color,
            );

            cell_rects.push((cell_rect, key.clone()));

            x += cell_width + cell_spacing;
        }

        // Clickable overlays for each cell
        for (cell_rect, cell_key) in cell_rects.iter() {
            let widget_id = format!("cg_cell_{}", cell_key);
            let response = ui.interact(
                *cell_rect,
                ui.id().with(widget_id),
                egui::Sense::click(),
            );
            if response.clicked() {
                self.details_selected_node = Some(cell_key.clone());
                self.details_selected_tab = Tab::ConnectionGraph;
                // Find the first connection for this cell's process
                if let Some(item) = connections.iter().find(|item| {
                    let c = &item.connection;
                    let k = format!("{}:{}", c.pid, c.process_name);
                    k == *cell_key
                }) {
                    self.details_selected_conn = Some(item.connection.clone());
                }
            }
        }

        // Set minimum scrollable size
        ui.set_min_size(egui::vec2(x, available.height()));
    }

    fn render_devices(&mut self, ui: &mut egui::Ui) {
        ui.heading(egui::RichText::new("Connected Devices").color(ORANGE));
        ui.separator();

        ui.label(egui::RichText::new("USB, Bluetooth, and other connected devices").color(GRAY).size(11.0));
        ui.separator();

        // Enumerate devices
        let devices = self.monitor_state.connected_devices.lock().unwrap().clone();

        if devices.is_empty() {
            ui.label(egui::RichText::new("No devices detected.").color(GRAY));
            ui.label(egui::RichText::new("Note: Device enumeration requires root privileges on macOS.").color(GRAY).size(10.0));
        } else {
            ui.label(egui::RichText::new(format!("{} device(s) found", devices.len())).color(WHITE));
            ui.separator();

            for device in devices {
                let type_color = match device.device_type {
                    DeviceType::Usb => ORANGE,
                    DeviceType::Bluetooth => GREEN,
                    DeviceType::Thunderbolt => YELLOW,
                    _ => GRAY,
                };

                ui.group(|ui| {
                    ui.horizontal(|ui| {
                        ui.colored_label(type_color, egui::RichText::new(format!("{:?}", device.device_type)).strong());
                        ui.add_space(8.0);
                        ui.label(egui::RichText::new(&device.name).strong());
                    });
                    ui.add_space(4.0);
                    ui.label(egui::RichText::new(format!("ID: {}", device.id)).color(GRAY).size(10.0));
                    ui.add_space(8.0);
                    if let Some(vendor) = &device.vendor {
                        ui.label(egui::RichText::new(format!("Vendor: {}", vendor)).color(GRAY).size(10.0));
                    }
                    ui.add_space(8.0);
                    if let Some(pid) = &device.product_id {
                        ui.label(egui::RichText::new(format!("PID: {}", pid)).color(GRAY).size(10.0));
                    }
                    ui.add_space(8.0);
                    let status_color = if device.is_connected { GREEN } else { RED };
                    ui.colored_label(status_color, if device.is_connected { "Connected" } else { "Disconnected" });
                });
                ui.separator();
            }
        }

        ui.separator();
        if ui.button("Refresh Device List").clicked() {
            // TODO: trigger device re-enumeration
        }
    }
    fn render_alerts(&mut self, ui: &mut egui::Ui) {
        crate::ui::render_alerts(ui, &*self.monitor_state);
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
            crate::ui::detail_row(ui, "Process", &proc.name);
            crate::ui::detail_row(ui, "PID", &proc.pid.to_string());
            if let Some(path) = &proc.path {
                crate::ui::detail_row(ui, "Path", path);
            }
            if let Some(user) = &proc.user {
                crate::ui::detail_row(ui, "User", user);
            }
            crate::ui::detail_row(ui, "Connections", &proc.connections.len().to_string());
            crate::ui::detail_row(ui, "Max Threat Score", &proc.total_threat_score.to_string());
            crate::ui::detail_row(ui, "Status", if proc.is_suspicious { "SUSPICIOUS" } else { "OK" });
        });

        ui.separator();

        // Actions
        ui.horizontal(|ui| {
            if ui.button("[Terminate]").clicked() {
                crate::ui::terminate_process(proc.pid, &proc.name, &self.monitor_state);
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
            ui.add_space(8.0);
        });
    }

    fn render_graph_node_detail(&mut self, ui: &mut egui::Ui, node: &crate::graph::GraphNode) {
        ui.heading(egui::RichText::new(&node.label).color(node.color).strong());
        ui.separator();

        egui::Grid::new("node_detail").num_columns(2).show(ui, |ui| {
            crate::ui::detail_row(ui, "Type", if node.is_process { "Process" } else { "Remote Host" });
            if let Some(pid) = node.pid {
                crate::ui::detail_row(ui, "PID", &pid.to_string());
            }
            crate::ui::detail_row(ui, "Process", &node.process_name);
            if let Some(iface) = &node.interface {
                crate::ui::detail_row(ui, "Interface", iface);
            }
            if let Some(ip) = &node.remote_ip {
                crate::ui::detail_row(ui, "Remote IP", ip);
            }
            if let Some(port) = node.remote_port {
                crate::ui::detail_row(ui, "Remote Port", &port.to_string());
            }
            crate::ui::detail_row(ui, "Connections", &node.connections.to_string());
            crate::ui::detail_row(ui, "Threat Score", &node.threat_score.to_string());
        });

        ui.separator();

        // Actions
        ui.horizontal(|ui| {
            if node.is_process {
                if let Some(pid) = node.pid {
                    if ui.button("[Terminate]").clicked() {
                        crate::ui::terminate_process(pid, &node.process_name, &self.monitor_state);
                    }
                    if ui.button("[Block All Ports]").clicked() {
                        // TODO
                    }
                    if ui.button("[Copy PID]").clicked() {
                        ui.output_mut(|o| o.copied_text = pid.to_string());
                    }
                    if ui.button("[Copy Name]").clicked() {
                        ui.output_mut(|o| o.copied_text = node.process_name.clone());
                    }
                }
            } else {
                if let Some(ip) = &node.remote_ip {
                    if ui.button("[Block IP]").clicked() {
                        crate::ui::block_ip(ip, node.pid.unwrap_or(0), &node.label, &self.monitor_state);
                    }
                }
                if let Some(port) = node.remote_port {
                    if ui.button("[Block Port]").clicked() {
                        crate::ui::block_port(port, node.pid.unwrap_or(0), &node.label, &self.monitor_state);
                    }
                }
                if ui.button("[Copy IP:Port]").clicked() {
                    ui.output_mut(|o| o.copied_text = node.label.clone());
                }
            }
            if ui.button("[Focus on Graph]").clicked() {
                self.selected_graph_node = Some(node.id.clone());
            }
        });
    }

    fn render_audit(&mut self, ui: &mut egui::Ui) {
        ui.heading(egui::RichText::new("Security Audit").color(ORANGE));
        ui.separator();

        ui.label(egui::RichText::new("Static security auditing with CVE enrichment").color(GRAY).size(11.0));
        ui.separator();

        // Copy all needed values from audit_state (release lock before egui closures)
        let (is_scanning, scan_complete, compliance_cis, compliance_nist, compliance_pci_dss, enable_nvd, audit_results, findings_count, suspicious_count, critical_count) = {
            let state = self.monitor_state.audit_state.lock().unwrap();
            (
                state.is_scanning,
                state.scan_complete,
                state.compliance_cis,
                state.compliance_nist,
                state.compliance_pci_dss,
                state.enable_nvd,
                state.audit_results.clone(),
                state.findings_count,
                state.suspicious_count,
                state.critical_count,
            )
        };

        // Scan buttons with running state
        let scan_btn_text = if is_scanning {
            "[ Scanning... ]"
        } else {
            "[ Run Full Audit ]"
        };

        ui.group(|ui| {
            ui.heading(egui::RichText::new("Audit Configuration").color(ORANGE));
            ui.separator();

            if ui.button(scan_btn_text).clicked() && !is_scanning {
                // Re-lock to mutate
                let mut state = self.monitor_state.audit_state.lock().unwrap();
                state.is_scanning = true;
                state.scan_complete = false;
                state.audit_results = "Scan in progress...".to_string();
                state.findings_count = 0;
                state.suspicious_count = 0;
                state.critical_count = 0;

                // Capture settings before releasing lock
                let compliance_cis = state.compliance_cis;
                let compliance_nist = state.compliance_nist;
                let compliance_pci_dss = state.compliance_pci_dss;
                let enable_nvd = state.enable_nvd;
                drop(state);

                // Trigger actual audit scan using the audit engine
                let monitor_state_clone = self.monitor_state.clone();

                tokio::task::spawn_blocking(move || {
                    use nodesec_core::audit::AuditEngine;

                    // Build standards filter
                    let mut standards: Vec<String> = Vec::new();
                    if compliance_cis { standards.push("CIS".to_string()); }
                    if compliance_nist { standards.push("NIST".to_string()); }
                    if compliance_pci_dss { standards.push("PCI-DSS".to_string()); }
                    let standards_filter = if standards.is_empty() { None } else { Some(standards) };

                    match AuditEngine::new(standards_filter, None) {
                        Ok(engine) => {
                            let output_dir = std::path::Path::new("artifacts");
                            let _ = std::fs::create_dir_all(output_dir);
                            match engine.run_audit(
                                None,                              // target_platform (auto-detect)
                                enable_nvd,                        // include_cves
                                50,                                // cve_limit
                                true,                              // generate_remediation
                                true,                              // scan_apps
                                100,                               // app_limit
                                true,                              // save_to_desktop
                                output_dir,                        // output_dir
                                false,                             // collect_logs
                                0,                                 // log_hours
                                false,                             // scan_ad
                            ) {
                                Ok(report) => {
                                    let rt = tokio::runtime::Runtime::new().unwrap();
                                    rt.block_on(async {
                                        let mut state = monitor_state_clone.audit_state.lock().unwrap();
                                        state.is_scanning = false;
                                        state.scan_complete = true;
                                        state.last_scan_time = Some(chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string());
                                        state.findings_count = report.summary.failed;
                                        state.suspicious_count = report.summary.failed;
                                        state.critical_count = report.summary.failed;
                                        state.audit_results = format!("Audit completed. {} passed, {} failed, {} skipped.",
                                            report.summary.passed, report.summary.failed, report.summary.skipped);
                                    });
                                }
                                Err(e) => {
                                    let rt = tokio::runtime::Runtime::new().unwrap();
                                    rt.block_on(async {
                                        let mut state = monitor_state_clone.audit_state.lock().unwrap();
                                        state.is_scanning = false;
                                        state.scan_complete = true;
                                        state.audit_results = format!("Audit failed: {}", e);
                                    });
                                }
                            }
                        }
                        Err(e) => {
                            let rt = tokio::runtime::Runtime::new().unwrap();
                            rt.block_on(async {
                                let mut state = monitor_state_clone.audit_state.lock().unwrap();
                                state.is_scanning = false;
                                state.scan_complete = true;
                                state.audit_results = format!("Audit engine failed: {}", e);
                            });
                        }
                    }
                });
            }
            ui.add_space(8.0);

            if ui.button("[ Scan Applications ]").clicked() {
                // TODO
            }
            ui.add_space(8.0);
            if ui.button("[ Scan AD Security ]").clicked() {
                // TODO
            }
        });

        ui.separator();
        ui.label(egui::RichText::new("Compliance Standards:").color(ORANGE).strong());
        ui.horizontal(|ui| {
            let mut cis_checked = compliance_cis;
            if ui.checkbox(&mut cis_checked, "CIS").changed() {
                let mut state = self.monitor_state.audit_state.lock().unwrap();
                state.compliance_cis = cis_checked;
            }
            ui.add_space(8.0);
            let mut nist_checked = compliance_nist;
            if ui.checkbox(&mut nist_checked, "NIST").changed() {
                let mut state = self.monitor_state.audit_state.lock().unwrap();
                state.compliance_nist = nist_checked;
            }
            ui.add_space(8.0);
            let mut pci_checked = compliance_pci_dss;
            if ui.checkbox(&mut pci_checked, "PCI-DSS").changed() {
                let mut state = self.monitor_state.audit_state.lock().unwrap();
                state.compliance_pci_dss = pci_checked;
            }
        });

        ui.separator();
        ui.label(egui::RichText::new("NVD CVE Enrichment:").color(ORANGE).strong());
        ui.horizontal(|ui| {
            let mut nvd_checked = enable_nvd;
            if ui.checkbox(&mut nvd_checked, "Enable NVD lookups").changed() {
                let mut state = self.monitor_state.audit_state.lock().unwrap();
                state.enable_nvd = nvd_checked;
            }
            ui.label(egui::RichText::new("(requires internet access)").color(GRAY).size(10.0));
        });

        // Scan status indicator
        if is_scanning {
            ui.separator();
            ui.group(|ui| {
                ui.heading(egui::RichText::new("Scan Status: RUNNING").color(ORANGE));
                ui.label("Security audit in progress... This may take several minutes.");
                ui.add_space(4.0);
                let t = Instant::now().elapsed().as_secs_f32();
                let phase = (t * 5.0).sin() * 0.5 + 0.5;
                ui.painter().rect_filled(
                    egui::Rect::from_center_size(egui::pos2(100.0, ui.cursor().top() + 10.0), egui::vec2(40.0, 8.0)),
                    4.0,
                    egui::Color32::from_rgb(0, 200 * phase as u8, 255 * (1.0 - phase) as u8),
                );
            });
        }

        if scan_complete && !is_scanning {
            ui.separator();
            ui.group(|ui| {
                ui.heading(egui::RichText::new("Scan Complete").color(GREEN));
                ui.horizontal(|ui| {
                    ui.label(format!("Findings: {}", findings_count));
                    ui.add_space(16.0);
                    ui.colored_label(RED, format!("Suspicious: {}", suspicious_count));
                    ui.add_space(16.0);
                    ui.colored_label(RED, format!("Critical: {}", critical_count));
                });
                ui.separator();
                ui.label(egui::RichText::new(&audit_results).color(WHITE).size(11.0));
            });
        }

        if !is_scanning && !scan_complete {
            ui.separator();
            ui.label(egui::RichText::new("Last Audit Results: No audit has been run yet.").color(GRAY));
        }
    }

    fn render_reports(&mut self, ui: &mut egui::Ui) {
        ui.heading(egui::RichText::new("Reports").color(ORANGE));
        ui.separator();

        ui.label(egui::RichText::new("View, export, and manage security reports").color(GRAY).size(11.0));
        ui.separator();

        ui.group(|ui| {
            ui.heading(egui::RichText::new("Report Management").color(ORANGE));
            ui.separator();

            ui.horizontal(|ui| {
                ui.button("List Reports").clicked();
                ui.add_space(8.0);
                ui.button("Export Report").clicked();
                ui.add_space(8.0);
                ui.button("Delete Report").clicked();
            });

            ui.separator();
            ui.label(egui::RichText::new("Recent Reports:").color(ORANGE).strong());

            // List reports from artifacts directory
            let artifacts_dir = std::path::Path::new("artifacts");
            let mut reports: Vec<std::path::PathBuf> = Vec::new();
            if artifacts_dir.exists() {
                if let Ok(entries) = std::fs::read_dir(artifacts_dir) {
                    for entry in entries.flatten() {
                        let path = entry.path();
                        if path.is_dir() && path.file_name().and_then(|n| n.to_str()).unwrap_or("").starts_with("nodesec-") {
                            reports.push(path);
                        }
                    }
                    reports.sort_by(|a, b| b.cmp(a)); // newest first
                }
            }

            if reports.is_empty() {
                // Also check Desktop/Hyntel Reports and Desktop/nodesec Reports
                if let Ok(home) = std::env::var("HOME") {
                    let desktop_dir = std::path::Path::new(&home).join("Desktop");
                    for report_dir_name in ["Hyntel Reports", "nodesec Reports"] {
                        let desktop_reports = desktop_dir.join(report_dir_name);
                        if desktop_reports.exists() {
                            if let Ok(entries) = std::fs::read_dir(desktop_reports) {
                                for entry in entries.flatten() {
                                    let path = entry.path();
                                    // Accept any item inside the Reports folder
                                    reports.push(path);
                                }
                            }
                        }
                    }
                }
                reports.sort_by(|a, b| b.cmp(a));
            }

            egui::ScrollArea::vertical().max_height(200.0).show(ui, |ui| {
                egui::Grid::new("reports_grid").num_columns(4).striped(true).show(ui, |ui| {
                    ui.label(egui::RichText::new("Report").color(ORANGE).strong());
                    ui.label(egui::RichText::new("Platform").color(ORANGE).strong());
                    ui.label(egui::RichText::new("Date").color(ORANGE).strong());
                    ui.label(egui::RichText::new("Format").color(ORANGE).strong());
                    ui.end_row();

                    if reports.is_empty() {
                        ui.label(egui::RichText::new("No reports found. Run an audit to generate reports.").color(GRAY));
                    } else {
                        for report_path in reports.iter().take(10) {
                            let dir_name = report_path.file_name().unwrap_or_default().to_string_lossy().to_string();
                            // Try to parse nodesec-platform-date format, otherwise show raw name
                            let parts: Vec<&str> = dir_name.splitn(3, '-').collect();
                            let platform = if parts.len() >= 2 { parts[1] } else { "unknown" };
                            let date_part = parts.get(2).unwrap_or(&"").to_string();
                            ui.label(&dir_name);
                            ui.label(platform);
                            ui.label(&date_part);
                            ui.label("TXT/JSON/CSV");
                            ui.end_row();
                        }
                    }
                });
            });
        });

        ui.separator();
        ui.heading(egui::RichText::new("Report Formats:").color(ORANGE).strong());
        ui.horizontal(|ui| {
            if ui.button("TXT").clicked() {}
            ui.add_space(8.0);
            if ui.button("JSON").clicked() {}
            ui.add_space(8.0);
            if ui.button("CSV").clicked() {}
        });
    }

    fn render_dashboard_summary(&mut self, ui: &mut egui::Ui) {
        let stats = self.monitor_state.stats.lock().unwrap();
        let connections = self.monitor_state.connections.lock().unwrap();

        // Top stat cards row
        ui.horizontal(|ui| {
            crate::ui::stat_card(ui, "Total Scanned", &stats.total.to_string(), WHITE);
            crate::ui::stat_card(ui, "Active Now", &connections.len().to_string(), GREEN);
            crate::ui::stat_card(ui, "Suspicious", &stats.suspicious.to_string(), RED);
            crate::ui::stat_card(ui, "Critical", &stats.critical.to_string(), RED);
        });

        ui.separator();

        // Monitoring status
        let monitoring = *self.monitor_state.monitoring.lock().unwrap();
        let status_text = if monitoring { "LIVE MONITORING" } else { "MONITORING STOPPED" };
        let status_color = if monitoring { GREEN } else { YELLOW };
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("Status: ").color(GRAY).strong());
            ui.colored_label(status_color, egui::RichText::new(status_text).strong());
        });

        ui.separator();

        // Recent activity
        ui.label(egui::RichText::new("Recent Activity:").color(ORANGE).strong());
        if connections.is_empty() {
            ui.label(egui::RichText::new("No connections captured yet.").color(GRAY));
        } else {
            let recent: Vec<_> = connections.iter().rev().take(5).collect();
            for item in recent {
                let conn = &item.connection;
                let threat_color = item.threat_level.color();
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new(format!("{}:{} → {}:{}", conn.src_ip, conn.src_port, conn.dst_ip, conn.dst_port)).size(10.0));
                    ui.add_space(16.0);
                    ui.label(egui::RichText::new(&conn.process_name).size(10.0));
                    ui.add_space(16.0);
                    ui.colored_label(threat_color, item.threat_level.label());
                });
            }
        }

        ui.separator();

        // Connection types breakdown
        use std::collections::HashMap;
        let mut type_counts: HashMap<String, usize> = HashMap::new();
        for item in connections.iter() {
            let proto = format!("{:?}", item.connection.protocol);
            *type_counts.entry(proto).or_insert(0) += 1;
        }

        if !type_counts.is_empty() {
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

    fn render_details_pane(&mut self, ui: &mut egui::Ui) {
        ui.heading(egui::RichText::new("Details").color(ORANGE).strong());
        ui.separator();

        match self.details_selected_tab {
            Tab::Connections => {
                if let Some(ref conn) = self.details_selected_conn {
                    let item = crate::state::ConnectionItem {
                        connection: conn.clone(),
                        threat_level: crate::state::ThreatLevel::from_score(conn.threat_score),
                    };
                    crate::ui::render_connection_detail_topdown(ui, &item, &self.monitor_state);
                } else {
                    ui.centered_and_justified(|ui| {
                        ui.label(egui::RichText::new("Select a connection to view details").color(GRAY));
                    });
                }
            }
            Tab::ProcessTree => {
                if let Some(pid) = self.details_selected_pid {
                    let proc = {
                        let connections = self.monitor_state.connections.lock().unwrap();
                        let processes = crate::state::ProcessTreeItem::from_connections(&connections);
                        processes.iter().find(|p| p.pid == pid).cloned()
                    };
                    if let Some(proc) = proc {
                        self.render_process_detail(ui, &proc);
                    } else {
                        ui.centered_and_justified(|ui| {
                            ui.label(egui::RichText::new("Select a process to view details").color(GRAY));
                        });
                    }
                } else {
                    ui.centered_and_justified(|ui| {
                        ui.label(egui::RichText::new("Select a process to view details").color(GRAY));
                    });
                }
            }
            Tab::ConnectionGraph => {
                if let Some(ref conn) = self.details_selected_conn {
                    let item = crate::state::ConnectionItem {
                        connection: conn.clone(),
                        threat_level: crate::state::ThreatLevel::from_score(conn.threat_score),
                    };
                    crate::ui::render_connection_detail_topdown(ui, &item, &self.monitor_state);
                } else {
                    ui.centered_and_justified(|ui| {
                        ui.label(egui::RichText::new("Click [View] on a connection to see details").color(GRAY));
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
                let status = if monitoring { "LIVE" } else { "STOPPED" };
                let status_color = if monitoring { GREEN } else { YELLOW };
                ui.label(egui::RichText::new(status).color(status_color).size(16.0).strong());

                ui.separator();

                ui.label(egui::RichText::new(format!("Platform: {:?}", self.monitor_state.platform)).color(GRAY).size(13.0));

                let stats = self.monitor_state.stats.lock().unwrap();
                ui.label(egui::RichText::new(format!("Connections: {}", stats.total)).color(GRAY).size(13.0));
                ui.label(egui::RichText::new(format!("Suspicious: {}", stats.suspicious)).color(RED).size(13.0));

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.add_space(20.0);
                    let details_text = if self.show_details_pane {
                        "[Hide Details]"
                    } else {
                        "[Show Details]"
                    };
                    if ui.button(details_text).clicked() {
                        self.show_details_pane = !self.show_details_pane;
                    }
                    ui.add_space(8.0);

                    // Root privilege toggle button (macOS only)
                    #[cfg(target_os = "macos")]
                    {
                        let is_root = unsafe { libc::geteuid() == 0 };
                        let mut root_status = self.monitor_state.root_status.lock().unwrap();
                        
                        // Update status based on current state
                        if *root_status == RootStatus::Unknown {
                            *root_status = if is_root { RootStatus::On } else { RootStatus::Off };
                        }
                        
                        let (root_text, root_color) = match *root_status {
                            RootStatus::On => ("[Root: ON]".to_string(), GREEN),
                            RootStatus::Off => ("[Root: OFF]".to_string(), RED),
                            RootStatus::Requesting => ("[Requesting Root...]".to_string(), ORANGE),
                            RootStatus::Unknown => ("[Root: ?]".to_string(), GRAY),
                        };
                        
                        drop(root_status);
                        
                        let btn = egui::Button::new(egui::RichText::new(&root_text).color(root_color).strong());
                        if ui.add(btn).clicked() {
                            if is_root {
                                // Already root
                                let mut rs = self.monitor_state.root_status.lock().unwrap();
                                *rs = RootStatus::On;
                            } else {
                                // Request root
                                let mut rs = self.monitor_state.root_status.lock().unwrap();
                                *rs = RootStatus::Requesting;
                                drop(rs);
                                ensure_root_privileges();
                            }
                        }
                    }
                    ui.add_space(8.0);
                    if ui.button("Quit").clicked() {
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                });
            });
        });

        // Tab bar - accessible tabs with clear positions
        egui::TopBottomPanel::top("tabs").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.add_space(10.0);
                for tab in [
                    Tab::Dashboard, Tab::Connections, Tab::ProcessTree,
                    Tab::ConnectionGraph, Tab::Alerts, Tab::Statistics,
                    Tab::Audit, Tab::Reports, Tab::Devices, Tab::Settings
                ] {
                    let selected = self.selected_tab == tab;
                    if ui.selectable_label(selected, tab.label()).clicked() {
                        self.selected_tab = tab;
                    }
                    ui.add_space(8.0);
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

        // Details pane on right side - resizable, shows details top-to-bottom per tab
        if self.show_details_pane {
            egui::SidePanel::right("details_pane")
                .min_width(280.0)
                .max_width(500.0)
                .resizable(true)
                .show(ctx, |ui| {
                    self.render_details_pane(ui);
                });
        }

        // Main content area
        egui::CentralPanel::default().show(ctx, |ui| {
            match self.selected_tab {
                Tab::Dashboard => self.render_dashboard(ui),
                Tab::Connections => self.render_connections(ui),
                Tab::ProcessTree => self.render_process_tree(ui),
                Tab::ConnectionGraph => self.render_connection_graph(ui),
                Tab::Alerts => self.render_alerts(ui),
                Tab::Statistics => self.render_statistics(ui),
                Tab::Audit => self.render_audit(ui),
                Tab::Reports => self.render_reports(ui),
                Tab::Devices => self.render_devices(ui),
                Tab::Settings => self.render_settings(ui),
            }
        });
    }
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

        // Enumerate connected devices on startup
        {
            let devices = enumerate_all_devices_platform();
            let mut devices_lock = monitor_state.connected_devices.lock().unwrap();
            *devices_lock = devices;
        }

        let app = App {
            selected_tab: Tab::Dashboard,
            monitor_state,
            last_update: Instant::now(),
            monitoring: false,
            connection_history: Arc::new(Mutex::new(VecDeque::with_capacity(300))),
            threat_history: Arc::new(Mutex::new(VecDeque::with_capacity(300))),
            selected_connection_id: None,
            selected_process: None,
            selected_graph_node: None,
            graph: ConnectionGraph::new(monitor_state_for_graph),
            filter: FilterSettings::default(),
            details_selected_tab: Tab::Dashboard,
            details_selected_conn: None,
            details_selected_pid: None,
            details_selected_node: None,
            show_details_pane: true,
            conn_sort_field: SortField::Time,
            conn_sort_dir: SortDir::Desc,
            proc_sort_field: SortField::Process,
            proc_sort_dir: SortDir::Asc,
    
    
            graph_offset: egui::Vec2::ZERO,
            graph_zoom: 1.0,
        };

        eframe::run_native(
            "Nodesec Network Monitor",
            options,
            Box::new(|cc| {
                // Configure fonts to support Unicode/emoji characters
                let mut fonts = egui::FontDefinitions::default();

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

/// On macOS, re-launch the application with root privileges using osascript password dialog.
/// lsof requires root to see other processes' network connections.
#[cfg(target_os = "macos")]
fn ensure_root_privileges() {
    use std::process::Command;

    // Check if already root (euid == 0)
    let is_root = unsafe { libc::geteuid() == 0 };

    if is_root {
        return;
    }

    // Get the current executable path
    let exe_path = match std::env::current_exe() {
        Ok(p) => p,
        Err(_) => return,
    };

    let exe_str = exe_path.to_string_lossy();

    // Use osascript to show a password dialog and re-launch with sudo
    let applescript = format!(
        "do shell script \"sudo '{}'\" with administrator privileges",
        exe_str
    );

    let _ = Command::new("osascript")
        .args(["-e", &applescript])
        .spawn();

    // Exit the current (non-root) instance
    std::process::exit(0);
}

/// Attempt to resolve process info for a connection using multiple fallback methods.
/// This runs on every platform and tries lsof (macOS/Linux), ss (Linux), /proc (Linux).
pub async fn resolve_process_info(
    src_ip: &std::net::IpAddr,
    src_port: u16,
) -> (u32, String, Option<String>, Option<String>, Option<String>) {
    // Try lsof first
    if let Ok(output) = tokio::process::Command::new("lsof")
        .args(["-nP", "-i", &format!("{}@{}:{}", if matches!(src_ip, std::net::IpAddr::V4(_)) { "4" } else { "6" }, src_ip, src_port)])
        .output()
        .await
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 9 {
                if let Ok(pid) = parts[1].parse::<u32>() {
                    let name = parts[0].to_string();
                    let user = parts[2].to_string();
                    let (path, cmd) = get_process_details_sync(pid);
                    return (pid, name, path, cmd, Some(user));
                }
            }
        }
    }

    // Fallback: return unknown
    (0, "unknown".to_string(), None, None, None)
}

fn get_process_details_sync(pid: u32) -> (Option<String>, Option<String>) {
    let output = match std::process::Command::new("ps")
        .args(["-p", &pid.to_string(), "-o", "args="])
        .output()
    {
        Ok(o) => o,
        Err(_) => return (None, None),
    };
    let args_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if args_str.is_empty() {
        return (None, None);
    }
    let exe = args_str.split_whitespace().next().unwrap_or("").to_string();
    (Some(exe.clone()), Some(args_str))
}

#[cfg(not(target_os = "macos"))]
fn ensure_root_privileges() {}

/// Platform-specific device enumeration (USB + Bluetooth)
fn enumerate_all_devices_platform() -> Vec<nodesec_core::models::ConnectedDevice> {
    #[cfg(target_os = "macos")]
    {
        let mut devices = Vec::new();

        // USB devices using system_profiler with recursive hub traversal
        if let Ok(output) = std::process::Command::new("system_profiler").args(["SPUSBDataType", "-json"]).output() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
                if let Some(items) = json.get("SPUSBDataType").and_then(|v| v.as_array()) {
                    for item in items {
                        extract_usb_from_json_recursive(&item, &mut devices);
                    }
                }
            }
        }

        // Fallback to ioreg if system_profiler returns empty
        // ioreg outputs XML plist format; convert to JSON with plutil for parsing
        if devices.is_empty() {
            if let Ok(ioreg_output) = std::process::Command::new("ioreg")
                .args(["-r", "-c", "IOUSBDevice", "-a"])
                .output()
            {
                let temp_path = std::env::temp_dir().join("nodesec_ioreg.plist");
                if std::fs::write(&temp_path, &ioreg_output.stdout).is_ok() {
                    if let Ok(plutil_output) = std::process::Command::new("plutil")
                        .args(["-convert", "json", "-o", "-", temp_path.to_str().unwrap_or("")])
                        .output()
                    {
                        if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&plutil_output.stdout) {
                            if let Some(items) = json.as_array() {
                                for item in items {
                                    let name = item.get("_name")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("Unknown USB Device")
                                        .to_string();
                                    let product_id = item.get("product_id")
                                        .and_then(|v| v.as_str())
                                        .map(|s| s.to_string());
                                    let vendor_id = item.get("vendor_id")
                                        .and_then(|v| v.as_str())
                                        .map(|s| s.to_string());
                                    let serial = item.get("serial_num")
                                        .and_then(|v| v.as_str())
                                        .map(|s| s.to_string());

                                    // ioreg may use different key names; try alternatives
                                    let product_id = product_id.or_else(|| {
                                        item.get("IDProduct").and_then(|v| v.as_str()).map(|s| s.to_string())
                                    });
                                    let vendor_id = vendor_id.or_else(|| {
                                        item.get("IDVendor").and_then(|v| v.as_str()).map(|s| s.to_string())
                                    });

                                    devices.push(nodesec_core::models::ConnectedDevice {
                                        id: format!("usb:{}:{}", vendor_id.as_deref().unwrap_or("unknown"), product_id.as_deref().unwrap_or("unknown")),
                                        name,
                                        device_type: nodesec_core::models::DeviceType::Usb,
                                        vendor: None,
                                        product_id,
                                        vendor_id,
                                        serial_number: serial,
                                        connected_at: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs(),
                                        last_seen: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs(),
                                        is_connected: true,
                                    });
                                }
                            }
                        }
                    }
                    // Clean up temp file
                    let _ = std::fs::remove_file(&temp_path);
                }
            }
        }

        // Bluetooth devices using system_profiler (correct JSON structure)
        if let Ok(output) = std::process::Command::new("system_profiler").args(["SPBluetoothDataType", "-json"]).output() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
                if let Some(items) = json.get("SPBluetoothDataType").and_then(|v| v.as_array()) {
                    for item in items {
                        // Connected devices - each entry is {"Device Name": {properties}}
                        if let Some(connected_list) = item.get("device_connected").and_then(|v| v.as_array()) {
                            for dev_entry in connected_list {
                                for (dev_name, dev_props) in dev_entry.as_object().unwrap_or(&serde_json::Map::new()) {
                                    let name = dev_name.clone();
                                    let address = dev_props.get("device_address").and_then(|v| v.as_str()).map(|s| s.to_string());

                                    devices.push(nodesec_core::models::ConnectedDevice {
                                        id: format!("bt:{}", address.as_deref().unwrap_or("unknown")),
                                        name,
                                        device_type: nodesec_core::models::DeviceType::Bluetooth,
                                        vendor: None,
                                        product_id: None,
                                        vendor_id: None,
                                        serial_number: address.clone(),
                                        connected_at: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs(),
                                        last_seen: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs(),
                                        is_connected: true,
                                    });
                                }
                            }
                        }
                        // Not connected devices (for history)
                        if let Some(not_connected_list) = item.get("device_not_connected").and_then(|v| v.as_array()) {
                            for dev_entry in not_connected_list {
                                for (dev_name, dev_props) in dev_entry.as_object().unwrap_or(&serde_json::Map::new()) {
                                    let name = dev_name.clone();
                                    let address = dev_props.get("device_address").and_then(|v| v.as_str()).map(|s| s.to_string());

                                    devices.push(nodesec_core::models::ConnectedDevice {
                                        id: format!("bt:{}", address.as_deref().unwrap_or("unknown")),
                                        name,
                                        device_type: nodesec_core::models::DeviceType::Bluetooth,
                                        vendor: None,
                                        product_id: None,
                                        vendor_id: None,
                                        serial_number: address,
                                        connected_at: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs(),
                                        last_seen: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs(),
                                        is_connected: false,
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }

        return devices;
    }

    #[cfg(target_os = "linux")]
    {
        let mut devices = Vec::new();

        // USB devices via lsusb
        if let Ok(output) = std::process::Command::new("lsusb").output() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() < 6 { continue; }
                let id_field = parts.iter().find(|p| p.contains(':') && p.len() == 7 && p.chars().nth(4) == Some(':'));
                if let Some(id) = id_field {
                    let id_parts: Vec<&str> = id.split(':').collect();
                    if id_parts.len() == 2 {
                        let vendor_id = id_parts[0].to_string();
                        let product_id = id_parts[1].to_string();
                        let id_index = parts.iter().position(|p| *p == id).unwrap_or(0);
                        let name = parts[id_index + 1..].join(" ");

                        devices.push(nodesec_core::models::ConnectedDevice {
                            id: format!("usb:{}:{}", vendor_id, product_id),
                            name,
                            device_type: nodesec_core::models::DeviceType::Usb,
                            vendor: None,
                            product_id: Some(product_id),
                            vendor_id: Some(vendor_id),
                            serial_number: None,
                            connected_at: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs(),
                            last_seen: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs(),
                            is_connected: true,
                        });
                    }
                }
            }
        }

        // Bluetooth devices via bluetoothctl
        if let Ok(output) = std::process::Command::new("bluetoothctl").args(["devices"]).output() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() < 3 || parts[0] != "Device" { continue; }
                let address = parts[1].to_string();
                let name = parts[2..].join(" ");

                devices.push(nodesec_core::models::ConnectedDevice {
                    id: format!("bt:{}", address),
                    name,
                    device_type: nodesec_core::models::DeviceType::Bluetooth,
                    vendor: None,
                    product_id: None,
                    vendor_id: None,
                    serial_number: Some(address),
                    connected_at: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs(),
                    last_seen: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs(),
                    is_connected: true,
                });
            }
        }

        return devices;
    }

    #[cfg(target_os = "windows")]
    {
        let mut devices = Vec::new();

        // USB devices via PowerShell
        if let Ok(output) = std::process::Command::new("powershell")
            .args(["-Command", "Get-PnpDevice -Class USB | Select-Object Name, InstanceId, Status | ConvertTo-Json"])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if let Ok(json_array) = serde_json::from_str::<Vec<serde_json::Value>>(&stdout) {
                for item in json_array {
                    let name = item.get("Name").and_then(|v| v.as_str()).unwrap_or("Unknown USB Device").to_string();
                    let instance_id = item.get("InstanceId").and_then(|v| v.as_str()).unwrap_or("unknown").to_string();
                    let status = item.get("Status").and_then(|v| v.as_str()).unwrap_or("Unknown").to_string();
                    let vid = instance_id.split("VID_").nth(1).and_then(|s| s.split('&').next()).map(|s| s.to_string());
                    let pid = instance_id.split("PID_").nth(1).and_then(|s| s.split('\\').next()).map(|s| s.to_string());

                    devices.push(nodesec_core::models::ConnectedDevice {
                        id: format!("usb:{}", instance_id),
                        name,
                        device_type: nodesec_core::models::DeviceType::Usb,
                        vendor: None,
                        product_id: pid,
                        vendor_id: vid,
                        serial_number: None,
                        connected_at: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs(),
                        last_seen: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs(),
                        is_connected: status == "OK",
                    });
                }
            }
        }

        // Bluetooth devices via PowerShell
        if let Ok(output) = std::process::Command::new("powershell")
            .args(["-Command", "Get-PnpDevice -Class Bluetooth | Select-Object Name, InstanceId, Status | ConvertTo-Json"])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if let Ok(json_array) = serde_json::from_str::<Vec<serde_json::Value>>(&stdout) {
                for item in json_array {
                    let name = item.get("Name").and_then(|v| v.as_str()).unwrap_or("Unknown Bluetooth Device").to_string();
                    let instance_id = item.get("InstanceId").and_then(|v| v.as_str()).unwrap_or("unknown").to_string();
                    let status = item.get("Status").and_then(|v| v.as_str()).unwrap_or("Unknown").to_string();

                    devices.push(nodesec_core::models::ConnectedDevice {
                        id: format!("bt:{}", instance_id),
                        name,
                        device_type: nodesec_core::models::DeviceType::Bluetooth,
                        vendor: None,
                        product_id: None,
                        vendor_id: None,
                        serial_number: Some(instance_id),
                        connected_at: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs(),
                        last_seen: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs(),
                        is_connected: status == "OK",
                    });
                }
            }
        }

        return devices;
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        Vec::new()
    }
}/// Recursively extract USB devices from JSON items (handles USB hubs with _items)
fn extract_usb_from_json_recursive(item: &serde_json::Value, devices: &mut Vec<nodesec_core::models::ConnectedDevice>) {
    let name = item.get("_name").and_then(|v| v.as_str()).unwrap_or("Unknown USB Device").to_string();
    let vendor = item.get("_vendor").and_then(|v| v.as_str()).map(|s| s.to_string());
    let product_id = item.get("product_id").and_then(|v| v.as_str()).map(|s| s.to_string());
    let vendor_id = item.get("vendor_id").and_then(|v| v.as_str()).map(|s| s.to_string());
    let serial = item.get("serial_num").and_then(|v| v.as_str()).map(|s| s.to_string());
    
    let is_hub = name.to_lowercase().contains("hub") || vendor_id.is_none();
    
    if !is_hub || vendor_id.is_some() {
        devices.push(nodesec_core::models::ConnectedDevice {
            id: format!("usb:{}:{}", vendor_id.as_deref().unwrap_or("unknown"), product_id.as_deref().unwrap_or("unknown")),
            name,
            device_type: nodesec_core::models::DeviceType::Usb,
            vendor,
            product_id,
            vendor_id,
            serial_number: serial,
            connected_at: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs(),
            last_seen: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs(),
            is_connected: true,
        });
    }
    
    // Recurse into _items (devices connected through hubs)
    if let Some(sub_items) = item.get("_items").and_then(|v| v.as_array()) {
        for sub in sub_items {
            extract_usb_from_json_recursive(sub, devices);
        }
    }
}

