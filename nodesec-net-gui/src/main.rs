use eframe::egui;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use std::collections::VecDeque;
use tokio::runtime;
use nodesec_core::models::Platform;

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
            Tab::Dashboard => "Dashboard",
            Tab::Connections => "Connections",
            Tab::ProcessTree => "Process Tree",
            Tab::ConnectionGraph => "Graph",
            Tab::Alerts => "Alerts",
            Tab::Statistics => "Statistics",
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
    selected_connection: Option<usize>,
    selected_process: Option<u32>,
    selected_graph_node: Option<String>,
    graph: ConnectionGraph,
    filter: FilterSettings,
    // Details pane - separate state so it persists across tab switches
    details_selected_tab: Tab,
    details_selected_index: Option<usize>,
    details_selected_pid: Option<u32>,
    details_selected_node: Option<String>,
    // Details pane visibility
    show_details_pane: bool,
    // Sort state
    conn_sort_field: SortField,
    conn_sort_dir: SortDir,
    proc_sort_field: SortField,
    proc_sort_dir: SortDir,
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
            details_selected_tab: Tab::Dashboard,
            details_selected_index: None,
            details_selected_pid: None,
            details_selected_node: None,
            show_details_pane: true,
            conn_sort_field: SortField::Time,
            conn_sort_dir: SortDir::Desc,
            proc_sort_field: SortField::Process,
            proc_sort_dir: SortDir::Asc,
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
                self.selected_connection = None;
                self.details_selected_index = None;
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

        // Clone connections to avoid borrow issues
        let mut connections: Vec<crate::state::ConnectionItem> = self.monitor_state.connections.lock().unwrap().clone();

        // Apply filter
        connections.retain(|item| self.filter.matches(item));

        // Sort
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

        egui::ScrollArea::both().show(ui, |ui| {
            ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Extend);

            // Sortable header row — click to toggle sort
            ui.horizontal(|ui| {
                ui.add_space(2.0);

                // Sel column
                if ui.small_button("Sel").clicked() {
                    // No sort for selection column
                }
                ui.add_space(8.0);

                // Time
                if self.conn_sort_field == SortField::Time {
                    ui.label(egui::RichText::new(format!("Time {}", self.conn_sort_dir.icon())).color(ORANGE).strong());
                } else if ui.small_button("Time").clicked() {
                    self.conn_sort_field = SortField::Time;
                    self.conn_sort_dir = SortDir::Asc;
                }
                ui.add_space(8.0);

                // PID
                if self.conn_sort_field == SortField::Pid {
                    ui.label(egui::RichText::new(format!("PID {}", self.conn_sort_dir.icon())).color(ORANGE).strong());
                } else if ui.small_button("PID").clicked() {
                    self.conn_sort_field = SortField::Pid;
                    self.conn_sort_dir = SortDir::Asc;
                }
                ui.add_space(16.0);

                // Process
                if self.conn_sort_field == SortField::Process {
                    ui.label(egui::RichText::new(format!("Process {}", self.conn_sort_dir.icon())).color(ORANGE).strong());
                } else if ui.small_button("Process").clicked() {
                    self.conn_sort_field = SortField::Process;
                    self.conn_sort_dir = SortDir::Asc;
                }
                ui.add_space(16.0);

                // Proto
                if self.conn_sort_field == SortField::Proto {
                    ui.label(egui::RichText::new(format!("Proto {}", self.conn_sort_dir.icon())).color(ORANGE).strong());
                } else if ui.small_button("Proto").clicked() {
                    self.conn_sort_field = SortField::Proto;
                    self.conn_sort_dir = SortDir::Asc;
                }
                ui.add_space(16.0);

                // Source
                if self.conn_sort_field == SortField::Source {
                    ui.label(egui::RichText::new(format!("Source {}", self.conn_sort_dir.icon())).color(ORANGE).strong());
                } else if ui.small_button("Source").clicked() {
                    self.conn_sort_field = SortField::Source;
                    self.conn_sort_dir = SortDir::Asc;
                }
                ui.add_space(16.0);

                // Destination
                if self.conn_sort_field == SortField::Destination {
                    ui.label(egui::RichText::new(format!("Destination {}", self.conn_sort_dir.icon())).color(ORANGE).strong());
                } else if ui.small_button("Destination").clicked() {
                    self.conn_sort_field = SortField::Destination;
                    self.conn_sort_dir = SortDir::Asc;
                }
                ui.add_space(16.0);

                // Threat
                if self.conn_sort_field == SortField::Score {
                    ui.label(egui::RichText::new(format!("Score {}", self.conn_sort_dir.icon())).color(ORANGE).strong());
                } else if ui.small_button("Score").clicked() {
                    self.conn_sort_field = SortField::Score;
                    self.conn_sort_dir = SortDir::Asc;
                }
                ui.add_space(8.0);

                ui.label(egui::RichText::new("").color(ORANGE)); // spacer
            });
            ui.separator();

            // Data rows using horizontal layout (NOT Grid — Grid crashes with interactive widgets)
            // Wrap each row in a Frame for visual separation
            for (i, item) in connections.iter().enumerate() {
                let conn = &item.connection;
                let threat_color = item.threat_level.color();

                let src = format!("{}:{}", conn.src_ip, conn.src_port);
                let dst = format!("{}:{}", conn.dst_ip, conn.dst_port);
                let proto = format!("{:?}", conn.protocol);
                let time = chrono::DateTime::from_timestamp(conn.timestamp as i64, 0)
                    .map(|dt| dt.format("%H:%M:%S").to_string())
                    .unwrap_or_default();

                let selected_conn = self.selected_connection;
                let is_selected = selected_conn == Some(i);

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
                        ui.horizontal(|ui| {
                            ui.add_space(2.0);

                            // Select button — full row selection
                            let btn_text = if is_selected { "[Selected]" } else { "[Select]" };
                            if ui.small_button(btn_text).clicked() {
                                self.selected_connection = Some(i);
                                self.details_selected_index = Some(i);
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

                ui.add_space(2.0);
            }
        });

        // Detail panel for selected connection (top-to-bottom layout below table)
        if let Some(idx) = self.selected_connection {
            if idx < connections.len() {
                ui.separator();
                crate::ui::render_connection_detail_topdown(ui, &connections[idx], &self.monitor_state);
            } else {
                self.selected_connection = None;
                self.details_selected_index = None;
            }
        }
    }

    fn render_process_tree(&mut self, ui: &mut egui::Ui) {
        // Hub-and-spoke process tree (like image 4)
        // Central hub at bottom, processes branch up with colored lines
        ui.heading(egui::RichText::new("Connection Processes").color(ORANGE));
        ui.separator();

        // Root privilege warning (macOS)
        #[cfg(target_os = "macos")]
        {
            let is_root = unsafe { libc::geteuid() == 0 };
            if !is_root {
                ui.group(|ui| {
                    ui.set_min_width(ui.available_width());
                    ui.colored_label(RED, egui::RichText::new("[!] Process names require root privileges").strong());
                    ui.label("Click \"Request Root\" in the header to enable PID/process name resolution via lsof.");
                });
                ui.separator();
            }
        }

        ui.label(egui::RichText::new("Central hub = all connections • Branches = processes • Click process for details").color(GRAY).size(11.0));
        ui.separator();

        let connections: Vec<crate::state::ConnectionItem> = self
            .monitor_state
            .connections
            .lock()
            .unwrap()
            .iter()
            .filter(|item| self.filter.matches(item))
            .cloned()
            .collect();

        if connections.is_empty() {
            ui.centered_and_justified(|ui| {
                ui.label(egui::RichText::new("No connections captured yet. Start monitoring to see connections.").color(GRAY));
            });
            return;
        }

        // Group by process
        use std::collections::HashMap;
        let mut process_map: HashMap<String, Vec<&crate::state::ConnectionItem>> = HashMap::new();
        for item in &connections {
            let key = if item.connection.pid == 0 && item.connection.process_name == "unknown" {
                format!("unknown:{}", item.connection.src_port)
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

        // Sort by threat score descending
        processes.sort_by(|a, b| b.2.cmp(&a.2).then_with(|| a.0.cmp(&b.0)));

        let available = ui.available_rect_before_wrap();
        let hub_y = available.bottom() - 60.0;
        let hub_x = available.min.x + available.width() / 2.0;

        // Cell dimensions
        let cell_width = 180.0;
        let cell_height = 70.0;
        let cell_spacing = 20.0;
        let num_procs = processes.len();
        let total_width = num_procs as f32 * (cell_width + cell_spacing);
        let start_x = hub_x - total_width / 2.0;

        // Draw branch lines from hub to each process cell (behind cells)
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

            // Vertical-ish line from hub to cell
            ui.painter().line_segment(
                [
                    egui::pos2(hub_x, hub_y),
                    egui::pos2(cell_x, cell_y + cell_height / 2.0),
                ],
                egui::Stroke::new(2.0, threat_color),
            );

            // Dot at top of branch
            ui.painter().circle_filled(
                egui::pos2(cell_x, cell_y + cell_height / 2.0),
                4.0,
                threat_color,
            );
        }

        // Draw hub at bottom center
        let hub_rect = egui::Rect::from_center_size(
            egui::pos2(hub_x, hub_y),
            egui::vec2(180.0, 40.0),
        );
        ui.painter().rect_filled(hub_rect, 8.0, egui::Color32::from_rgb(60, 60, 60));
        ui.painter().rect_stroke(hub_rect, 8.0, egui::Stroke::new(2.0, ORANGE));
        ui.painter().text(
            hub_rect.center(),
            egui::Align2::CENTER_CENTER,
            "All Connections",
            egui::FontId::new(14.0, egui::FontFamily::Proportional),
            WHITE,
        );

        // Draw process cells in a horizontal scrollable row
        egui::ScrollArea::horizontal().show(ui, |ui| {
            ui.set_min_size(egui::vec2(total_width + cell_spacing * 2.0, available.height() - 80.0));

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
                ui.painter().rect_filled(
                    cell_rect,
                    6.0,
                    egui::Color32::from_rgb(40, 40, 40),
                );
                ui.painter().rect_stroke(
                    cell_rect,
                    6.0,
                    egui::Stroke::new(2.0, if is_selected { WHITE } else { threat_color }),
                );

                // Cell content
                let old_clip = ui.clip_rect();
                ui.set_clip_rect(cell_rect.shrink(8.0));
                ui.vertical(|ui| {
                    ui.add_space(2.0);
                    let display_name = if key.starts_with("unknown") {
                        format!("Unknown (port {})", key.split(':').nth(1).unwrap_or(&"0"))
                    } else {
                        key.split(':').nth(1).unwrap_or(&key).to_string()
                    };
                    ui.label(egui::RichText::new(&display_name).color(WHITE).size(11.0).strong());
                    ui.add_space(1.0);
                    ui.label(egui::RichText::new(format!("PID: {}", pid)).color(GRAY).size(9.0));
                    ui.add_space(1.0);
                    ui.label(egui::RichText::new(format!("{} connections", conns.len())).color(ORANGE).size(9.0));
                    ui.add_space(1.0);
                    ui.colored_label(threat_color, egui::RichText::new(format!("Threat: {}", threat_score)).size(9.0));
                });
                ui.set_clip_rect(old_clip);

                // Clickable overlay
                let response = ui.interact(
                    cell_rect,
                    ui.id().with(format!("proc_btn_{}", i)),
                    egui::Sense::click(),
                );
                if response.clicked() {
                    self.selected_process = Some(pid);
                    self.details_selected_pid = Some(pid);
                    self.details_selected_tab = Tab::ProcessTree;
                }
            }
        });

        // Details panel for selected process (bottom section)
        if let Some(pid) = self.selected_process {
            let all_conns: Vec<crate::state::ConnectionItem> = self
                .monitor_state
                .connections
                .lock()
                .unwrap()
                .iter()
                .filter(|item| item.connection.pid == pid)
                .cloned()
                .collect();

            if let Some(proc_item) = all_conns.first() {
                ui.separator();
                let proc = crate::state::ProcessTreeItem {
                    pid,
                    name: proc_item.connection.process_name.clone(),
                    path: proc_item.connection.process_path.clone(),
                    user: proc_item.connection.user.clone(),
                    connections: all_conns.iter().map(|c| c.connection.clone()).collect(),
                    children: Vec::new(),
                    total_threat_score: proc_item.connection.threat_score,
                    is_suspicious: proc_item.connection.is_suspicious,
                };
                self.render_process_detail(ui, &proc);
            }
        }
    }

    fn render_connection_graph(&mut self, ui: &mut egui::Ui) {
        // Cell-based graph: rounded rectangles (cells) connected by lines
        // Top-down layout with ample space between cells (like image 3/4 style)
        ui.heading(egui::RichText::new("Connection Graph (Cell View)").color(ORANGE));
        ui.separator();

        ui.label(egui::RichText::new("Cells = processes • Lines = shared connections • Click cell for details").color(GRAY).size(11.0));
        ui.separator();

        let connections: Vec<crate::state::ConnectionItem> = self
            .monitor_state
            .connections
            .lock()
            .unwrap()
            .iter()
            .filter(|item| self.filter.matches(item))
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
            let key = if item.connection.pid == 0 && item.connection.process_name == "unknown" {
                format!("unknown:{}", item.connection.src_port)
            } else {
                format!("{}:{}", item.connection.pid, item.connection.process_name)
            };
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

        // Layout: vertical column of cells with ample spacing (like image 3/4)
        let cell_width = 300.0;
        let cell_height = 110.0;
        let cell_spacing = 25.0;

        let total_height = cells.len() as f32 * (cell_height + cell_spacing) + cell_spacing;

        let available = ui.available_rect_before_wrap();

        egui::ScrollArea::both().show(ui, |ui| {
            ui.set_min_size(egui::vec2(available.width(), total_height));

            let mut y = cell_spacing;
            let center_x = available.min.x + available.width() / 2.0 - cell_width / 2.0;

            for (i, (key, conns, cell_color)) in cells.iter().enumerate() {
                let cell_rect = egui::Rect::from_min_size(
                    egui::pos2(center_x, y),
                    egui::vec2(cell_width, cell_height),
                );

                // Draw connecting line from previous cell to this cell
                if i > 0 {
                    let prev_bottom = egui::pos2(center_x + cell_width / 2.0, y - cell_spacing / 2.0);
                    let this_top = egui::pos2(center_x + cell_width / 2.0, y);
                    ui.painter().line_segment(
                        [prev_bottom, this_top],
                        egui::Stroke::new(2.0, GRAY),
                    );
                }

                // Cell frame
                let is_selected = self.details_selected_node == Some(format!("cell_{}", i));
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

                // Cell content - use scope with clip rect instead of child_ui
                let old_clip = ui.clip_rect();
                ui.set_clip_rect(cell_rect.shrink(10.0));
                ui.vertical_centered(|ui| {
                    // Process name (truncated)
                    let display_name = if key.starts_with("unknown") {
                        format!("Unknown (port {})", key.split(':').nth(1).unwrap_or(&"0"))
                    } else {
                        key.split(':').nth(1).unwrap_or(&key).to_string()
                    };
                    ui.label(egui::RichText::new(&display_name).color(WHITE).size(13.0).strong());
                    ui.add_space(2.0);
                    ui.label(egui::RichText::new(format!("PID: {}", key.split(':').next().unwrap_or(&"0"))).color(GRAY).size(10.0));
                    ui.add_space(2.0);
                    ui.label(egui::RichText::new(format!("Connections: {}", conns.len())).color(ORANGE).size(11.0));
                    ui.add_space(2.0);
                    ui.colored_label(*cell_color, egui::RichText::new(format!("Max Threat: {}", conns.iter().map(|c| c.connection.threat_score).max().unwrap_or(0))).size(10.0));
                });
                ui.set_clip_rect(old_clip);

                // Clickable button overlay for the cell
                let response = ui.interact(
                    cell_rect,
                    ui.id().with(format!("cell_btn_{}", i)),
                    egui::Sense::click(),
                );
                if response.clicked() {
                    self.details_selected_node = Some(format!("cell_{}", i));
                    self.details_selected_tab = Tab::ConnectionGraph;
                    self.details_selected_index = Some(0);
                }

                y += cell_height + cell_spacing;
            }
        });

        // Details panel for selected cell (bottom section)
        if let Some(idx) = self.details_selected_index {
            if let Some(item) = connections.get(idx) {
                ui.separator();
                crate::ui::render_connection_detail_topdown(ui, item, &self.monitor_state);
            }
        }
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

    fn render_details_pane(&mut self, ui: &mut egui::Ui) {
        ui.heading(egui::RichText::new("Details").color(ORANGE).strong());
        ui.separator();

        match self.details_selected_tab {
            Tab::Connections => {
                if let Some(idx) = self.details_selected_index {
                    let connections = self.monitor_state.connections.lock().unwrap();
                    if idx < connections.len() {
                        crate::ui::render_connection_detail_topdown(ui, &connections[idx], &self.monitor_state);
                    } else {
                        ui.centered_and_justified(|ui| {
                            ui.label(egui::RichText::new("Select a connection to view details").color(GRAY));
                        });
                    }
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
                if let Some(idx) = self.details_selected_index {
                    let connections = self.monitor_state.connections.lock().unwrap();
                    if idx < connections.len() {
                        crate::ui::render_connection_detail_topdown(ui, &connections[idx], &self.monitor_state);
                    } else {
                        ui.centered_and_justified(|ui| {
                            ui.label(egui::RichText::new("Click [View] on a connection to see details").color(GRAY));
                        });
                    }
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

                    // Root privilege indicator and request button (macOS only)
                    #[cfg(target_os = "macos")]
                    {
                        let is_root = unsafe { libc::geteuid() == 0 };
                        let root_text = if is_root {
                            "[Root: ON]".to_string()
                        } else {
                            "[Root: OFF]".to_string()
                        };
                        let root_color = if is_root { GREEN } else { RED };
                        ui.colored_label(root_color, root_text);
                        ui.add_space(4.0);
                        if !is_root && ui.button("Request Root").clicked() {
                            ensure_root_privileges();
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
                    Tab::ConnectionGraph, Tab::Alerts, Tab::Statistics, Tab::Settings
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
            details_selected_tab: Tab::Dashboard,
            details_selected_index: None,
            details_selected_pid: None,
            details_selected_node: None,
            show_details_pane: true,
            conn_sort_field: SortField::Time,
            conn_sort_dir: SortDir::Desc,
            proc_sort_field: SortField::Process,
            proc_sort_dir: SortDir::Asc,
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
    #[cfg(target_os = "macos")]
    {
        ensure_root_privileges();
    }

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