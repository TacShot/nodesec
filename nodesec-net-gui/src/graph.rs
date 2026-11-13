//! Connection graph visualization for network monitoring

use egui::{Color32, Pos2, Response, Shape, Sense, Stroke, Vec2, Widget, Align2, FontId};
use nodesec_core::models::NetworkConnection;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct GraphNode {
    pub id: String,
    pub label: String,
    pub pos: Pos2,
    pub target_pos: Pos2,
    pub color: Color32,
    pub size: f32,
    pub is_process: bool,
    pub threat_score: u8,
    pub connections: usize,
    pub pid: Option<u32>,
    pub process_name: String,
    pub interface: Option<String>,
    pub connection_type: ConnectionType,
    pub remote_ip: Option<String>,
    pub remote_port: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ConnectionType {
    Process,
    Tcp,
    Udp,
    Bluetooth,
    Wired,
    Wireless,
    Usb,
    Local,
    Browser,
    Unknown,
}

impl ConnectionType {
    pub fn from_connection(conn: &NetworkConnection) -> Self {
        match conn.protocol {
            nodesec_core::models::NetworkProtocol::Tcp => {
                if conn.dst_ip.is_loopback() || conn.src_ip.is_loopback() {
                    ConnectionType::Local
                } else if conn.dst_port == 443 || conn.dst_port == 80 {
                    ConnectionType::Browser
                } else {
                    ConnectionType::Tcp
                }
            }
            nodesec_core::models::NetworkProtocol::Udp => ConnectionType::Udp,
            _ => ConnectionType::Unknown,
        }
    }
    
    pub fn color(&self) -> Color32 {
        match self {
            ConnectionType::Process => Color32::from_rgb(0, 200, 100),
            ConnectionType::Tcp => Color32::from_rgb(100, 150, 255),
            ConnectionType::Udp => Color32::from_rgb(255, 200, 100),
            ConnectionType::Bluetooth => Color32::from_rgb(100, 100, 255),
            ConnectionType::Wired => Color32::from_rgb(150, 255, 150),
            ConnectionType::Wireless => Color32::from_rgb(200, 150, 255),
            ConnectionType::Usb => Color32::from_rgb(255, 150, 100),
            ConnectionType::Local => Color32::from_rgb(180, 180, 180),
            ConnectionType::Browser => Color32::from_rgb(255, 100, 200),
            ConnectionType::Unknown => Color32::from_rgb(128, 128, 128),
        }
    }
    
    pub fn label(&self) -> &'static str {
        match self {
            ConnectionType::Process => "Process",
            ConnectionType::Tcp => "TCP",
            ConnectionType::Udp => "UDP",
            ConnectionType::Bluetooth => "Bluetooth",
            ConnectionType::Wired => "Wired",
            ConnectionType::Wireless => "Wireless",
            ConnectionType::Usb => "USB",
            ConnectionType::Local => "Local",
            ConnectionType::Browser => "Browser",
            ConnectionType::Unknown => "Unknown",
        }
    }
}

#[derive(Debug, Clone)]
struct GraphEdge {
    from: String,
    to: String,
    color: Color32,
    thickness: f32,
}

pub struct ConnectionGraph {
    pub nodes: Arc<Mutex<HashMap<String, GraphNode>>>,
    pub edges: Arc<Mutex<Vec<GraphEdge>>>,
    layout_iteration: Mutex<usize>,
    pub selected_node: Arc<Mutex<Option<String>>>,
    pub hovered_node: Arc<Mutex<Option<String>>>,
    last_update: Mutex<Instant>,
    center_pos: Arc<Mutex<Pos2>>,
    zoom: Arc<Mutex<f32>>,
    pan_offset: Arc<Mutex<Vec2>>,
    last_connection_count: Mutex<usize>,
    layout_dirty: Arc<Mutex<bool>>,
    pub monitor_state: Arc<crate::state::MonitorState>,
}

impl ConnectionGraph {
    pub fn new(monitor_state: Arc<crate::state::MonitorState>) -> Self {
        Self {
            nodes: Arc::new(Mutex::new(HashMap::new())),
            edges: Arc::new(Mutex::new(Vec::new())),
            layout_iteration: Mutex::new(0),
            selected_node: Arc::new(Mutex::new(None)),
            hovered_node: Arc::new(Mutex::new(None)),
            last_update: Mutex::new(Instant::now()),
            center_pos: Arc::new(Mutex::new(Pos2::new(400.0, 300.0))),
            zoom: Arc::new(Mutex::new(1.0)),
            pan_offset: Arc::new(Mutex::new(Vec2::ZERO)),
            last_connection_count: Mutex::new(0),
            layout_dirty: Arc::new(Mutex::new(true)),
            monitor_state,
        }
    }
    
    pub fn update(&self, connections: &[crate::state::ConnectionItem]) {
        let conn_count = connections.len();
        let mut last_count = self.last_connection_count.lock().unwrap();
        let count_changed = (conn_count as i32 - *last_count as i32).abs() > 3;
        *last_count = conn_count;
        
        if !count_changed && !*self.layout_dirty.lock().unwrap() {
            self.update_node_attributes(connections);
            return;
        }
        
        *self.layout_dirty.lock().unwrap() = false;
        
        let mut nodes = self.nodes.lock().unwrap();
        let mut edges = self.edges.lock().unwrap();
        
        let old_positions: HashMap<String, Pos2> = nodes.iter()
            .map(|(k, v)| (k.clone(), v.pos))
            .collect();
        
        nodes.clear();
        edges.clear();
        
        let mut process_connections: HashMap<u32, Vec<&NetworkConnection>> = HashMap::new();
        for item in connections {
            process_connections
                .entry(item.connection.pid)
                .or_default()
                .push(&item.connection);
        }
        
        let mut interface_groups: HashMap<String, Vec<u32>> = HashMap::new();
        
        for (pid, conns) in &process_connections {
            let first = conns[0];
            let avg_threat = conns.iter().map(|c| c.threat_score as u32).sum::<u32>() / conns.len() as u32;
            let is_suspicious = conns.iter().any(|c| c.is_suspicious);
            
            let color = if is_suspicious {
                if avg_threat > 75 { Color32::RED } else { Color32::from_rgb(255, 165, 0) }
            } else {
                Color32::from_rgb(0, 200, 100)
            };
            
            let conn_type = ConnectionType::from_connection(first);
            let interface_key = conn_type.label().to_string();
            interface_groups.entry(interface_key.clone()).or_default().push(*pid);
            
            let node = GraphNode {
                id: format!("proc_{}", pid),
                label: format!("{} (PID: {})", first.process_name, pid),
                pos: old_positions.get(&format!("proc_{}", pid)).cloned().unwrap_or(Pos2::ZERO),
                target_pos: Pos2::ZERO,
                color,
                size: 30.0 + (conns.len() as f32 * 2.0).min(50.0),
                is_process: true,
                threat_score: avg_threat as u8,
                connections: conns.len(),
                pid: Some(*pid),
                process_name: first.process_name.clone(),
                interface: Some(interface_key),
                connection_type: ConnectionType::Process,
                remote_ip: None,
                remote_port: None,
            };
            nodes.insert(node.id.clone(), node);
        }
        
        let mut remote_hosts: HashMap<String, (String, u16, Vec<&NetworkConnection>, ConnectionType)> = HashMap::new();
        
        for item in connections {
            let conn = &item.connection;
            let remote_key = format!("{}:{}", conn.dst_ip, conn.dst_port);
            let conn_type = ConnectionType::from_connection(conn);
            
            remote_hosts
                .entry(remote_key.clone())
                .or_insert_with(|| (conn.dst_ip.to_string(), conn.dst_port, Vec::new(), conn_type))
                .2.push(conn);
        }
        
        for (key, (ip, port, conns, conn_type)) in remote_hosts {
            let avg_threat = conns.iter().map(|c| c.threat_score as u32).sum::<u32>() / conns.len() as u32;
            let is_suspicious = conns.iter().any(|c| c.is_suspicious);
            
            let color = if is_suspicious {
                if avg_threat > 75 { Color32::RED } else { Color32::from_rgb(255, 165, 0) }
            } else {
                conn_type.color()
            };
            
            let node = GraphNode {
                id: format!("host_{}", key),
                label: format!("{}:{}", ip, port),
                pos: old_positions.get(&format!("host_{}", key)).cloned().unwrap_or(Pos2::ZERO),
                target_pos: Pos2::ZERO,
                color,
                size: 20.0,
                is_process: false,
                threat_score: avg_threat as u8,
                connections: conns.len(),
                pid: None,
                process_name: String::new(),
                interface: Some(conn_type.label().to_string()),
                connection_type: conn_type.clone(),
                remote_ip: Some(ip.clone()),
                remote_port: Some(port),
            };
            nodes.insert(node.id.clone(), node);
            
            let mut process_ids: HashSet<u32> = HashSet::new();
            for conn in conns {
                process_ids.insert(conn.pid);
            }
            
            for pid in process_ids {
                edges.push(GraphEdge {
                    from: format!("proc_{}", pid),
                    to: format!("host_{}", key),
                    color: if is_suspicious { Color32::RED } else { Color32::from_rgb(100, 100, 100) },
                    thickness: 1.5,
                });
            }
        }
        
        self.run_layout(&mut nodes, &edges);
    }
    
    fn update_node_attributes(&self, connections: &[crate::state::ConnectionItem]) {
        let mut nodes = self.nodes.lock().unwrap();
        
        let mut process_threats: HashMap<u32, (u32, bool)> = HashMap::new();
        let mut host_threats: HashMap<String, (u32, bool)> = HashMap::new();
        
        for item in connections {
            let conn = &item.connection;
            let proc_entry = process_threats.entry(conn.pid).or_insert((0, false));
            proc_entry.0 += conn.threat_score as u32;
            proc_entry.1 = proc_entry.1 || conn.is_suspicious;
            
            let host_key = format!("{}:{}", conn.dst_ip, conn.dst_port);
            let host_entry = host_threats.entry(host_key).or_insert((0, false));
            host_entry.0 += conn.threat_score as u32;
            host_entry.1 = host_entry.1 || conn.is_suspicious;
        }
        
        for (pid, (total_threat, is_suspicious)) in &process_threats {
            let avg_threat = total_threat / process_threats.get(pid).map(|_| 1).unwrap_or(1);
            if let Some(node) = nodes.get_mut(&format!("proc_{}", pid)) {
                node.threat_score = avg_threat as u8;
                node.color = if *is_suspicious {
                    if avg_threat > 75 { Color32::RED } else { Color32::from_rgb(255, 165, 0) }
                } else {
                    Color32::from_rgb(0, 200, 100)
                };
            }
        }
        
        for (key, (total_threat, is_suspicious)) in &host_threats {
            let avg_threat = total_threat / host_threats.get(key).map(|_| 1).unwrap_or(1);
            if let Some(node) = nodes.get_mut(&format!("host_{}", key)) {
                node.threat_score = avg_threat as u8;
                let conn_type = ConnectionType::from_connection(&connections[0].connection);
                node.color = if *is_suspicious {
                    if avg_threat > 75 { Color32::RED } else { Color32::from_rgb(255, 165, 0) }
                } else {
                    conn_type.color()
                };
            }
        }
    }
    
    fn run_layout(&self, nodes: &mut HashMap<String, GraphNode>, edges: &[GraphEdge]) {
        let center = *self.center_pos.lock().unwrap();
        let k = 200.0;
        let damping = 0.85;
        let max_displacement = 30.0;
        
        let mut interface_positions: HashMap<String, Vec<String>> = HashMap::new();
        for (id, node) in nodes.iter() {
            interface_positions
                .entry(node.interface.clone().unwrap_or("Unknown".to_string()))
                .or_default()
                .push(id.clone());
        }
        
        let interface_count = interface_positions.len() as f32;
        for (idx, (interface, node_ids)) in interface_positions.iter().enumerate() {
            let angle = (idx as f32 / interface_count) * 2.0 * std::f32::consts::PI;
            let cluster_center = Pos2::new(
                center.x + angle.cos() * 250.0,
                center.y + angle.sin() * 250.0,
            );
            
            let node_count = node_ids.len() as f32;
            for (i, node_id) in node_ids.iter().enumerate() {
                if let Some(node) = nodes.get_mut(node_id) {
                    if node.pos == Pos2::ZERO {
                        let angle = (i as f32 / node_count) * 2.0 * std::f32::consts::PI;
                        let radius = if node.is_process { 80.0 } else { 120.0 };
                        node.pos = Pos2::new(
                            cluster_center.x + angle.cos() * radius,
                            cluster_center.y + angle.sin() * radius,
                        );
                        node.target_pos = node.pos;
                    }
                }
            }
        }
        
        for iteration in 0..20 {
            let temp_k = k * (1.0 - iteration as f32 / 20.0);
            
            let node_ids: Vec<String> = nodes.keys().cloned().collect();
            for i in 0..node_ids.len() {
                for j in (i + 1)..node_ids.len() {
                    let id1 = &node_ids[i];
                    let id2 = &node_ids[j];
                    
                    if let (Some(n1), Some(n2)) = (nodes.get(id1), nodes.get(id2)) {
                        let diff = n2.pos - n1.pos;
                        let dist = diff.length().max(1.0);
                        
                        if dist > 500.0 { continue; }
                        
                        let force = temp_k * temp_k / dist;
                        let dir = diff / dist;
                        let displacement = (force * 0.015 * damping).min(max_displacement);
                        
                        if let Some(n1_mut) = nodes.get_mut(id1) {
                            n1_mut.pos -= dir * displacement;
                        }
                        if let Some(n2_mut) = nodes.get_mut(id2) {
                            n2_mut.pos += dir * displacement;
                        }
                    }
                }
            }
            
            for edge in edges {
                if let (Some(n1), Some(n2)) = (nodes.get(&edge.from), nodes.get(&edge.to)) {
                    let diff = n2.pos - n1.pos;
                    let dist = diff.length().max(1.0);
                    let force = dist * dist / temp_k;
                    let dir = diff / dist;
                    let displacement = (force * 0.015 * damping).min(max_displacement);
                    
                    if let Some(n1_mut) = nodes.get_mut(&edge.from) {
                        n1_mut.pos += dir * displacement;
                    }
                    if let Some(n2_mut) = nodes.get_mut(&edge.to) {
                        n2_mut.pos -= dir * displacement;
                    }
                }
            }
            
            for (_, node) in nodes.iter_mut() {
                let to_center = center - node.pos;
                let dist = to_center.length();
                if dist > 400.0 {
                    node.pos += to_center * 0.015;
                }
            }
        }
        
        for (_, node) in nodes.iter_mut() {
            let diff = node.target_pos - node.pos;
            if diff.length() > 1.0 {
                node.pos += diff * 0.1;
            } else {
                node.pos = node.target_pos;
            }
        }
        
        *self.layout_iteration.lock().unwrap() += 1;
        *self.last_update.lock().unwrap() = Instant::now();
    }
    
    pub fn select_node(&self, node_id: &str) {
        *self.selected_node.lock().unwrap() = Some(node_id.to_string());
    }
    
    pub fn clear_selection(&self) {
        *self.selected_node.lock().unwrap() = None;
    }
    
    pub fn set_hovered_node(&self, node_id: Option<String>) {
        *self.hovered_node.lock().unwrap() = node_id;
    }
    
    pub fn get_selected(&self) -> Option<GraphNode> {
        let selected_id = self.selected_node.lock().unwrap().clone()?;
        let nodes = self.nodes.lock().unwrap();
        nodes.get(&selected_id).cloned()
    }
    
    pub fn get_hovered(&self) -> Option<GraphNode> {
        let hovered_id = self.hovered_node.lock().unwrap().clone()?;
        let nodes = self.nodes.lock().unwrap();
        nodes.get(&hovered_id).cloned()
    }
    
    pub fn handle_click(&self, ui: &egui::Ui, pos: Pos2) -> bool {
        let nodes = self.nodes.lock().unwrap();
        let zoom = *self.zoom.lock().unwrap();
        let pan = *self.pan_offset.lock().unwrap();
        
        let graph_pos = (pos - pan) / zoom;
        
        for (id, node) in nodes.iter() {
            let dist = (node.pos - graph_pos).length();
            if dist < node.size {
                *self.selected_node.lock().unwrap() = Some(id.clone());
                return true;
            }
        }
        false
    }
    
    pub fn handle_hover(&self, ui: &egui::Ui, pos: Pos2) -> bool {
        let nodes = self.nodes.lock().unwrap();
        let zoom = *self.zoom.lock().unwrap();
        let pan = *self.pan_offset.lock().unwrap();
        
        let graph_pos = (pos - pan) / zoom;
        
        for (id, node) in nodes.iter() {
            let dist = (node.pos - graph_pos).length();
            if dist < node.size {
                *self.hovered_node.lock().unwrap() = Some(id.clone());
                return true;
            }
        }
        *self.hovered_node.lock().unwrap() = None;
        false
    }
    
    pub fn render(&self, ui: &mut egui::Ui, rect: egui::Rect) -> Response {
        let nodes = self.nodes.lock().unwrap();
        let edges = self.edges.lock().unwrap();
        let zoom = *self.zoom.lock().unwrap();
        let pan = *self.pan_offset.lock().unwrap();
        let selected_id = self.selected_node.lock().unwrap().clone();
        let hovered_id = self.hovered_node.lock().unwrap().clone();
        
        let response = ui.allocate_rect(rect, Sense::click_and_drag());
        
        // Handle pan - use secondary button or shift+drag to avoid conflicts with node selection
        if response.dragged_by(egui::PointerButton::Secondary) || 
           (response.dragged() && ui.input(|i| i.modifiers.shift)) {
            let delta = response.drag_delta();
            *self.pan_offset.lock().unwrap() += delta;
        }
        
        if response.hovered() {
            let scroll = ui.input(|i| i.smooth_scroll_delta.y + i.raw_scroll_delta.y);
            if scroll != 0.0 {
                let mut z = self.zoom.lock().unwrap();
                let old_zoom = *z;
                *z = (*z * (1.0 + scroll * 0.008)).clamp(0.15, 5.0);
                
                if let Some(mouse_pos) = response.hover_pos() {
                    let rel_pos = (mouse_pos - *self.center_pos.lock().unwrap()) / old_zoom;
                    *self.pan_offset.lock().unwrap() -= rel_pos * (*z - old_zoom);
                }
            }
            
            let pinch = ui.input(|i| i.zoom_delta());
            if pinch != 1.0 {
                let mut z = self.zoom.lock().unwrap();
                *z = (*z * pinch).clamp(0.15, 5.0);
            }
        }
        
        // Handle click for node selection - use a separate interaction
        let click_response = ui.interact(rect, egui::Id::new("graph_click"), Sense::click());
        if click_response.clicked() {
            if let Some(click_pos) = click_response.interact_pointer_pos() {
                self.handle_click(ui, click_pos);
            }
        }
        
        if response.hovered() {
            if let Some(hover_pos) = response.hover_pos() {
                self.handle_hover(ui, hover_pos);
            }
        }
        
        // Context menu on right-click
        response.context_menu(|ui| {
            if let Some(node) = self.get_selected() {
                ui.heading("Node Actions");
                ui.separator();
                
                let monitor_state = self.monitor_state.clone();
                
                if node.is_process {
                    if let Some(pid) = node.pid {
                        if ui.button("🔴 Terminate Process").clicked() {
                            crate::ui::terminate_process(pid, &node.process_name, &monitor_state);
                            ui.close_menu();
                        }
                        if ui.button("🚫 Block All Ports").clicked() {
                            ui.close_menu();
                        }
                        if ui.button("📋 Copy PID").clicked() {
                            ui.output_mut(|o| o.copied_text = pid.to_string());
                            ui.close_menu();
                        }
                        if ui.button("📋 Copy Process Name").clicked() {
                            ui.output_mut(|o| o.copied_text = node.process_name);
                            ui.close_menu();
                        }
                    }
                } else {
                    if let Some(ip) = &node.remote_ip {
                        if ui.button("🚫 Block IP").clicked() {
                            crate::ui::block_ip(ip, node.pid.unwrap_or(0), &node.label, &monitor_state);
                            ui.close_menu();
                        }
                    }
                    if let Some(port) = node.remote_port {
                        if ui.button("🚫 Block Port").clicked() {
                            crate::ui::block_port(port, node.pid.unwrap_or(0), &node.label, &monitor_state);
                            ui.close_menu();
                        }
                    }
                    if ui.button("📋 Copy IP:Port").clicked() {
                        ui.output_mut(|o| o.copied_text = node.label);
                        ui.close_menu();
                    }
                }
                
                ui.separator();
                if ui.button("🔍 Focus on Node").clicked() {
                    if let Some(n) = self.get_selected() {
                        let zoom = *self.zoom.lock().unwrap();
                        *self.center_pos.lock().unwrap() = response.rect.center() - n.pos.to_vec2() * zoom;
                        *self.pan_offset.lock().unwrap() = Vec2::ZERO;
                    }
                    ui.close_menu();
                }
            }
        });
        
        let painter = ui.painter();
        
        for edge in edges.iter() {
            if let (Some(from), Some(to)) = (nodes.get(&edge.from), nodes.get(&edge.to)) {
                let from_pos = from.pos * zoom + pan;
                let to_pos = to.pos * zoom + pan;
                painter.add(Shape::line_segment(
                    [from_pos, to_pos],
                    Stroke::new(edge.thickness * zoom, edge.color),
                ));
            }
        }
        
        for (id, node) in nodes.iter() {
            let pos = node.pos * zoom + pan;
            let size = node.size * zoom;
            let is_selected = selected_id.as_ref() == Some(id);
            let is_hovered = hovered_id.as_ref() == Some(id);
            
            let fill_color = if is_selected {
                node.color.gamma_multiply(1.3)
            } else if is_hovered {
                node.color.gamma_multiply(1.15)
            } else {
                node.color
            };
            
            painter.add(Shape::circle_filled(pos, size, fill_color));
            
            if is_selected {
                painter.add(Shape::circle_stroke(pos, size + 4.0, Stroke::new(3.0 * zoom, Color32::YELLOW)));
            } else if is_hovered {
                painter.add(Shape::circle_stroke(pos, size + 2.0, Stroke::new(2.0 * zoom, Color32::WHITE)));
            } else {
                painter.add(Shape::circle_stroke(pos, size, Stroke::new(2.0 * zoom, Color32::WHITE)));
            }
            
            painter.text(
                pos + Vec2::new(0.0, size + 15.0 * zoom),
                Align2::CENTER_TOP,
                &node.label,
                FontId::proportional(10.0 * zoom.max(0.5)),
                Color32::WHITE,
            );
            
            if node.connections > 1 {
                painter.text(
                    pos + Vec2::new(0.0, size + 28.0 * zoom),
                    Align2::CENTER_TOP,
                    format!("{} conn", node.connections),
                    FontId::proportional(9.0 * zoom.max(0.5)),
                    Color32::GRAY,
                );
            }
        }
        
        let legend_y = rect.bottom() - 70.0;
        let legend_items = [
            (ConnectionType::Process, "Process"),
            (ConnectionType::Tcp, "TCP"),
            (ConnectionType::Browser, "Browser"),
            (ConnectionType::Local, "Local"),
        ];
        
        for (i, (ct, label)) in legend_items.iter().enumerate() {
            let x = rect.left() + 10.0 + (i as f32 * 100.0);
            let y = legend_y;
            painter.add(Shape::circle_filled(Pos2::new(x, y), 8.0, ct.color()));
            painter.text(
                Pos2::new(x + 15.0, y),
                Align2::LEFT_CENTER,
                label,
                FontId::proportional(10.0),
                Color32::WHITE,
            );
        }
        
        painter.text(
            Pos2::new(rect.right() - 10.0, rect.bottom() - 10.0),
            Align2::RIGHT_BOTTOM,
            "Click: select • Right-drag: pan • Scroll: zoom • Pinch: zoom • Right-click: menu",
            FontId::proportional(10.0),
            Color32::GRAY,
        );
        
        response
    }
}