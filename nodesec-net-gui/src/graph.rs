//! Connection graph visualization for network monitoring

use egui::{Color32, Pos2, Shape, Stroke, Vec2};
use nodesec_core::models::NetworkConnection;
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

#[derive(Debug, Clone)]
struct GraphNode {
    id: String,
    label: String,
    pos: Pos2,
    color: Color32,
    size: f32,
    is_process: bool,
    threat_score: u8,
    connections: usize,
}

#[derive(Debug, Clone)]
struct GraphEdge {
    from: String,
    to: String,
    color: Color32,
    thickness: f32,
}

pub struct ConnectionGraph {
    pub nodes: Mutex<HashMap<String, GraphNode>>,
    pub edges: Mutex<Vec<GraphEdge>>,
    layout_iteration: Mutex<usize>,
}

impl ConnectionGraph {
    pub fn new() -> Self {
        Self {
            nodes: Mutex::new(HashMap::new()),
            edges: Mutex::new(Vec::new()),
            layout_iteration: Mutex::new(0),
        }
    }
    
    pub fn update(&self, connections: &[crate::state::ConnectionItem]) {
        let mut nodes = self.nodes.lock().unwrap();
        let mut edges = self.edges.lock().unwrap();
        
        // Clear old data
        nodes.clear();
        edges.clear();
        
        // Group connections by process
        let mut process_connections: HashMap<u32, Vec<&NetworkConnection>> = HashMap::new();
        for item in connections {
            process_connections
                .entry(item.connection.pid)
                .or_default()
                .push(&item.connection);
        }
        
        // Create process nodes
        for (pid, conns) in &process_connections {
            let first = conns[0];
            let avg_threat = conns.iter().map(|c| c.threat_score as u32).sum::<u32>() / conns.len() as u32;
            let is_suspicious = conns.iter().any(|c| c.is_suspicious);
            
            let color = if is_suspicious {
                if avg_threat > 75 { Color32::RED } else { Color32::from_rgb(255, 165, 0) }
            } else {
                Color32::GREEN
            };
            
            let node = GraphNode {
                id: format!("proc_{}", pid),
                label: format!("{} (PID: {})", first.process_name, pid),
                pos: Pos2::ZERO, // Will be set by layout
                color,
                size: 30.0 + (conns.len() as f32 * 2.0).min(50.0),
                is_process: true,
                threat_score: avg_threat as u8,
                connections: conns.len(),
            };
            nodes.insert(node.id.clone(), node);
        }
        
        // Create remote host nodes and edges
        let mut remote_hosts: HashMap<String, (String, u16, Vec<&NetworkConnection>)> = HashMap::new();
        
        for item in connections {
            let conn = &item.connection;
            let remote_key = format!("{}:{}", conn.dst_ip, conn.dst_port);
            remote_hosts
                .entry(remote_key.clone())
                .or_insert_with(|| (conn.dst_ip.to_string(), conn.dst_port, Vec::new()))
                .2.push(conn);
        }
        
        for (key, (ip, port, conns)) in remote_hosts {
            let avg_threat = conns.iter().map(|c| c.threat_score as u32).sum::<u32>() / conns.len() as u32;
            let is_suspicious = conns.iter().any(|c| c.is_suspicious);
            
            let color = if is_suspicious {
                if avg_threat > 75 { Color32::RED } else { Color32::from_rgb(255, 165, 0) }
            } else {
                Color32::from_rgb(100, 200, 255)
            };
            
            let node = GraphNode {
                id: format!("host_{}", key),
                label: format!("{}:{}", ip, port),
                pos: Pos2::ZERO,
                color,
                size: 20.0,
                is_process: false,
                threat_score: avg_threat as u8,
                connections: conns.len(),
            };
            nodes.insert(node.id.clone(), node);
            
            // Create edges from processes to this host
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
        
        // Run force-directed layout
        self.run_layout(&mut nodes, &edges);
    }
    
    fn run_layout(&self, nodes: &mut HashMap<String, GraphNode>, edges: &[GraphEdge]) {
        // Simple force-directed layout (Fruchterman-Reingold inspired)
        let center = Pos2::new(400.0, 300.0);
        let k = 150.0; // Optimal distance
        
        // Initialize positions in a circle
        let node_count = nodes.len() as f32;
        for (i, (_, node)) in nodes.iter_mut().enumerate() {
            let angle = (i as f32 / node_count) * 2.0 * std::f32::consts::PI;
            node.pos = Pos2::new(
                center.x + angle.cos() * 200.0,
                center.y + angle.sin() * 200.0,
            );
        }
        
        // Run iterations
        for _ in 0..50 {
            // Repulsion between all nodes
            let node_ids: Vec<String> = nodes.keys().cloned().collect();
            for i in 0..node_ids.len() {
                for j in (i + 1)..node_ids.len() {
                    let id1 = &node_ids[i];
                    let id2 = &node_ids[j];
                    
                    if let (Some(n1), Some(n2)) = (nodes.get(id1), nodes.get(id2)) {
                        let diff = n2.pos - n1.pos;
                        let dist = diff.length().max(1.0);
                        let force = k * k / dist;
                        let dir = diff / dist;
                        
                        if let Some(n1_mut) = nodes.get_mut(id1) {
                            n1_mut.pos -= dir * force * 0.01;
                        }
                        if let Some(n2_mut) = nodes.get_mut(id2) {
                            n2_mut.pos += dir * force * 0.01;
                        }
                    }
                }
            }
            
            // Attraction along edges
            for edge in edges {
                if let (Some(n1), Some(n2)) = (nodes.get(&edge.from), nodes.get(&edge.to)) {
                    let diff = n2.pos - n1.pos;
                    let dist = diff.length().max(1.0);
                    let force = dist * dist / k;
                    let dir = diff / dist;
                    
                    if let Some(n1_mut) = nodes.get_mut(&edge.from) {
                        n1_mut.pos += dir * force * 0.01;
                    }
                    if let Some(n2_mut) = nodes.get_mut(&edge.to) {
                        n2_mut.pos -= dir * force * 0.01;
                    }
                }
            }
            
            // Center gravity
            for (_, node) in nodes.iter_mut() {
                let to_center = center - node.pos;
                let dist = to_center.length();
                if dist > 300.0 {
                    node.pos += to_center * 0.05;
                }
            }
        }
        
        // Increment layout iteration for animation
        *self.layout_iteration.lock().unwrap() += 1;
    }
    
    pub fn render(&self, ui: &mut egui::Ui, _rect: egui::Rect) {
        let nodes = self.nodes.lock().unwrap();
        let edges = self.edges.lock().unwrap();
        
        if nodes.is_empty() {
            ui.centered_and_justified(|ui| {
                ui.label("No connections to display. Start monitoring to see the graph.");
            });
            return;
        }
        
        let painter = ui.painter();
        
        // Draw edges
        for edge in edges.iter() {
            if let (Some(from), Some(to)) = (nodes.get(&edge.from), nodes.get(&edge.to)) {
                painter.add(Shape::line_segment(
                    [from.pos, to.pos],
                    Stroke::new(edge.thickness, edge.color),
                ));
            }
        }
        
        // Draw nodes
        for node in nodes.values() {
            let circle = Shape::circle_filled(node.pos, node.size, node.color);
            painter.add(circle);
            
            // Draw border
            painter.add(Shape::circle_stroke(
                node.pos, 
                node.size, 
                Stroke::new(2.0, Color32::WHITE),
            ));
            
            // Draw label
            painter.text(
                node.pos + Vec2::new(0.0, node.size + 15.0),
                egui::Align2::CENTER_TOP,
                &node.label,
                egui::FontId::proportional(10.0),
                Color32::WHITE,
            );
            
            // Draw connection count
            if node.connections > 1 {
                painter.text(
                    node.pos + Vec2::new(0.0, node.size + 28.0),
                    egui::Align2::CENTER_TOP,
                    format!("{} connections", node.connections),
                    egui::FontId::proportional(9.0),
                    Color32::GRAY,
                );
            }
        }
    }
}