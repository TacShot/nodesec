use anyhow::Result;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind, MouseEventKind, MouseButton},
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    ExecutableCommand,
    execute,
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, Borders, List, ListItem, Paragraph, Table, Row, Cell, Tabs},
    Frame, Terminal,
};
use std::io::{stdout, Stdout};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, Mutex};
use nodesec_core::{
    models::{NetworkConnection, NetworkProtocol, Platform},
    network::{linux::LinuxNetworkMonitor, macos::MacOSNetworkMonitor, windows::WindowsNetworkMonitor, common::NetworkMonitor},
};

const ORANGE: Color = Color::Rgb(255, 165, 0);
const GRAY: Color = Color::DarkGray;
const RED: Color = Color::Red;
const GREEN: Color = Color::Green;
const YELLOW: Color = Color::Yellow;

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

struct ConnectionItem {
    connection: NetworkConnection,
    threat_level: ThreatLevel,
}

impl Clone for ConnectionItem {
    fn clone(&self) -> Self {
        Self {
            connection: self.connection.clone(),
            threat_level: self.threat_level,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum ThreatLevel {
    Safe,
    Low,
    Medium,
    High,
    Critical,
}

impl ThreatLevel {
    fn color(&self) -> Color {
        match self {
            ThreatLevel::Safe => GREEN,
            ThreatLevel::Low => YELLOW,
            ThreatLevel::Medium => Color::Rgb(255, 165, 0),
            ThreatLevel::High => Color::Rgb(255, 100, 100),
            ThreatLevel::Critical => RED,
        }
    }
    
    fn label(&self) -> &'static str {
        match self {
            ThreatLevel::Safe => "SAFE",
            ThreatLevel::Low => "LOW",
            ThreatLevel::Medium => "MED",
            ThreatLevel::High => "HIGH",
            ThreatLevel::Critical => "CRIT",
        }
    }
}

fn threat_level_from_score(score: u8) -> ThreatLevel {
    match score {
        0..=25 => ThreatLevel::Safe,
        26..=49 => ThreatLevel::Low,
        50..=74 => ThreatLevel::Medium,
        75..=89 => ThreatLevel::High,
        _ => ThreatLevel::Critical,
    }
}

struct App {
    selected_tab: Tab,
    // Async data sources
    connections_arc: Arc<Mutex<Vec<ConnectionItem>>>,
    alerts_arc: Arc<Mutex<Vec<String>>>,
    stats_arc: Arc<Mutex<ConnectionStats>>,
    // Local cached copies for rendering (no locks needed)
    connections: Vec<ConnectionItem>,
    alerts: Vec<String>,
    stats: ConnectionStats,
    scroll_offset: usize,
    selected_connection: usize,
    running: bool,
    last_update: Instant,
    rx: mpsc::Receiver<NetworkConnection>,
    platform: Platform,
}

#[derive(Default, Clone)]
struct ConnectionStats {
    total: usize,
    active: usize,
    suspicious: usize,
    critical: usize,
    bytes_sent: u64,
    bytes_received: u64,
}

impl App {
    fn new(rx: mpsc::Receiver<NetworkConnection>, platform: Platform) -> Self {
        let connections_arc = Arc::new(Mutex::new(Vec::new()));
        let alerts_arc = Arc::new(Mutex::new(Vec::new()));
        let stats_arc = Arc::new(Mutex::new(ConnectionStats::default()));
        
        Self {
            selected_tab: Tab::Connections,
            connections_arc: connections_arc.clone(),
            alerts_arc: alerts_arc.clone(),
            stats_arc: stats_arc.clone(),
            connections: Vec::new(),
            alerts: Vec::new(),
            stats: ConnectionStats::default(),
            scroll_offset: 0,
            selected_connection: 0,
            running: true,
            last_update: Instant::now(),
            rx,
            platform,
        }
    }

    async fn refresh_data(&mut self) {
        // Lock and clone data for rendering
        self.connections = self.connections_arc.lock().await.clone();
        self.alerts = self.alerts_arc.lock().await.clone();
        self.stats = self.stats_arc.lock().await.clone();
    }

    async fn run(&mut self, terminal: &mut Terminal<CrosstermBackend<Stdout>>) -> Result<()> {
        let mut last_tick = Instant::now();
        
        loop {
            // Refresh data from async sources
            self.refresh_data().await;
            
            terminal.draw(|frame| self.render(frame))?;
            
            // Handle incoming connections
            while let Ok(conn) = self.rx.try_recv() {
                self.add_connection(conn).await;
            }
            
            // Handle events
            if event::poll(Duration::from_millis(50))? {
                match event::read()? {
                    Event::Key(key) => {
                        if key.kind == KeyEventKind::Press {
                            if self.handle_key(key.code).await? {
                                break;
                            }
                        }
                    }
                    Event::Mouse(mouse) => {
                        self.handle_mouse(mouse).await?;
                    }
                    _ => {}
                }
            }
            
            // Periodic stats update
            if last_tick.elapsed() >= Duration::from_secs(1) {
                self.update_stats().await;
                last_tick = Instant::now();
            }
        }
        Ok(())
    }
    
    async fn handle_key(&mut self, key: KeyCode) -> Result<bool> {
        match key {
            KeyCode::Char('q') | KeyCode::Esc => return Ok(true),
            KeyCode::Tab => {
                self.selected_tab = match self.selected_tab {
                    Tab::Connections => Tab::Alerts,
                    Tab::Alerts => Tab::Statistics,
                    Tab::Statistics => Tab::Settings,
                    Tab::Settings => Tab::Connections,
                };
            }
            KeyCode::BackTab => {
                self.selected_tab = match self.selected_tab {
                    Tab::Connections => Tab::Settings,
                    Tab::Alerts => Tab::Connections,
                    Tab::Statistics => Tab::Alerts,
                    Tab::Settings => Tab::Statistics,
                };
            }
            KeyCode::Up => {
                if self.scroll_offset > 0 {
                    self.scroll_offset -= 1;
                }
            }
            KeyCode::Down => {
                self.scroll_offset += 1;
            }
            KeyCode::PageUp => {
                self.scroll_offset = self.scroll_offset.saturating_sub(10);
            }
            KeyCode::PageDown => {
                self.scroll_offset += 10;
            }
            KeyCode::Enter => {
                // View connection details
            }
            KeyCode::Char(' ') => {
                // Pause/resume
            }
            KeyCode::Char('f') => {
                // Filter
            }
            KeyCode::Char('a') => {
                self.selected_tab = Tab::Alerts;
            }
            _ => {}
        }
        Ok(false)
    }

    async fn handle_mouse(&mut self, mouse: crossterm::event::MouseEvent) -> Result<()> {
        use crossterm::event::{MouseEventKind, MouseButton};
        
        match mouse.kind {
            MouseEventKind::Down(MouseButton::Left) => {
                // Handle left-click on tabs or table rows
                // For now, just handle tab switching via click
                if mouse.row == 0 {
                    // Click on tab bar area
                    let tab_width = 20; // Approximate tab width
                    let tab_index = mouse.column / tab_width;
                    self.selected_tab = match tab_index {
                        0 => Tab::Connections,
                        1 => Tab::Alerts,
                        2 => Tab::Statistics,
                        3 => Tab::Settings,
                        _ => self.selected_tab,
                    };
                }
            }
            MouseEventKind::ScrollUp => {
                if self.scroll_offset > 0 {
                    self.scroll_offset -= 3;
                }
            }
            MouseEventKind::ScrollDown => {
                self.scroll_offset += 3;
            }
            _ => {}
        }
        Ok(())
    }
    
    async fn add_connection(&mut self, conn: NetworkConnection) {
        let threat_level = threat_level_from_score(conn.threat_score);
        let is_suspicious = conn.is_suspicious;
        
        let mut connections = self.connections_arc.lock().await;
        connections.insert(0, ConnectionItem {
            connection: conn.clone(),
            threat_level,
        });
        
        // Keep only last 1000 connections
        if connections.len() > 1000 {
            connections.truncate(1000);
        }
        
        // Add alert if suspicious
        if is_suspicious {
            let mut alerts = self.alerts_arc.lock().await;
            alerts.insert(0, format!(
                "[{}] {} -> {}:{} (PID: {}, Score: {})",
                chrono::Local::now().format("%H:%M:%S"),
                conn.process_name,
                conn.dst_ip,
                conn.dst_port,
                conn.pid,
                conn.threat_score
            ));
            if alerts.len() > 100 {
                alerts.truncate(100);
            }
        }
        
        // Update stats
        let mut stats = self.stats_arc.lock().await;
        stats.total += 1;
        if is_suspicious {
            stats.suspicious += 1;
        }
        if threat_level == ThreatLevel::Critical {
            stats.critical += 1;
        }
    }
    
    async fn update_stats(&mut self) {
        let mut stats = self.stats_arc.lock().await;
        let connections = self.connections_arc.lock().await;
        stats.active = connections.len();
    }

    fn render(&mut self, frame: &mut Frame) {
        let area = frame.area();
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Length(3),
                Constraint::Min(10),
                Constraint::Length(3),
            ])
            .split(area);

        self.render_header(frame, chunks[0]);
        self.render_tabs(frame, chunks[1]);
        self.render_content(frame, chunks[2]);
        self.render_footer(frame, chunks[3]);
    }

    fn render_header(&self, frame: &mut Frame, area: Rect) {
        let status = if self.running { "LIVE" } else { "PAUSED" };
        let status_color = if self.running { GREEN } else { YELLOW };
        
        let scan_indicator = if self.last_update.elapsed().as_secs() < 3 {
            " ● SCANNING"
        } else {
            ""
        };
        
        let header = Paragraph::new(
            Line::from(vec![
                Span::styled("NODESEC NETWORK", Style::default().fg(ORANGE).add_modifier(Modifier::BOLD)),
                Span::raw("  "),
                Span::styled(format!("[{}]", status), Style::default().fg(status_color).add_modifier(Modifier::BOLD)),
                Span::styled(scan_indicator, Style::default().fg(YELLOW).add_modifier(Modifier::BOLD)),
                Span::raw("  "),
                Span::styled(format!("Platform: {:?}", self.platform), Style::default().fg(GRAY)),
                Span::raw("  "),
                Span::styled(format!("Connections: {}", self.stats.total), Style::default().fg(GRAY)),
            ])
        )
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(ORANGE)));
        
        frame.render_widget(header, area);
    }

    fn render_tabs(&self, frame: &mut Frame, area: Rect) {
        let tab_labels: Vec<&str> = [Tab::Connections, Tab::Alerts, Tab::Statistics, Tab::Settings]
            .iter()
            .map(|t| t.label())
            .collect();
        
        let tabs = Tabs::new(tab_labels)
            .select(self.selected_tab as usize)
            .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(Color::White)))
            .style(Style::default().fg(GRAY))
            .highlight_style(Style::default().fg(Color::White).bg(Color::Black).add_modifier(Modifier::BOLD))
            .divider(Span::raw(" | "));
        
        frame.render_widget(tabs, area);
    }

    fn render_content(&mut self, frame: &mut Frame, area: Rect) {
        match self.selected_tab {
            Tab::Connections => self.render_connections(frame, area),
            Tab::Alerts => self.render_alerts(frame, area),
            Tab::Statistics => self.render_statistics(frame, area),
            Tab::Settings => self.render_settings(frame, area),
        }
    }

    fn render_connections(&mut self, frame: &mut Frame, area: Rect) {
        let rows: Vec<Row> = self.connections
            .iter()
            .skip(self.scroll_offset)
            .take(area.height as usize - 2)
            .enumerate()
            .map(|(i, item)| {
                let conn = &item.connection;
                let threat_color = item.threat_level.color();
                
                let src = format!("{}:{}", conn.src_ip, conn.src_port);
                let dst = format!("{}:{}", conn.dst_ip, conn.dst_port);
                let proto = format!("{:?}", conn.protocol);
                
                let selected = i == self.selected_connection;
                let style = if selected {
                    Style::default().fg(Color::White).bg(Color::Black).add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(GRAY)
                };
                
                Row::new(vec![
                    Cell::from(conn.pid.to_string()),
                    Cell::from(conn.process_name.clone()),
                    Cell::from(proto),
                    Cell::from(src),
                    Cell::from(dst),
                    Cell::from(item.threat_level.label()).style(Style::default().fg(threat_color)),
                    Cell::from(conn.threat_score.to_string()).style(Style::default().fg(threat_color)),
                ]).style(style)
            })
            .collect();
        
        let header = Row::new(vec![
            Cell::from("PID").style(Style::default().fg(ORANGE).add_modifier(Modifier::BOLD)),
            Cell::from("Process").style(Style::default().fg(ORANGE).add_modifier(Modifier::BOLD)),
            Cell::from("Proto").style(Style::default().fg(ORANGE).add_modifier(Modifier::BOLD)),
            Cell::from("Source").style(Style::default().fg(ORANGE).add_modifier(Modifier::BOLD)),
            Cell::from("Destination").style(Style::default().fg(ORANGE).add_modifier(Modifier::BOLD)),
            Cell::from("Threat").style(Style::default().fg(ORANGE).add_modifier(Modifier::BOLD)),
            Cell::from("Score").style(Style::default().fg(ORANGE).add_modifier(Modifier::BOLD)),
        ]);
        
        let table = Table::new(rows, [
            Constraint::Length(6),
            Constraint::Length(20),
            Constraint::Length(6),
            Constraint::Length(20),
            Constraint::Length(20),
            Constraint::Length(6),
            Constraint::Length(6),
        ])
        .header(header)
        .block(Block::default()
            .borders(Borders::ALL)
            .title("Live Connections")
            .border_style(Style::default().fg(Color::White)))
        .column_spacing(1);
        
        frame.render_widget(table, area);
    }

    fn render_alerts(&self, frame: &mut Frame, area: Rect) {
        let items: Vec<ListItem> = if self.alerts.is_empty() {
            vec![ListItem::new("No alerts")]
        } else {
            self.alerts.iter().map(|alert| {
                ListItem::new(Line::from(Span::styled(alert, Style::default().fg(RED))))
            }).collect()
        };
        
        let list = List::new(items)
            .block(Block::default()
                .borders(Borders::ALL)
                .title("Threat Alerts")
                .border_style(Style::default().fg(RED)));
        
        frame.render_widget(list, area);
    }

    fn render_statistics(&self, frame: &mut Frame, area: Rect) {
        let mut counts = std::collections::HashMap::new();
        for item in &self.connections {
            *counts.entry(item.threat_level).or_insert(0) += 1;
        }
        
        let text = vec![
            Line::from(vec![
                Span::styled("Total Connections: ", Style::default().fg(ORANGE)),
                Span::styled(self.stats.total.to_string(), Style::default().fg(Color::White)),
            ]),
            Line::from(vec![
                Span::styled("Active Connections: ", Style::default().fg(ORANGE)),
                Span::styled(self.stats.active.to_string(), Style::default().fg(Color::White)),
            ]),
            Line::from(vec![
                Span::styled("Suspicious: ", Style::default().fg(ORANGE)),
                Span::styled(self.stats.suspicious.to_string(), Style::default().fg(RED)),
            ]),
            Line::from(vec![
                Span::styled("Critical: ", Style::default().fg(ORANGE)),
                Span::styled(self.stats.critical.to_string(), Style::default().fg(RED)),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::styled("Threat Distribution:", Style::default().fg(ORANGE).add_modifier(Modifier::BOLD)),
            ]),
            Line::from(vec![
                Span::styled("  Safe: ", Style::default().fg(GREEN)),
                Span::styled(counts.get(&ThreatLevel::Safe).unwrap_or(&0).to_string(), Style::default().fg(Color::White)),
            ]),
            Line::from(vec![
                Span::styled("  Low: ", Style::default().fg(YELLOW)),
                Span::styled(counts.get(&ThreatLevel::Low).unwrap_or(&0).to_string(), Style::default().fg(Color::White)),
            ]),
            Line::from(vec![
                Span::styled("  Medium: ", Style::default().fg(Color::Rgb(255, 165, 0))),
                Span::styled(counts.get(&ThreatLevel::Medium).unwrap_or(&0).to_string(), Style::default().fg(Color::White)),
            ]),
            Line::from(vec![
                Span::styled("  High: ", Style::default().fg(Color::Rgb(255, 100, 100))),
                Span::styled(counts.get(&ThreatLevel::High).unwrap_or(&0).to_string(), Style::default().fg(Color::White)),
            ]),
            Line::from(vec![
                Span::styled("  Critical: ", Style::default().fg(RED)),
                Span::styled(counts.get(&ThreatLevel::Critical).unwrap_or(&0).to_string(), Style::default().fg(Color::White)),
            ]),
        ];
        
        let paragraph = Paragraph::new(text)
            .block(Block::default()
                .borders(Borders::ALL)
                .title("Statistics")
                .border_style(Style::default().fg(Color::White)));
        
        frame.render_widget(paragraph, area);
    }

    fn render_settings(&self, frame: &mut Frame, area: Rect) {
        let text = vec![
            Line::from(vec![
                Span::styled("Network Monitoring Settings", Style::default().fg(ORANGE).add_modifier(Modifier::BOLD)),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::styled("Platform: ", Style::default().fg(ORANGE)),
                Span::styled(format!("{:?}", self.platform), Style::default().fg(Color::White)),
            ]),
            Line::from(vec![
                Span::styled("Update Interval: ", Style::default().fg(ORANGE)),
                Span::styled("2 seconds", Style::default().fg(Color::White)),
            ]),
            Line::from(vec![
                Span::styled("Threat Threshold: ", Style::default().fg(ORANGE)),
                Span::styled("50", Style::default().fg(Color::White)),
            ]),
            Line::from(vec![
                Span::styled("Max Connections: ", Style::default().fg(ORANGE)),
                Span::styled("1000", Style::default().fg(Color::White)),
            ]),
            Line::from(vec![
                Span::styled("Retention: ", Style::default().fg(ORANGE)),
                Span::styled("5 minutes", Style::default().fg(Color::White)),
            ]),
            Line::from(""),
            Line::from("Press 'q' to quit, Tab to switch tabs"),
        ];
        
        let paragraph = Paragraph::new(text)
            .block(Block::default()
                .borders(Borders::ALL)
                .title("Settings")
                .border_style(Style::default().fg(Color::White)))
            .wrap(ratatui::widgets::Wrap { trim: true });
        
        frame.render_widget(paragraph, area);
    }

    fn render_footer(&self, frame: &mut Frame, area: Rect) {
        let footer = Paragraph::new(
            Line::from(vec![
                Span::styled("Tab/Shift+Tab: Switch tabs  ", Style::default().fg(GRAY)),
                Span::styled("↑/↓: Scroll  ", Style::default().fg(GRAY)),
                Span::styled("Space: Pause  ", Style::default().fg(GRAY)),
                Span::styled("a: Alerts  ", Style::default().fg(GRAY)),
                Span::styled("q: Quit", Style::default().fg(GRAY)),
            ])
        )
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(GRAY)));
        
        frame.render_widget(footer, area);
    }
}

pub async fn run_net_tui(interface: Option<String>, interval: u64) -> Result<()> {
    enable_raw_mode()?;
    execute!(stdout(), EnterAlternateScreen, crossterm::event::EnableMouseCapture)?;

    let backend = CrosstermBackend::new(stdout());
    let mut terminal = Terminal::new(backend)?;
    
    // Create network monitor
    let platform = Platform::detect();
    let monitor: Box<dyn NetworkMonitor> = match platform {
        Platform::Linux => Box::new(LinuxNetworkMonitor::new()),
        Platform::MacOS => Box::new(MacOSNetworkMonitor::new()),
        Platform::Windows => Box::new(WindowsNetworkMonitor::new()),
        Platform::Unknown => Box::new(LinuxNetworkMonitor::new()),
    };
    
    // Wrap monitor in Arc<Mutex> for sharing with scan task
    let monitor = Arc::new(Mutex::new(monitor));
    
    // Start monitoring
    let (tx, rx) = mpsc::channel(1000);
    {
        let mut m = monitor.lock().await;
        let _ = m.start().await;
    }
    
    // Spawn monitoring task
    let monitor_clone = monitor.clone();
    let tx_clone = tx.clone();
    tokio::spawn(async move {
        let mut interval_timer = tokio::time::interval(Duration::from_secs(interval));
        loop {
            interval_timer.tick().await;
            
            // Scan for new connections
            {
                let mut m = monitor_clone.lock().await;
                if let Err(e) = m.scan_once().await {
                    eprintln!("Scan error: {}", e);
                }
            }
            
            // Drain events and send to TUI
            let events = {
                let m = monitor_clone.lock().await;
                m.drain_events().await
            };
            
            for event in events {
                if tx_clone.send(event).await.is_err() {
                    break; // Channel closed
                }
            }
        }
    });
    
    let mut app = App::new(rx, Platform::detect());
        let result = app.run(&mut terminal).await;

        // Stop monitor
        {
            let mut m = monitor.lock().await;
            let _ = m.stop().await;
        }

        disable_raw_mode()?;
        execute!(stdout(), LeaveAlternateScreen, crossterm::event::DisableMouseCapture)?;

        result
    }

fn main() -> Result<()> {
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(run_net_tui(None, 2))
}