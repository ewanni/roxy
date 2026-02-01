//! Dashboard screen

use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Paragraph, List, ListItem},
};
use crate::server::ServerMetrics;
use crate::tui::app::App;

/// Dashboard data structure for rendering
#[derive(Clone, Debug, Default)]
pub struct DashboardData {
    pub uptime: u64,
    pub active_connections: usize,
    pub total_bytes_sent: u64,
    pub total_bytes_received: u64,
    pub sessions: Vec<SessionInfo>,
}

/// Session information for dashboard display
#[derive(Clone, Debug)]
pub struct SessionInfo {
    pub username: String,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub connected_at: String,
}

/// Convert App state to DashboardData
impl From<&App> for DashboardData {
    fn from(app: &App) -> Self {
        let uptime = match &app.server_state {
            crate::tui::app::ServerState::Running { started_at, .. } => {
                started_at.elapsed().as_secs()
            }
            _ => 0,
        };

        let total_bytes_sent: u64 = app.client_connections.iter().map(|c| c.bytes_sent).sum();
        let total_bytes_received: u64 = app.client_connections.iter().map(|c| c.bytes_received).sum();

        let sessions: Vec<SessionInfo> = app.client_connections
            .iter()
            .map(|c| SessionInfo {
                username: c.username.clone(),
                bytes_sent: c.bytes_sent,
                bytes_received: c.bytes_received,
                connected_at: c.connected_at.elapsed().as_secs().to_string(),
            })
            .collect();

        DashboardData {
            uptime,
            active_connections: app.client_connections.len(),
            total_bytes_sent,
            total_bytes_received,
            sessions,
        }
    }
}

/// Convert ServerMetrics to DashboardData
impl From<ServerMetrics> for DashboardData {
    fn from(metrics: ServerMetrics) -> Self {
        let sessions: Vec<SessionInfo> = metrics
            .active_sessions
            .values()
            .map(|s| SessionInfo {
                username: s.username.clone(),
                bytes_sent: s.bytes_sent,
                bytes_received: s.bytes_received,
                connected_at: s.connected_at.to_string(),
            })
            .collect();

        DashboardData {
            uptime: metrics.uptime_seconds,
            active_connections: metrics.active_connections,
            total_bytes_sent: metrics.total_bytes_sent,
            total_bytes_received: metrics.total_bytes_received,
            sessions,
        }
    }
}

/// Render the dashboard screen
pub fn render_dashboard(frame: &mut Frame, area: Rect, data: &DashboardData) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(10),
            Constraint::Length(3),
        ])
        .split(area);

    // Header
    let header = Paragraph::new(format!(
        "ROXY Server Monitor | Uptime: {}s | Connections: {}",
        data.uptime, data.active_connections
    ))
    .block(Block::default().borders(Borders::ALL).title("Status"));
    frame.render_widget(header, chunks[0]);

    let main_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(50),
            Constraint::Percentage(50),
        ])
        .split(chunks[1]);

    render_metrics(frame, main_chunks[0], data);
    render_sessions(frame, main_chunks[1], data);

    let footer = Paragraph::new("q: Quit | r: Refresh | u: Users | s: Settings")
        .block(Block::default().borders(Borders::ALL));
    frame.render_widget(footer, chunks[2]);
}

/// Render metrics panel
fn render_metrics(frame: &mut Frame, area: Rect, data: &DashboardData) {
    let metrics_text = format!(
        "Bytes Sent: {} MB\nBytes Received: {} MB\nTotal Sessions: {}",
        data.total_bytes_sent / 1_000_000,
        data.total_bytes_received / 1_000_000,
        data.sessions.len()
    );
    let metrics = Paragraph::new(metrics_text)
        .block(Block::default().borders(Borders::ALL).title("Metrics"));
    frame.render_widget(metrics, area);
}

/// Render active sessions list
fn render_sessions(frame: &mut Frame, area: Rect, data: &DashboardData) {
    let sessions: Vec<ListItem<'_>> = data
        .sessions
        .iter()
        .map(|s| {
            ListItem::new(format!(
                "{} | Sent: {} MB | Rx: {} MB | {}s",
                s.username,
                s.bytes_sent / 1_000_000,
                s.bytes_received / 1_000_000,
                s.connected_at
            ))
        })
        .collect();
    let list = List::new(sessions)
        .block(Block::default().borders(Borders::ALL).title("Active Sessions"));
    frame.render_widget(list, area);
}