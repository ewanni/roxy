//! Application state management

use crate::config::Config;
use crate::server::ServerMetrics;
use crate::tui::AppEvent;
use crate::tui::screens::dashboard::DashboardData;
use crate::tui::screens::users::UsersScreen;
use anyhow::Result;
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio::sync::RwLock;
use uuid::Uuid;
use chrono::Utc;

#[cfg(feature = "tui-remote")]
use reqwest;

/// Remote metrics response from server /metrics endpoint
#[cfg(feature = "tui-remote")]
#[derive(Debug, Clone, serde::Deserialize)]
pub struct MetricsResponse {
    pub active_connections: usize,
    pub total_bytes_sent: u64,
    pub total_bytes_received: u64,
    pub uptime_seconds: u64,
    pub sessions: Vec<SessionSnapshot>,
}

/// Session snapshot from remote metrics
#[cfg(feature = "tui-remote")]
#[derive(Debug, Clone, serde::Deserialize)]
pub struct SessionSnapshot {
    pub username: String,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub duration_seconds: u64,
}

/// Source of metrics data
#[derive(Debug, Clone)]
pub enum MetricsSource {
    /// Local metrics from shared state
    Local(Arc<RwLock<ServerMetrics>>),
    /// Remote metrics from HTTP endpoint (stub for future implementation)
    Remote(String),
}

/// Main application state
#[derive(Debug)]
pub struct App {
    pub current_screen: Screen,
    pub should_quit: bool,
    pub server_state: ServerState,
    pub client_connections: Vec<ClientConnection>,
    pub users: Vec<UserInfo>,
    pub logs: VecDeque<LogEntry>,
    pub metrics: MetricsHistory,
    pub event_rx: mpsc::Receiver<ControllerEvent>,
    // New fields for Roadmap Step 2.3
    pub metrics_source: MetricsSource,
    pub dashboard_data: DashboardData,
    pub users_screen: UsersScreen,
    pub refresh_interval: Duration,
}

/// Screen enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    Dashboard,
    ServerManagement,
    ClientManagement,
    UserManagement,
    UserAdd,
    UserEdit(usize),
    UserDelete(usize),
    LogsViewer,
    ConfigEditor,
}

/// Server state
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerState {
    Stopped,
    Starting,
    Running {
        started_at: Instant,
        active_connections: usize,
    },
    Stopping,
    Error(String),
}

/// Client connection info
#[derive(Debug, Clone)]
pub struct ClientConnection {
    pub id: Uuid,
    pub username: String,
    pub remote_addr: String,
    pub connected_at: Instant,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub granted_routes: Vec<String>,
}

/// User info (mirrors config::User)
#[derive(Debug, Clone)]
pub struct UserInfo {
    pub username: String,
    pub active: bool,
    pub allowed_routes: Vec<String>,
    pub expires_at: Option<String>,
    pub bandwidth_limit_mbps: Option<u32>,
}

/// Log entry
#[derive(Debug, Clone)]
pub struct LogEntry {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub level: LogLevel,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

/// Metrics history (last 60 seconds)
#[derive(Debug, Default)]
pub struct MetricsHistory {
    pub bandwidth_in: Vec<(Instant, f64)>,
    pub bandwidth_out: Vec<(Instant, f64)>,
    pub connection_count: Vec<(Instant, usize)>,
    pub cpu_usage: Vec<(Instant, f32)>,
}

/// Events from controllers to app
#[derive(Debug)]
pub enum ControllerEvent {
    ServerStarted,
    ServerStopped,
    ServerError(String),
    ConnectionEstablished(ClientConnection),
    ConnectionClosed(Uuid),
    MetricsUpdate(MetricsSnapshot),
    LogEntry(LogEntry),
    UserAdded(String),
    UserDeleted(String),
    ConfigReloaded,
}

#[derive(Debug, Clone)]
pub struct MetricsSnapshot {
    pub timestamp: Instant,
    pub active_connections: usize,
    pub bandwidth_in_bps: f64,
    pub bandwidth_out_bps: f64,
    pub cpu_percent: f32,
}

impl App {
    pub fn new(config: &Config, remote: Option<String>) -> Result<Self> {
        let (_controller_tx, controller_rx) = mpsc::channel::<ControllerEvent>(100);

        // Use default localhost:9090 if remote is not specified
        let remote_url = remote.unwrap_or_else(|| "http://127.0.0.1:9090".to_string());
        let metrics_source = MetricsSource::Remote(remote_url);

        Ok(Self {
            current_screen: Screen::Dashboard,
            should_quit: false,
            server_state: ServerState::Stopped,
            client_connections: Vec::new(),
            users: Vec::new(),
            logs: VecDeque::with_capacity(1000),
            metrics: MetricsHistory::default(),
            event_rx: controller_rx,
            // New fields for Roadmap Step 2.3
            metrics_source,
            dashboard_data: DashboardData::default(),
            users_screen: UsersScreen::new(config),
            refresh_interval: Duration::from_secs(1),
        })
    }

    /// Refresh dashboard data from metrics source
    pub async fn refresh_data(&mut self) -> Result<()> {
        let metrics = match &self.metrics_source {
            MetricsSource::Local(m) => m.read().await.clone(),
            #[cfg(feature = "tui-remote")]
            MetricsSource::Remote(url) => {
                self.fetch_remote_metrics(url).await?
            }
            #[cfg(not(feature = "tui-remote"))]
            MetricsSource::Remote(_) => {
                ServerMetrics::default()
            }
        };
        self.dashboard_data = DashboardData::from(metrics);
        Ok(())
    }

    /// Fetch metrics from remote HTTP endpoint
    #[cfg(feature = "tui-remote")]
    async fn fetch_remote_metrics(&self, url: &str) -> Result<ServerMetrics> {
        let client = reqwest::Client::new();
        let resp = client
            .get(format!("{}/metrics", url))
            .timeout(Duration::from_secs(5))
            .send()
            .await?
            .error_for_status()?
            .json::<MetricsResponse>()
            .await?;

        let metrics = ServerMetrics {
            active_connections: resp.active_connections,
            total_bytes_sent: resp.total_bytes_sent,
            total_bytes_received: resp.total_bytes_received,
            uptime_seconds: resp.uptime_seconds,
            active_sessions: resp.sessions.into_iter().map(|snap| {
                // Calculate connected_at from duration
                let connected_at = Utc::now() - chrono::Duration::seconds(snap.duration_seconds as i64);
                (Uuid::nil(), crate::server::SessionInfo {
                    username: snap.username,
                    connected_at,
                    bytes_sent: snap.bytes_sent,
                    bytes_received: snap.bytes_received,
                    remote_addr: "unknown".to_string(),
                })
            }).collect(),
        };

        Ok(metrics)
    }

    pub async fn run(&mut self) -> Result<()> {
        use crate::tui::events::handle_events;
        use crossterm::{
            execute,
            terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
        };
        use ratatui::{backend::CrosstermBackend, Terminal};
        use std::io;

        // Setup terminal
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen)?;
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;

        // Main loop: refresh, handle events, render
        let mut last_refresh = Instant::now();
        let mut last_render = Instant::now();

        while !self.should_quit {
            // Periodic data refresh
            if last_refresh.elapsed() >= self.refresh_interval {
                if let Err(e) = self.refresh_data().await {
                    tracing::error!("Failed to refresh data: {}", e);
                }
                last_refresh = Instant::now();
            }

            // Handle events
            if let Some(event) = handle_events().await? {
                self.handle_app_event(event);
            }

            // Handle controller events
            if let Ok(ctrl_event) = self.event_rx.try_recv() {
                self.handle_controller_event(ctrl_event);
            }

            // Render at most 30 FPS
            if last_render.elapsed() >= Duration::from_millis(33) {
                terminal.draw(|f| crate::tui::ui::render(f, self))?;
                last_render = Instant::now();
            }
        }

        // Cleanup
        disable_raw_mode()?;
        execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
        terminal.show_cursor()?;

        Ok(())
    }

    fn handle_app_event(&mut self, event: AppEvent) {
        match event {
            AppEvent::Quit => {
                self.should_quit = true;
            }
            AppEvent::Refresh => {
                // Trigger refresh - will re-render on next tick
            }
            AppEvent::NextScreen => {
                self.navigate_next();
            }
            AppEvent::PrevScreen => {
                self.navigate_prev();
            }
            AppEvent::UserManagement => {
                self.current_screen = Screen::UserManagement;
            }
            AppEvent::SelectNext => {
                if matches!(self.current_screen, Screen::UserManagement) {
                    self.users_screen.select_next();
                }
            }
            AppEvent::SelectPrev => {
                if matches!(self.current_screen, Screen::UserManagement) {
                    self.users_screen.select_prev();
                }
            }
        }
    }

    fn handle_controller_event(&mut self, event: ControllerEvent) {
        match event {
            ControllerEvent::ServerStarted => {
                self.server_state = ServerState::Running {
                    started_at: Instant::now(),
                    active_connections: 0,
                };
            }
            ControllerEvent::ServerStopped => {
                self.server_state = ServerState::Stopped;
            }
            ControllerEvent::ServerError(msg) => {
                self.server_state = ServerState::Error(msg);
            }
            ControllerEvent::ConnectionEstablished(conn) => {
                self.client_connections.push(conn);
            }
            ControllerEvent::ConnectionClosed(id) => {
                self.client_connections.retain(|c| c.id != id);
            }
            ControllerEvent::MetricsUpdate(snapshot) => {
                let now = Instant::now();
                self.metrics.bandwidth_in.push((now, snapshot.bandwidth_in_bps));
                self.metrics.bandwidth_out.push((now, snapshot.bandwidth_out_bps));
                self.metrics.connection_count.push((now, snapshot.active_connections));
                self.metrics.cpu_usage.push((now, snapshot.cpu_percent));

                // Keep only last 60 seconds of data
                let cutoff = now - Duration::from_secs(60);
                self.metrics.bandwidth_in.retain(|&(t, _)| t > cutoff);
                self.metrics.bandwidth_out.retain(|&(t, _)| t > cutoff);
                self.metrics.connection_count.retain(|&(t, _)| t > cutoff);
                self.metrics.cpu_usage.retain(|&(t, _)| t > cutoff);
            }
            ControllerEvent::LogEntry(entry) => {
                self.logs.push_front(entry);
                if self.logs.len() > 1000 {
                    self.logs.pop_back();
                }
            }
            ControllerEvent::UserAdded(username) => {
                self.users.push(UserInfo {
                    username,
                    active: true,
                    allowed_routes: Vec::new(),
                    expires_at: None,
                    bandwidth_limit_mbps: None,
                });
            }
            ControllerEvent::UserDeleted(username) => {
                self.users.retain(|u| u.username != username);
            }
            ControllerEvent::ConfigReloaded => {
                // Config reloaded signal
            }
        }
    }

    fn navigate_next(&mut self) {
        self.current_screen = match self.current_screen {
            Screen::Dashboard => Screen::ServerManagement,
            Screen::ServerManagement => Screen::ClientManagement,
            Screen::ClientManagement => Screen::UserManagement,
            Screen::UserManagement => Screen::LogsViewer,
            Screen::LogsViewer => Screen::ConfigEditor,
            Screen::ConfigEditor => Screen::Dashboard,
            Screen::UserAdd => Screen::UserManagement,
            Screen::UserEdit(_) => Screen::UserManagement,
            Screen::UserDelete(_) => Screen::UserManagement,
        };
    }

    fn navigate_prev(&mut self) {
        self.current_screen = match self.current_screen {
            Screen::Dashboard => Screen::ConfigEditor,
            Screen::ServerManagement => Screen::Dashboard,
            Screen::ClientManagement => Screen::ServerManagement,
            Screen::UserManagement => Screen::ClientManagement,
            Screen::LogsViewer => Screen::UserManagement,
            Screen::ConfigEditor => Screen::LogsViewer,
            Screen::UserAdd => Screen::UserManagement,
            Screen::UserEdit(_) => Screen::UserManagement,
            Screen::UserDelete(_) => Screen::UserManagement,
        };
    }
}