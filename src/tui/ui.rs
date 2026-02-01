//! UI rendering

use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Paragraph},
    Frame,
};
use super::app::{App, Screen, ServerState};

pub fn render(f: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(3),
        ])
        .split(f.size());
    
    render_title_bar(f, chunks[0], app);
    
    match app.current_screen {
        Screen::Dashboard => {
            let data = super::screens::dashboard::DashboardData::from(app);
            super::screens::dashboard::render_dashboard(f, chunks[1], &data);
        }
        Screen::UserManagement => {
            app.users_screen.render(f, chunks[1]);
        }
        _ => {
            let placeholder = Paragraph::new("Screen not implemented yet")
                .block(Block::default().borders(Borders::ALL));
            f.render_widget(placeholder, chunks[1]);
        }
    }
    
    render_status_bar(f, chunks[2], app);
}

fn render_title_bar(f: &mut Frame, area: Rect, _app: &App) {
    let title = Paragraph::new("ROXY DPI Bypass Server - TUI")
        .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
        .block(Block::default().borders(Borders::ALL));
    f.render_widget(title, area);
}

fn render_status_bar(f: &mut Frame, area: Rect, app: &App) {
    let status = match &app.server_state {
        ServerState::Stopped => "Stopped".to_string(),
        ServerState::Starting => "Starting...".to_string(),
        ServerState::Running { active_connections, .. } => {
            format!("Running | Connections: {}", active_connections)
        }
        ServerState::Stopping => "Stopping...".to_string(),
        ServerState::Error(err) => format!("Error: {}", err),
    };
    
    let help = match app.current_screen {
        Screen::Dashboard => "[F1-F5] Navigate | [Q] Quit",
        Screen::ServerManagement => "[S] Start | [T] Stop | [ESC] Back",
        Screen::UserManagement => "[A] Add | [ESC] Back | [Q] Quit",
        _ => "[ESC] Back | [Q] Quit",
    };
    
    let text = format!("{} | {}", status, help);
    let widget = Paragraph::new(text)
        .style(Style::default().fg(Color::White).bg(Color::DarkGray));
    f.render_widget(widget, area);
}
