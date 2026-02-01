use ratatui::{prelude::*, widgets::{Block, Borders, Table, Row, Cell}};
use crate::config::{Config, User};

#[derive(Clone, Debug)]
pub struct UserInfo {
    pub username: String,
    pub active: bool,
    pub sessions: usize,
    pub bandwidth_used: u64,
}

#[derive(Debug)]
pub struct UsersScreen {
    users: Vec<UserInfo>,
    selected_index: usize,
}

impl UsersScreen {
    pub fn new(config: &Config) -> Self {
        let users = config.users.iter()
            .map(|(name, user): (&String, &User)| UserInfo {
                username: name.clone(),
                active: user.active,
                sessions: 0,  // TODO from metrics
                bandwidth_used: 0,
            })
            .collect();
        Self { users, selected_index: 0 }
    }
    
    pub fn render(&self, frame: &mut Frame, area: Rect) {
        let rows: Vec<Row> = self.users
            .iter()
            .enumerate()
            .map(|(i, user)| {
                let style = if i == self.selected_index {
                    Style::default().bg(Color::DarkGray)
                } else {
                    Style::default()
                };
                
                Row::new(vec![
                    Cell::from(user.username.clone()),
                    Cell::from(if user.active { "✓" } else { "✗" }),
                    Cell::from(user.sessions.to_string()),
                    Cell::from(format!("{} MB", user.bandwidth_used / 1_000_000)),
                ])
                .style(style)
            })
            .collect();
        
        let widths = [
            Constraint::Percentage(40),
            Constraint::Percentage(15),
            Constraint::Percentage(15),
            Constraint::Percentage(30),
        ];
        
        let table = Table::new(rows, widths)
            .header(Row::new(vec!["Username", "Active", "Sessions", "Bandwidth"]).style(Style::default().bold()))
            .block(Block::default().borders(Borders::ALL).title("Users"));
        
        frame.render_widget(table, area);
    }
    
    pub fn select_next(&mut self) {
        if self.selected_index < self.users.len().saturating_sub(1) {
            self.selected_index += 1;
        }
    }
    
    pub fn select_prev(&mut self) {
        if self.selected_index > 0 {
            self.selected_index -= 1;
        }
    }
}