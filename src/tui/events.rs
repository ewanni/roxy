//! Event handling and input processing for TUI navigation.

use crossterm::event::{self, Event, KeyCode};
use std::time::Duration;
use anyhow::Result;

/// Application-level events generated from user input.
#[derive(Debug, Clone, PartialEq)]
pub enum AppEvent {
    /// Quit the application.
    Quit,
    /// Refresh the current view.
    Refresh,
    /// Navigate to the next screen.
    NextScreen,
    /// Navigate to the previous screen.
    PrevScreen,
    /// Open user management screen.
    UserManagement,
    /// Select next item in list.
    SelectNext,
    /// Select previous item in list.
    SelectPrev,
}

/// Handles keyboard events for TUI navigation.
///
/// Polls for events with a 100ms timeout and maps key presses to [`AppEvent`] variants.
/// Returns `None` for unhandled keys or when no events are available.
pub async fn handle_events() -> Result<Option<AppEvent>> {
    if event::poll(Duration::from_millis(100))? {
        if let Event::Key(key) = event::read()? {
            return Ok(match key.code {
                KeyCode::Char('q') => Some(AppEvent::Quit),
                KeyCode::Char('r') => Some(AppEvent::Refresh),
                KeyCode::Char('u') => Some(AppEvent::UserManagement),
                KeyCode::Tab => Some(AppEvent::NextScreen),
                KeyCode::BackTab => Some(AppEvent::PrevScreen), // Shift+Tab
                KeyCode::Down | KeyCode::Char('j') => Some(AppEvent::SelectNext),
                KeyCode::Up | KeyCode::Char('k') => Some(AppEvent::SelectPrev),
                _ => None,
            });
        }
    }
    Ok(None)
}