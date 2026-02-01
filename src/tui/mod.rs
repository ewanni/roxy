//! TUI module for ROXY server management
//! 
//! Entry point: [`run_tui()`]

pub mod app;
pub mod events;
pub mod ui;
pub mod screens;

use anyhow::Result;
use crossterm::{
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::io;
pub use app::App;
pub use events::AppEvent;

/// Main entry point for TUI
/// 
/// Call this from main.rs after initializing config and logging
pub async fn run_tui(config: crate::config::Config) -> Result<()> {
    // Create app state
    let mut app = App::new(&config, None)?;
    
    // Run the app
    app.run().await
}
