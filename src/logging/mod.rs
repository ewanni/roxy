//! Logging configuration for ROXY server
//!
//! Provides multi-level logging with configurable themes and optional file output.

use serde::{Deserialize, Serialize};
use std::path::Path;
use tokio::fs;
use tracing::Level;
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

/// ANSI color codes for log levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogTheme {
    /// Color for TRACE level logs
    pub trace: String,
    /// Color for DEBUG level logs
    pub debug: String,
    /// Color for INFO level logs
    pub info: String,
    /// Color for WARN level logs
    pub warn: String,
    /// Color for ERROR level logs
    pub error: String,
}

/// Default ANSI color theme
impl Default for LogTheme {
    fn default() -> Self {
        Self {
            trace: "\x1b[37m".to_string(), // White
            debug: "\x1b[36m".to_string(), // Cyan
            info: "\x1b[32m".to_string(),  // Green
            warn: "\x1b[33m".to_string(),  // Yellow
            error: "\x1b[31m".to_string(), // Red
        }
    }
}

/// Initialize logging with the given configuration
pub async fn init_logging(
    log_level: &str,
    theme_path: &str,
    log_to_file: bool,
    log_file_path: Option<&str>,
) -> anyhow::Result<()> {
    // Load theme
    let theme = load_theme(theme_path).await?;

    // Parse log level
    let level = parse_log_level(log_level)?;

    // Create filter
    let filter = EnvFilter::from_default_env()
        .add_directive(level.into())
        .add_directive("roxy=trace".parse()?);

    // Create console layer with colors
    let console_layer = fmt::layer()
        .with_writer(std::io::stdout)
        .with_ansi(true)
        .event_format(LogFormatter { theme: theme.clone() });

    // Create file layer if requested
    let file_layer = if log_to_file {
        let _file_path = log_file_path.unwrap_or("logs/roxy.log");
        let file_appender = RollingFileAppender::new(Rotation::DAILY, "logs", "roxy.log");
        Some(
            fmt::layer()
                .with_writer(file_appender)
                .with_ansi(false)
                .event_format(LogFormatter { theme }),
        )
    } else {
        None
    };

    // Initialize subscriber
    let registry = tracing_subscriber::registry().with(filter);

    if let Some(file_layer) = file_layer {
        registry.with(console_layer).with(file_layer).init();
    } else {
        registry.with(console_layer).init();
    }

    Ok(())
}

/// Custom log formatter with theme colors
struct LogFormatter {
    theme: LogTheme,
}

impl<S, N> fmt::FormatEvent<S, N> for LogFormatter
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
    N: for<'a> fmt::FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        ctx: &fmt::FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &tracing::Event<'_>,
    ) -> std::fmt::Result {
        let metadata = event.metadata();

        // Write timestamp
        let now = std::time::SystemTime::now();
        let datetime: chrono::DateTime<chrono::Utc> = now.into();
        write!(writer, "[{}] ", datetime.format("%Y-%m-%d %H:%M:%S%.3f UTC"))?;

        // Write level with color
        let level_color = match *metadata.level() {
            Level::TRACE => &self.theme.trace,
            Level::DEBUG => &self.theme.debug,
            Level::INFO => &self.theme.info,
            Level::WARN => &self.theme.warn,
            Level::ERROR => &self.theme.error,
        };
        write!(writer, "{}{:<5}\x1b[0m ", level_color, metadata.level())?;

        // Write target
        write!(writer, "{}: ", metadata.target())?;

        // Write message
        ctx.field_format().format_fields(writer.by_ref(), event)?;

        writeln!(writer)
    }
}


/// Load log theme from YAML file
async fn load_theme<P: AsRef<Path>>(path: P) -> anyhow::Result<LogTheme> {
    match fs::read_to_string(&path).await {
        Ok(contents) => {
            let theme: LogTheme = serde_yaml::from_str(&contents)?;
            Ok(theme)
        }
        Err(err) => {
            tracing::warn!(%err, "Failed to read theme file, using default theme");
            Ok(LogTheme::default())
        }
    }
}

/// Parse log level string to tracing Level
fn parse_log_level(level: &str) -> anyhow::Result<Level> {
    match level.to_uppercase().as_str() {
        "TRACE" => Ok(Level::TRACE),
        "DEBUG" => Ok(Level::DEBUG),
        "INFO" => Ok(Level::INFO),
        "WARN" => Ok(Level::WARN),
        "ERROR" => Ok(Level::ERROR),
        _ => Err(anyhow::anyhow!("Invalid log level: {}", level)),
    }
}