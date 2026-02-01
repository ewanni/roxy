//! Configuration management for ROXY server
//!
//! Handles loading and saving user configurations from YAML files,
//! including SCRAM authentication credentials.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use tokio::fs;
use chrono::{DateTime, Utc};
use tracing::warn;

/// User configuration containing SCRAM authentication data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    /// Salt used in SCRAM authentication
    pub salt: Vec<u8>,
    /// Stored key for SCRAM authentication
    pub stored_key: Vec<u8>,
    /// Server key for SCRAM server signature
    pub server_key: Vec<u8>,
    /// Allowed routes for this user
    pub allowed_routes: Vec<String>,
    /// Whether the user account is active
    #[serde(default = "default_user_active")]
    pub active: bool,
    /// Optional expiration timestamp in ISO 8601 format
    pub expires_at: Option<String>,
    /// Optional per-user bandwidth limit in Mbps
    pub bandwidth_limit_mbps: Option<u32>,
}

/// Server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Network address to bind the server
    #[serde(default = "default_server_bind_address")]
    pub bind_address: String,
    /// Server port
    #[serde(default = "default_server_port")]
    pub port: u16,
    /// Maximum concurrent connections
    #[serde(default = "default_max_concurrent_connections")]
    pub max_concurrent_connections: usize,
    /// Buffer size for network operations
    #[serde(default = "default_buffer_size")]
    pub buffer_size: usize,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind_address: default_server_bind_address(),
            port: default_server_port(),
            max_concurrent_connections: default_max_concurrent_connections(),
            buffer_size: default_buffer_size(),
        }
    }
}

/// TLS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    /// Enable TLS/HTTPS support
    #[serde(default = "default_tls_enabled")]
    pub enabled: bool,
    /// Path to TLS certificate file (PEM format)
    #[serde(default = "default_tls_cert_path")]
    pub cert_path: Option<String>,
    /// Path to TLS private key file (PEM format)
    #[serde(default = "default_tls_key_path")]
    pub key_path: Option<String>,
    /// Allowed TLS protocol versions
    #[serde(default = "default_tls_versions")]
    pub versions: Vec<String>,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            enabled: default_tls_enabled(),
            cert_path: default_tls_cert_path(),
            key_path: default_tls_key_path(),
            versions: default_tls_versions(),
        }
    }
}

/// Timeout configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeoutConfig {
    /// Client connection timeout in seconds
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout: u64,
    /// Read timeout in seconds
    #[serde(default = "default_read_timeout")]
    pub read_timeout: u64,
    /// Write timeout in seconds
    #[serde(default = "default_write_timeout")]
    pub write_timeout: u64,
    /// Idle connection timeout in seconds
    #[serde(default = "default_idle_timeout")]
    pub idle_timeout: u64,
}

impl Default for TimeoutConfig {
    fn default() -> Self {
        Self {
            connect_timeout: default_connect_timeout(),
            read_timeout: default_read_timeout(),
            write_timeout: default_write_timeout(),
            idle_timeout: default_idle_timeout(),
        }
    }
}

/// QUIC protocol configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuicConfig {
    /// Enable QUIC protocol support
    #[serde(default = "default_quic_enabled")]
    pub enabled: bool,
    /// QUIC bind address
    #[serde(default = "default_quic_bind_address")]
    pub bind_address: String,
    /// QUIC port
    #[serde(default = "default_quic_port")]
    pub port: u16,
    /// Maximum idle timeout in milliseconds
    #[serde(default = "default_quic_idle_timeout_ms")]
    pub idle_timeout_ms: u64,
}

impl Default for QuicConfig {
    fn default() -> Self {
        Self {
            enabled: default_quic_enabled(),
            bind_address: default_quic_bind_address(),
            port: default_quic_port(),
            idle_timeout_ms: default_quic_idle_timeout_ms(),
        }
    }
}

/// SOCKS5 proxy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Socks5Config {
    /// Whether SOCKS5 is enabled
    #[serde(default = "default_socks5_enabled")]
    pub enabled: bool,
    /// Bind address for SOCKS5 server
    #[serde(default = "default_socks5_bind_addr")]
    pub bind_addr: String,
    /// Client port for SOCKS5 connections
    #[serde(default = "default_socks5_client_port")]
    pub client_port: u16,
    /// Server port for SOCKS5 connections
    #[serde(default = "default_socks5_server_port")]
    pub server_port: u16,
}

impl Default for Socks5Config {
    fn default() -> Self {
        Self {
            enabled: default_socks5_enabled(),
            bind_addr: default_socks5_bind_addr(),
            client_port: default_socks5_client_port(),
            server_port: default_socks5_server_port(),
        }
    }
}


/// Server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Map of username to user data
    #[serde(default)]
    pub users: HashMap<String, User>,
    /// Session lifetime in seconds
    #[serde(default = "default_session_lifetime")]
    pub session_lifetime: u32,
    /// ALPN protocols
    #[serde(default = "default_alpn_protocols")]
    pub alpn_protocols: Vec<String>,
    /// Log level (TRACE, DEBUG, INFO, WARN, ERROR)
    #[serde(default = "default_log_level")]
    pub log_level: String,
    /// Path to logging theme configuration file
    #[serde(default = "default_log_theme_path")]
    pub log_theme_path: String,
    /// Whether to log to file
    #[serde(default = "default_log_to_file")]
    pub log_to_file: bool,
    /// Path to log file (used when log_to_file is true)
    #[serde(default = "default_log_file_path")]
    pub log_file_path: Option<String>,
    /// Server configuration
    #[serde(default)]
    pub server: ServerConfig,
    /// TLS configuration
    #[serde(default)]
    pub tls: TlsConfig,
    /// Timeout configuration
    #[serde(default)]
    pub timeouts: TimeoutConfig,
    /// QUIC configuration
    #[serde(default)]
    pub quic: QuicConfig,
    /// SOCKS5 proxy configuration
    #[serde(default)]
    pub socks5: Socks5Config,
    /// Whether to allow plain HTTP connections (non-TLS)
    #[serde(default = "default_allow_plain_http")]
    pub allow_plain_http: bool,
    /// Default bandwidth limit in Mbps for users without specific limits
    #[serde(default = "default_bandwidth_limit_mbps")]
    pub default_bandwidth_limit_mbps: Option<u32>,
}

fn default_session_lifetime() -> u32 {
    3600
}

fn default_alpn_protocols() -> Vec<String> {
    vec!["h2".to_string(), "http/1.1".to_string()]
}

fn default_log_level() -> String {
    "INFO".to_string()
}

fn default_log_theme_path() -> String {
    "config/logging_theme.yml".to_string()
}

fn default_log_to_file() -> bool {
    false
}

fn default_log_file_path() -> Option<String> {
    None
}

fn default_socks5_enabled() -> bool {
    true
}

fn default_socks5_bind_addr() -> String {
    "127.0.0.1".to_string()
}

fn default_socks5_client_port() -> u16 {
    1080
}

fn default_socks5_server_port() -> u16 {
    1081
}

fn default_allow_plain_http() -> bool {
    false
}

fn default_user_active() -> bool {
    true
}

fn default_bandwidth_limit_mbps() -> Option<u32> {
    None
}

fn default_server_bind_address() -> String {
    "0.0.0.0".to_string()
}

fn default_server_port() -> u16 {
    8443
}

fn default_max_concurrent_connections() -> usize {
    1000
}

fn default_buffer_size() -> usize {
    8192
}

fn default_tls_enabled() -> bool {
    true
}

fn default_tls_cert_path() -> Option<String> {
    Some("certs/server.crt".to_string())
}

fn default_tls_key_path() -> Option<String> {
    Some("certs/server.key".to_string())
}

fn default_tls_versions() -> Vec<String> {
    vec!["1.3".to_string(), "1.2".to_string()]
}

fn default_connect_timeout() -> u64 {
    10
}

fn default_read_timeout() -> u64 {
    30
}

fn default_write_timeout() -> u64 {
    30
}

fn default_idle_timeout() -> u64 {
    300
}

fn default_quic_enabled() -> bool {
    false
}

fn default_quic_bind_address() -> String {
    "0.0.0.0".to_string()
}

fn default_quic_port() -> u16 {
    4433
}

fn default_quic_idle_timeout_ms() -> u64 {
    30000
}

impl Config {
    /// Load configuration from a YAML file
    pub async fn load<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        match fs::read_to_string(&path).await {
            Ok(contents) => {
                // Parse YAML, propagate parse errors instead of silently defaulting
                let config: Config = serde_yaml::from_str(&contents)
                    .map_err(|e| anyhow::anyhow!("Failed to parse YAML configuration: {}", e))?;
                // Validate configuration
                config.validate()?;
                Ok(config)
            }
            Err(e) => {
                // Distinguish NotFound from other errors
                if e.kind() == std::io::ErrorKind::NotFound {
                    // File not found, return empty config with warning
                    warn!("Configuration file not found at '{}', using default configuration", path.as_ref().display());
                    let config = Config {
                        users: HashMap::new(),
                        session_lifetime: default_session_lifetime(),
                        alpn_protocols: default_alpn_protocols(),
                        log_level: default_log_level(),
                        log_theme_path: default_log_theme_path(),
                        log_to_file: default_log_to_file(),
                        log_file_path: default_log_file_path(),
                        server: ServerConfig::default(),
                        tls: TlsConfig::default(),
                        timeouts: TimeoutConfig::default(),
                        quic: QuicConfig::default(),
                        socks5: Socks5Config::default(),
                        allow_plain_http: default_allow_plain_http(),
                        default_bandwidth_limit_mbps: default_bandwidth_limit_mbps(),
                    };
                    config.validate()?;
                    Ok(config)
                } else {
                    // Other error (permission denied, disk error, etc.)
                    Err(anyhow::anyhow!(
                        "Failed to read configuration file '{}': {}",
                        path.as_ref().display(),
                        e
                    ))
                }
            }
        }
    }

    /// Save configuration to a YAML file
    pub async fn save<P: AsRef<Path>>(&self, path: P) -> anyhow::Result<()> {
        let yaml = serde_yaml::to_string(self)?;
        fs::write(path, yaml).await?;
        Ok(())
    }

    /// Validate configuration fields
    pub fn validate(&self) -> anyhow::Result<()> {
        // Validate log level
        let valid_levels = ["TRACE", "DEBUG", "INFO", "WARN", "ERROR"];
        if !valid_levels.contains(&self.log_level.to_uppercase().as_str()) {
            return Err(anyhow::anyhow!("Invalid log level: {}", self.log_level));
        }

        // Validate log file path if logging to file
        if self.log_to_file {
            if let Some(ref path) = self.log_file_path {
                if path.trim().is_empty() {
                    return Err(anyhow::anyhow!("Log file path cannot be empty when log_to_file is true"));
                }
            }
        }

        // Validate server configuration
        if self.server.port == 0 {
            return Err(anyhow::anyhow!("Server port must be between 1 and 65535"));
        }
        if self.server.max_concurrent_connections == 0 {
            return Err(anyhow::anyhow!("Max concurrent connections must be greater than 0"));
        }
        if self.server.buffer_size == 0 {
            return Err(anyhow::anyhow!("Buffer size must be greater than 0"));
        }

        // Validate TLS configuration
        let valid_tls_versions = ["1.2", "1.3"];
        for version in &self.tls.versions {
            if !valid_tls_versions.contains(&version.as_str()) {
                return Err(anyhow::anyhow!("Invalid TLS version: {}. Supported versions: {:?}", version, valid_tls_versions));
            }
        }
        if self.tls.enabled {
            if self.tls.cert_path.as_ref().map_or(true, |p| p.trim().is_empty()) {
                return Err(anyhow::anyhow!("TLS certificate path is required when TLS is enabled"));
            }
            if self.tls.key_path.as_ref().map_or(true, |p| p.trim().is_empty()) {
                return Err(anyhow::anyhow!("TLS private key path is required when TLS is enabled"));
            }
        }

        // Validate timeout configuration
        if self.timeouts.connect_timeout == 0 {
            return Err(anyhow::anyhow!("Connect timeout must be greater than 0"));
        }
        if self.timeouts.read_timeout == 0 {
            return Err(anyhow::anyhow!("Read timeout must be greater than 0"));
        }
        if self.timeouts.write_timeout == 0 {
            return Err(anyhow::anyhow!("Write timeout must be greater than 0"));
        }
        if self.timeouts.idle_timeout == 0 {
            return Err(anyhow::anyhow!("Idle timeout must be greater than 0"));
        }

        // Validate QUIC configuration
        if self.quic.port == 0 {
            return Err(anyhow::anyhow!("QUIC port must be between 1 and 65535"));
        }
        if self.quic.enabled && self.quic.idle_timeout_ms == 0 {
            return Err(anyhow::anyhow!("QUIC idle timeout must be greater than 0 when QUIC is enabled"));
        }

        // Validate SOCKS5 configuration
        if self.socks5.client_port == 0 || self.socks5.client_port > 65535 {
            return Err(anyhow::anyhow!("SOCKS5 client port must be between 1 and 65535"));
        }
        if self.socks5.server_port == 0 || self.socks5.server_port > 65535 {
            return Err(anyhow::anyhow!("SOCKS5 server port must be between 1 and 65535"));
        }

        // Validate business rules
        if !self.allow_plain_http && !self.tls.enabled {
            return Err(anyhow::anyhow!("Either allow_plain_http must be true or TLS must be enabled"));
        }

        Ok(())
    }

    /// Filter out inactive or expired users, logging warnings for deactivated users
    pub fn filter_active_users(&mut self) -> anyhow::Result<()> {
        let current_time = Utc::now();
        let mut users_to_remove = Vec::new();

        for (username, user) in &self.users {
            if !user.active {
                warn!("User '{}' is deactivated (active=false)", username);
                users_to_remove.push(username.clone());
            } else if let Some(expires_at) = &user.expires_at {
                match DateTime::parse_from_rfc3339(expires_at) {
                    Ok(expiry) => {
                        if expiry <= current_time {
                            warn!("User '{}' has expired (expires_at={})", username, expires_at);
                            users_to_remove.push(username.clone());
                        }
                    }
                    Err(e) => {
                        warn!("Invalid expires_at format for user '{}': {} (keeping user active)", username, e);
                    }
                }
            }
        }

        for username in users_to_remove {
            self.users.remove(&username);
        }

        Ok(())
    }

    /// Add a new user to the configuration
    pub fn add_user(&mut self, username: String, auth: crate::auth::ScramAuth, routes: Vec<String>) -> anyhow::Result<()> {
        let user = User {
            salt: auth.salt,
            stored_key: auth.stored_key,
            server_key: auth.server_key,
            allowed_routes: routes,
            active: true,
            expires_at: None,
            bandwidth_limit_mbps: None,
        };
        self.users.insert(username, user);
        Ok(())
    }
}