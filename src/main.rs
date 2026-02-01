use anyhow::anyhow;
use clap::{Parser, Subcommand};
#[cfg(feature = "quic-experimental")]
use roxy::{config::Config, auth::ScramAuth, server::Server, client::RoxyClient, client::RoxyClientConfig, logging, transport::quic::QuicServer};
#[cfg(not(feature = "quic-experimental"))]
use roxy::{config::Config, auth::ScramAuth, server::Server, client::RoxyClient, client::RoxyClientConfig, logging};
use std::path::PathBuf;
use std::time::Duration;
use tokio::task::JoinSet;
use tokio::sync::broadcast;

/// ROXY DPI Bypass Server
#[derive(Parser)]
#[command(name = "roxy-server")]
#[command(about = "A DPI bypass server using obfuscated protocols")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the ROXY server
    Server {
        /// Port to listen on
        #[arg(long, default_value = "8443")]
        port: u16,

        /// Path to TLS certificate file (PEM format)
        #[arg(long)]
        tls_cert: Option<String>,

        /// Path to TLS private key file (PEM format)
        #[arg(long)]
        tls_key: Option<String>,

        /// Path to the users configuration file
        #[arg(long, default_value = "config/users.yml")]
        config: PathBuf,
    },
    /// Connect as a ROXY client
    Client {
        /// Server address (host:port)
        #[arg(long)]
        server: String,

        /// Username for authentication
        #[arg(long)]
        user: String,

        /// Password for authentication (or use ROXY_PASSWORD env var)
        #[arg(long)]
        password: Option<String>,

        /// Requested routes (comma-separated)
        #[arg(long)]
        routes: Option<String>,

        /// Skip TLS certificate verification (DANGEROUS)
        #[arg(long)]
        skip_cert_verification: bool,
    },
    /// User management commands
    User {
        /// Path to the users configuration file
        #[arg(long, default_value = "config/users.yml")]
        config: PathBuf,

        #[command(subcommand)]
        user_command: UserCommands,
    },
    /// Launch TUI dashboard for monitoring and management
    Tui {
        /// Path to server configuration file (for monitoring local server)
        #[arg(long, default_value = "config/users.yml")]
        config: PathBuf,
        
        /// Remote server address for monitoring (optional)
        #[arg(long)]
        remote: Option<String>,
    },
}

#[derive(Subcommand)]
enum UserCommands {
    /// Add a new user
    Add {
        /// Username
        #[arg(long)]
        name: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load config first to get logging settings
    let cli = Cli::parse();
    let config_path = match &cli.command {
        Some(Commands::Server { config, .. }) => config,
        Some(Commands::User { config, .. }) => config,
        _ => &PathBuf::from("config/users.yml"), // Default for client and TUI
    };

    let config = Config::load(config_path).await?;

    // Initialize logging
    logging::init_logging(
        &config.log_level,
        &config.log_theme_path,
        config.log_to_file,
        config.log_file_path.as_deref(),
    )
    .await?;

    match cli.command {
        // NEW: Launch TUI when no command provided
        None => {
            let mut app = roxy::tui::App::new(&config, None)?;
            app.run().await?;
        }
        Some(Commands::Server { tls_cert, tls_key, config: _, .. }) => {
            // Filter out inactive/expired users
            let mut config = config;
            config.validate()?;
            config.filter_active_users()?;

            // Create broadcast channel for graceful shutdown
            let (shutdown_tx, _) = broadcast::channel(1);
            
            // Create task set for spawning multiple servers
            let mut tasks = JoinSet::new();

            // Spawn main ROXY TCP server
            let cfg_clone = config.clone();
            let tcp_server = Server::new(cfg_clone, tls_cert.as_deref(), tls_key.as_deref())?;
            tasks.spawn(async move {
                tcp_server.run().await
            });

            // Conditionally spawn SOCKS5 server
            if config.socks5.enabled {
                let cfg_clone = config.clone();
                tasks.spawn(async move {
                    roxy::transport::socks5::run_server(&cfg_clone).await
                });
            }

            #[cfg(feature = "quic-experimental")]
            {
                if config.quic.enabled {
                    let cfg_clone = config.clone();
                    tasks.spawn(async move {
                        QuicServer::new(cfg_clone).run().await
                    });
                }
            }
            #[cfg(not(feature = "quic-experimental"))]
            {
                if config.quic.enabled {
                    tracing::warn!("QUIC is enabled in config but the \"quic-experimental\" feature is not enabled. QUIC server will not start.");
                }
            }

            // Spawn signal handler for graceful shutdown
            let shutdown_tx_clone = shutdown_tx.clone();
            tokio::spawn(async move {
                if let Err(e) = tokio::signal::ctrl_c().await {
                    tracing::error!("Signal handler error: {}", e);
                    return;
                }
                tracing::info!("Shutdown signal received");
                let _ = shutdown_tx_clone.send(());
            });

            // Wait for all tasks to complete with timeout
            let shutdown_timeout = Duration::from_secs(5);
            let start = tokio::time::Instant::now();

            while !tasks.is_empty() {
                tokio::select! {
                    Some(result) = tasks.join_next() => {
                        match result {
                            Ok(Ok(())) => {
                                tracing::info!("Task completed successfully");
                            }
                            Ok(Err(e)) => {
                                tracing::error!("Task error: {}", e);
                                return Err(e);
                            }
                            Err(e) => {
                                tracing::error!("Join error: {}", e);
                                return Err(anyhow!("Task join error: {}", e));
                            }
                        }
                    }
                    _ = tokio::time::sleep(Duration::from_millis(100)), if start.elapsed() > shutdown_timeout => {
                        tracing::warn!("Shutdown timeout exceeded, aborting remaining tasks");
                        tasks.abort_all();
                        break;
                    }
                }
            }
            tracing::info!("All tasks completed");
        }
        Some(Commands::Client { server, user, password, routes, skip_cert_verification }) => {
            // Get password from argument or environment variable
            let pwd = match password.or_else(|| std::env::var("ROXY_PASSWORD").ok()) {
                Some(p) => p,
                None => {
                    // Prompt for password in interactive mode
                    eprint!("Password: ");
                    rpassword::read_password().map_err(|_| {
                        anyhow!(
                            "Failed to read password from terminal. \
                            This may happen in non-interactive mode. \
                            Please use the --password flag or set the ROXY_PASSWORD environment variable."
                        )
                    })?
                }
            };

            // Parse routes
            let requested_routes: Vec<String> = routes
                .map(|r| r.split(',').map(|s| s.trim().to_string()).collect())
                .unwrap_or_default();

            // Build client configuration
            let config = RoxyClientConfig::builder(&server)
                .credentials(&user, &pwd)
                .routes(requested_routes)
                .timeout(30);

            let config = if skip_cert_verification {
                config.skip_verification().build()?
            } else {
                config.build()?
            };

            // Create and connect client
            let mut client = RoxyClient::new(config);
            client.connect().await?;

            println!("Connected to ROXY server: {}", server);
            if let Some(session) = client.session_info() {
                println!("Session ID: {}", session.session_id);
                println!("Granted routes: {}", session.granted_routes.join(", "));
                println!("Session lifetime: {}s", session.session_lifetime);
            }

            // Keep connection alive
            tokio::signal::ctrl_c().await?;
            client.disconnect().await?;
            println!("Disconnected");
        }
        Some(Commands::User { config: config_path, user_command }) => match user_command {
            UserCommands::Add { name } => {
                // Use already loaded config
                let mut config = config;
                // Read password from stdin
                eprint!("Password: ");
                let stdin = std::io::stdin();
                let mut handle = stdin.lock();
                let password = rpassword::read_password_from_bufread(&mut handle)?;
                // Generate SCRAM credentials
                let auth = ScramAuth::new(&name, &password)?;
                // Add user
                config.add_user(name, auth, vec![])?;
                // Save config
                config.save(config_path).await?;
                println!("User added successfully");
            }
        }
        Some(Commands::Tui { config: config_path, remote }) => {
            // Load configuration
            let config = Config::load(&config_path).await?;
            
            // Initialize TUI application
            let mut app = roxy::tui::App::new(&config, remote)?;
            
            // Run TUI event loop
            app.run().await?;
        }
    }

    Ok(())
}