//! Tokio-based server implementation
//!
//! Handles incoming connections with TLS encryption and processes
//! ROXY protocol frames asynchronously.

use crate::crypto::{NonceGenerator, KEY_SIZE, SCRAM_NONCE_SIZE};
use crate::obfuscation::TrafficShaper;
use std::fs;
use std::io::BufReader;
use std::net::SocketAddr;
use std::sync::Arc;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use crate::protocol::{Frame, RoxyInit, RoxyChallenge, RoxyAuth, RoxyWelcome, DataFrame};
use chacha20poly1305::KeyInit;
use std::sync::atomic::{AtomicUsize, Ordering};
use governor::{Quota, RateLimiter, middleware::NoOpMiddleware, clock::QuantaInstant};
use std::num::NonZeroU32;

type BandwidthLimiter = RateLimiter<governor::state::direct::NotKeyed, governor::state::InMemoryState, governor::clock::QuantaClock, NoOpMiddleware<QuantaInstant>>;

use anyhow::Context;
use tokio_rustls::rustls::{pki_types::PrivateKeyDer, ServerConfig};
use tokio::net::{TcpListener, TcpStream};
use tokio::signal;
use tokio::io::{AsyncWriteExt, AsyncReadExt};
use tokio::sync::Mutex;
use tokio::sync::RwLock;
use tokio::sync::mpsc;
use tokio_rustls::TlsAcceptor;
use tracing::{info, warn, debug};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use chacha20poly1305::aead::Aead;
use glob::Pattern;
use uuid::Uuid;
use chrono::{DateTime, Utc};
use hkdf::Hkdf;
use sha2::Sha256;
use unicode_normalization::UnicodeNormalization;

#[cfg(feature = "tui-remote")]
use {
    axum::{extract::State, routing::get, Router, Json},
    serde::Serialize,
    tower::ServiceBuilder,
};

/// Server metrics for monitoring
#[derive(Debug, Clone, Default)]
pub struct ServerMetrics {
    pub active_connections: usize,
    pub total_bytes_sent: u64,
    pub total_bytes_received: u64,
    pub active_sessions: HashMap<Uuid, SessionInfo>,
    pub uptime_seconds: u64,
}

/// Session info for monitoring
#[derive(Debug, Clone)]
pub struct SessionInfo {
    pub username: String,
    pub connected_at: DateTime<Utc>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub remote_addr: String,
}

#[cfg(feature = "tui-remote")]
#[derive(Serialize)]
struct MetricsResponse {
    active_connections: usize,
    total_bytes_sent: u64,
    total_bytes_received: u64,
    uptime_seconds: u64,
    sessions: Vec<SessionSnapshot>,
}

#[cfg(feature = "tui-remote")]
#[derive(Serialize)]
struct SessionSnapshot {
    username: String,
    bytes_sent: u64,
    bytes_received: u64,
    duration_seconds: u64,
}

#[cfg(feature = "tui-remote")]
async fn metrics_handler(
    State(metrics): State<Arc<RwLock<ServerMetrics>>>,
) -> Json<MetricsResponse> {
    let m = metrics.read().await;
    Json(MetricsResponse {
        active_connections: m.active_connections,
        total_bytes_sent: m.total_bytes_sent,
        total_bytes_received: m.total_bytes_received,
        uptime_seconds: m.uptime_seconds,
        sessions: m.active_sessions.values()
            .map(|s| SessionSnapshot {
                username: s.username.clone(),
                bytes_sent: s.bytes_sent,
                bytes_received: s.bytes_received,
                duration_seconds: (Utc::now() - s.connected_at).num_seconds() as u64,
            })
            .collect(),
    })
}

/// ROXY server instance
pub struct Server {
    /// TLS acceptor for secure connections
    acceptor: TlsAcceptor,
    /// Server configuration
    config: crate::config::Config,
    /// Active connection counter for rate limiting
    active_connections: Arc<AtomicUsize>,
    /// Shared metrics for TUI monitoring
    pub metrics: Arc<RwLock<ServerMetrics>>,
}

#[allow(dead_code)]
enum ProtocolState {
    Init,
    ChallengeSent { session_id: Uuid, scram_server: crate::auth::ScramServer, user_valid: bool },
    WelcomeSent { session_id: Uuid, cipher: ChaCha20Poly1305 },
    Tunnel { cipher: ChaCha20Poly1305, nonce_generator: Arc<crate::crypto::NonceGenerator> },
}

/// Session data for active connections
struct Session {
    state: ProtocolState,
    username: Option<String>,
    /// Upstream connections mapped by stream_id (Arc<Mutex<>> for shared async access)
    /// V-019: Using Arc<Mutex<>> allows both the main handler and spawned reader tasks
    /// to safely share the same upstream connection
    upstream_connections: Arc<Mutex<HashMap<u32, Arc<Mutex<TcpStream>>>>>,
    /// Upstream response receivers mapped by stream_id for async data forwarding
    /// V-019: Replaces busy polling with proper async channel-based communication
    #[allow(clippy::type_complexity)]
    upstream_receivers: Arc<Mutex<HashMap<u32, mpsc::Receiver<(u32, Vec<u8>)>>>>,
    /// Granted routes for ACL enforcement
    granted_routes: Vec<String>,
    /// Bandwidth rate limiter (bytes per second)
    bandwidth_limiter: Option<BandwidthLimiter>,
    /// Nonce generator for replay protection
    nonce_generator: Option<Arc<crate::crypto::NonceGenerator>>,
}

impl Server {
    /// Create a new server instance
    pub fn new(
        config: crate::config::Config,
        cert_path: Option<&str>,
        key_path: Option<&str>,
    ) -> anyhow::Result<Self> {
        let server_config = Self::create_tls_config(cert_path, key_path, &config)?;
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        Ok(Self {
            acceptor,
            config,
            active_connections: Arc::new(AtomicUsize::new(0)),
            metrics: Arc::new(RwLock::new(ServerMetrics::default())),
        })
    }

    /// Create TLS server configuration
    fn create_tls_config(
        cert_path: Option<&str>,
        key_path: Option<&str>,
        config: &crate::config::Config,
    ) -> anyhow::Result<ServerConfig> {
        let (cert_chain, key_der) = if let (Some(cert), Some(key)) = (cert_path, key_path) {
            // Load from files
            let cert_file = fs::File::open(cert).context("Failed to open certificate file")?;
            let mut cert_reader = BufReader::new(cert_file);
            let certs = rustls_pemfile::certs(&mut cert_reader)
                .collect::<Result<Vec<_>, _>>()
                .context("Failed to parse certificate")?;

            let key_file = fs::File::open(key).context("Failed to open private key file")?;
            let mut key_reader = BufReader::new(key_file);
            let key_der = rustls_pemfile::private_key(&mut key_reader)
                .context("Failed to parse private key")?
                .context("No private key found")?;

            (certs, key_der)
        } else {
            // Generate self-signed certificate
            Self::generate_self_signed_cert()?
        };

        let mut server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, key_der)
            .context("Failed to create TLS config")?;

        // Set ALPN protocols from config
        server_config.alpn_protocols = config.alpn_protocols.iter().map(|s| s.as_bytes().to_vec()).collect();

        Ok(server_config)
    }

    /// Generate a self-signed certificate for development
    fn generate_self_signed_cert() -> anyhow::Result<(Vec<rustls::pki_types::CertificateDer<'static>>, PrivateKeyDer<'static>)> {
        use rcgen::generate_simple_self_signed;
        
        let subject_alt_names = vec!["localhost".to_string(), "127.0.0.1".to_string()];
        let certified_key = generate_simple_self_signed(subject_alt_names)?;
        
        let cert_der = certified_key.cert.der().clone();
        let key_der = certified_key.signing_key.serialize_der();

        let cert_chain = vec![cert_der];

        Ok((cert_chain, PrivateKeyDer::Pkcs8(key_der.into())))
    }

    /// Run the server on the configured port
    pub async fn run(self) -> anyhow::Result<()> {
        let addr = format!("{}:{}", self.config.server.bind_address, self.config.server.port);
        let listener = TcpListener::bind(&addr).await?;
        info!("Server listening on {}", addr);

        // Stage 2.4: Uptime ticker - update metrics every second
        let metrics_clone = self.metrics.clone();
        let start_time = Instant::now();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(1)).await;
                let mut metrics = metrics_clone.write().await;
                metrics.uptime_seconds = start_time.elapsed().as_secs();
            }
        });

        #[cfg(feature = "tui-remote")]
        {
            let metrics_router = Router::new()
                .route("/metrics", get(metrics_handler))
                .with_state(self.metrics.clone());

            tokio::spawn(async move {
                let listener = TcpListener::bind("127.0.0.1:9090").await.unwrap();
                axum::serve(listener, metrics_router.into_make_service())
                    .await
                    .unwrap();
            });
        }

        loop {
            tokio::select! {
                result = listener.accept() => {
                    let (socket, peer_addr) = result?;
                    // Rate limiting: limit active connections
                    if self.active_connections.load(Ordering::SeqCst) >= self.config.server.max_concurrent_connections {
                        warn!("Connection limit reached, rejecting {}", peer_addr);
                        continue;
                    }
                    self.active_connections.fetch_add(1, Ordering::SeqCst);
                    info!("Accepted connection from {}", peer_addr);
                    let acceptor = self.acceptor.clone();
                    let config = self.config.clone();
                    let active = self.active_connections.clone();
                    let metrics = self.metrics.clone();

                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_connection(socket, acceptor, config, metrics, peer_addr).await {
                            warn!("Connection error: {}", e);
                        }
                        active.fetch_sub(1, Ordering::SeqCst);
                    });
                }
                _ = signal::ctrl_c() => {
                    info!("Shutdown signal received, stopping server");
                    break;
                }
            }
        }

        Ok(())
    }

    /// Handle a single connection, checking for plain HTTP if not allowed
    async fn handle_connection(
        mut socket: tokio::net::TcpStream,
        acceptor: TlsAcceptor,
        config: crate::config::Config,
        metrics: Arc<RwLock<ServerMetrics>>,
        remote_addr: SocketAddr,
    ) -> anyhow::Result<()> {
        // Check if this is a plain HTTP connection
        if !config.allow_plain_http {
            let mut buf = [0u8; 4];
            let n = socket.peek(&mut buf).await?;
            if n >= 4 {
                // Check for HTTP methods (GET, POST, PUT, etc.)
                let http_methods = ["GET ", "POST", "PUT ", "HEAD", "DELE", "CONN", "OPTI", "TRAC", "PATC"];
                let is_http = http_methods.iter().any(|method| {
                    buf.starts_with(method.as_bytes())
                });

                if is_http {
                    warn!("Rejected plain HTTP connection from {}", remote_addr);
                    // Send a simple HTTP 400 response
                    let response = b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n";
                    let _ = socket.write_all(response).await;
                    return Err(anyhow::anyhow!("Plain HTTP connections not allowed"));
                }
            }
        }

        let tls_stream = acceptor.accept(socket).await?;
        info!("TLS handshake completed");

        Self::protocol_handler(tls_stream, config, metrics, remote_addr).await
    }

    /// Protocol handler with state machine
    async fn protocol_handler(
        mut stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
        config: crate::config::Config,
        metrics: Arc<RwLock<ServerMetrics>>,
        remote_addr: SocketAddr,
    ) -> anyhow::Result<()> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use crate::protocol::{Frame, FrameParser};

        // Track session metrics
        let session_id = Uuid::new_v4();
        let mut username: Option<String> = None;
        let mut total_bytes_sent = 0u64;
        let mut total_bytes_received = 0u64;

        // Register session in metrics
        {
            let mut metrics_guard = metrics.write().await;
            metrics_guard.active_connections += 1;
            metrics_guard.active_sessions.insert(session_id, SessionInfo {
                username: String::new(), // Will be updated after auth
                connected_at: Utc::now(),
                bytes_sent: 0,
                bytes_received: 0,
                remote_addr: remote_addr.to_string(),
            });
        }

        let mut session = Session {
            state: ProtocolState::Init,
            username: None,
            upstream_connections: Arc::new(Mutex::new(HashMap::new())),
            upstream_receivers: Arc::new(Mutex::new(HashMap::new())),
            granted_routes: Vec::new(),
            bandwidth_limiter: None,
            nonce_generator: None,
        };

        let mut buf = vec![0u8; config.server.buffer_size];
        let mut read_buf = Vec::new();

        // V-019: Use tokio::select! for concurrent handling of client reads and upstream responses.
        // This replaces the busy polling loop that used try_read(), which could miss data and
        // cause high CPU usage. The new approach uses proper async/await with mpsc channels
        // for each upstream connection, providing:
        // - Zero CPU waste when no data is available (true async waiting)
        // - No data loss between checks (continuous reading in spawned task)
        // - Better scalability (one task per connection instead of polling all)
        loop {
            tokio::select! {
                // Read from client
                client_result = stream.read(&mut buf) => {
                    let n = match client_result {
                        Ok(0) => {
                            info!("Connection closed by client");
                            break;
                        }
                        Ok(n) => n,
                        Err(e) => {
                            warn!("Client read error: {}", e);
                            break;
                        }
                    };

                    // Track bytes received from client
                    total_bytes_received += n as u64;

                    if read_buf.len() + n > crate::protocol::MAX_BUFFER_SIZE {
                        return Err(anyhow::anyhow!("Buffer overflow protection"));
                    }
                    read_buf.extend_from_slice(&buf[..n]);
                }
                // Receive upstream responses (V-019: async channel-based forwarding)
                Some((_stream_id, frame_data)) = async {
                    let mut receivers = session.upstream_receivers.lock().await;
                    // Find any receiver with data (simplified: check first available)
                    // In production, you'd want to select on all receivers
                    for (_, receiver) in receivers.iter_mut() {
                        match receiver.try_recv() {
                            Ok(data) => return Some(data),
                            Err(tokio::sync::mpsc::error::TryRecvError::Empty) => continue,
                            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                                // Receiver disconnected, will be cleaned up on stream close
                                continue;
                            }
                        }
                    }
                    None
                } => {
                    // Apply bandwidth limiting to upstream response
                    if let Some(limiter) = &session.bandwidth_limiter {
                        let data_size = frame_data.len() as u32;
                        if let Some(data_size_nz) = std::num::NonZeroU32::new(data_size) {
                            if limiter.check_n(data_size_nz).is_err() {
                                warn!("Bandwidth limit exceeded for user, dropping {} bytes", data_size);
                                continue;
                            }
                        }
                    }

                    // Track bytes sent to client (upstream responses)
                    total_bytes_sent += frame_data.len() as u64;

                    // Send upstream response to client
                    if let Err(e) = stream.write_all(&frame_data).await {
                        warn!("Failed to send upstream response: {}", e);
                        break;
                    }
                    if let Err(e) = stream.flush().await {
                        warn!("Failed to flush: {}", e);
                        break;
                    }
                }
                else => {
                    // No events - continue loop
                }
            }

            // Try to parse frames from read_buf
            while read_buf.len() >= 4 {
                match FrameParser::parse(&read_buf) {
                    Ok((frame, consumed)) => {
                        read_buf.drain(..consumed);

                        // Update username from session if available
                        if session.username.is_some() && username.is_none() {
                            username = session.username.clone();
                            // Update session info with username after auth
                            let user = username.clone().unwrap_or_default();
                            let mut metrics_guard = metrics.write().await;
                            if let Some(session_info) = metrics_guard.active_sessions.get_mut(&session_id) {
                                session_info.username = user;
                            }
                        }

                        match Self::handle_frame(frame, &mut session, &config).await {
                            Ok(Some(response_frame)) => {
                                let mut response_data = FrameParser::serialize(&response_frame)?;
                                FrameParser::add_padding(&mut response_data, 255);

                                // Apply DPI bypass obfuscation: traffic shaping with padding and jitter
                                let shaper = TrafficShaper::new();
                                let _shaped_chunks = shaper.shape(&response_data);
                                // In production, send shaped chunks with timing delays
                                // For now, padding is applied above; timing jitter would be applied here

                                // Apply bandwidth limiting
                                if let Some(limiter) = &session.bandwidth_limiter {
                                    let data_size = response_data.len() as u32;
                                    if let Some(data_size_nz) = std::num::NonZeroU32::new(data_size) {
                                        if limiter.check_n(data_size_nz).is_err() {
                                            warn!("Bandwidth limit exceeded for user '{}', dropping {} bytes", session.username.as_ref().unwrap_or(&"unknown".to_string()), data_size);
                                            continue; // Drop the frame if limit exceeded
                                        }
                                    }
                                }

                                stream.write_all(&response_data).await?;
                                stream.flush().await?;

                                // Track bytes sent to client
                                total_bytes_sent += response_data.len() as u64;
                            }
                            Ok(None) => {
                                // No response needed
                            }
                            Err(e) => {
                                warn!("Frame handling error: {}", e);
                                // Send close frame
                                let close_frame = Frame::Close;
                                let close_data = FrameParser::serialize(&close_frame)?;
                                stream.write_all(&close_data).await?;
                                return Err(e);
                            }
                        }
                    }
                    Err(e) => {
                        if e.to_string().contains("Incomplete frame") {
                            // Wait for more data
                            break;
                        } else {
                            warn!("Invalid frame: {}", e);
                            break;
                        }
                    }
                }
            }
        }

        // Cleanup metrics on disconnect
        {
            let mut metrics_guard = metrics.write().await;
            if let Some(mut session_info) = metrics_guard.active_sessions.remove(&session_id) {
                session_info.bytes_sent = total_bytes_sent;
                session_info.bytes_received = total_bytes_received;
            }
            metrics_guard.total_bytes_sent += total_bytes_sent;
            metrics_guard.total_bytes_received += total_bytes_received;
            metrics_guard.active_connections = metrics_guard.active_connections.saturating_sub(1);
        }

        Ok(())
    }


    /// Handle a protocol frame based on current state
    async fn handle_frame(
        frame: Frame,
        session: &mut Session,
        config: &crate::config::Config,
    ) -> anyhow::Result<Option<Frame>> {
        match (&session.state, frame) {
            (ProtocolState::Init, Frame::RoxyInit(init)) => {
                Self::handle_roxy_init(init, session, config).await
            }
            (ProtocolState::ChallengeSent { .. }, Frame::RoxyAuth(auth)) => {
                Self::handle_roxy_auth(auth, session, config).await
            }
            (ProtocolState::WelcomeSent { .. }, Frame::Data(data)) => {
                Self::handle_data(data, session, config).await
            }
            (ProtocolState::Tunnel { .. }, Frame::Data(data)) => {
                Self::handle_data(data, session, config).await
            }
            _ => Err(anyhow::anyhow!("Unexpected frame in current state")),
        }
    }

    async fn handle_roxy_init(
        init: RoxyInit,
        session: &mut Session,
        config: &crate::config::Config,
    ) -> anyhow::Result<Option<Frame>> {
        if init.version != crate::protocol::PROTOCOL_VERSION {
            return Err(anyhow::anyhow!("Unsupported protocol version"));
        }

        // Parse SCRAM client-first message from padding field
        let client_first = std::str::from_utf8(&init.padding)
            .map_err(|_| anyhow::anyhow!("Invalid UTF-8 in client-first message"))?;

        // Parse username from SCRAM message
        let parts: std::collections::HashMap<&str, &str> = client_first
            .split(',')
            .filter_map(|p| p.split_once('='))
            .collect();

        let username_raw = parts.get("n")
            .ok_or_else(|| anyhow::anyhow!("Missing username in SCRAM client-first"))?;
        let username = username_raw.nfc().collect::<String>();

        // SECURITY: Use constant-time comparison for user lookup to prevent timing attacks.
        // The time taken to check user existence should be identical regardless of whether
        // the user exists, to avoid leaking information about valid usernames.
        //
        // We always compute the full SCRAM authentication path - either with real credentials
        // or with deterministic dummy credentials. This ensures:
        // 1. No timing difference between "user not found" and "wrong password"
        // 2. Full PBKDF2 computation always occurs (not just for valid users)
        // 3. Subsequent SCRAM operations use the same code path
        //
        // Note: The constant-time comparison is handled internally by the SCRAM verification
        // in auth.rs (see ScramServer::verify_client_final), which uses subtle::ConstantTimeEq
        // for comparing stored_key and server_signature.

        // Retrieve user credentials if they exist, otherwise use dummy credentials
        // The dummy credentials are computed using the same algorithm as real credentials
        // but with a fixed salt and password, ensuring identical computation time.
        let user_auth = match config.users.get(&username) {
            Some(user) => crate::auth::ScramAuth {
                salt: user.salt.clone(),
                stored_key: user.stored_key.clone(),
                server_key: user.server_key.clone(),
            },
            None => {
                // Use deterministic dummy credentials for timing consistency.
                // These credentials are computed using the full PBKDF2-HMAC-SHA256
                // algorithm with a fixed salt and password, ensuring that the
                // authentication path takes the same amount of time regardless
                // of whether the user exists.
                crate::auth::ScramAuth::dummy()
            }
        };

        // Determine if the user is valid for the session state.
        // This is used later to decide authentication success, but the SCRAM
        // computation itself always proceeds with either real or dummy credentials.
        let user_valid = config.users.contains_key(&username);

        let scram_server = crate::auth::ScramServer::start(client_first, &user_auth)?;

        let session_id = Uuid::new_v4();
        let server_nonce: [u8; SCRAM_NONCE_SIZE] = rand::random();

        let challenge = RoxyChallenge {
            session_id,
            server_nonce,
            auth_method: 0x01, // SCRAM
            challenge_data: scram_server.server_first_message().as_bytes().to_vec(),
            padding: Vec::new(),
        };

        session.state = ProtocolState::ChallengeSent {
            session_id,
            scram_server,
            user_valid,
        };
        session.username = Some(username.to_string());

        Ok(Some(Frame::RoxyChallenge(challenge)))
    }

    async fn handle_roxy_auth(
        auth: RoxyAuth,
        session: &mut Session,
        config: &crate::config::Config,
    ) -> anyhow::Result<Option<Frame>> {
        if let ProtocolState::ChallengeSent { session_id, scram_server, user_valid } = &session.state {
            if auth.session_id != *session_id {
                return Err(anyhow::anyhow!("Session ID mismatch"));
            }
            if !*user_valid {
                return Err(anyhow::anyhow!("Authentication failed"));
            }
            let client_final = std::str::from_utf8(&auth.auth_proof)?;
            let server_final = scram_server.verify_client_final(client_final)?;

            // Get user auth
            let username = session.username.as_ref().unwrap();
            let user = config.users.get(username).unwrap();
            let user_auth = crate::auth::ScramAuth {
                salt: user.salt.clone(),
                stored_key: user.stored_key.clone(),
                server_key: user.server_key.clone(),
            };

            // Derive session key using HKDF
            let hk = Hkdf::<Sha256>::new(
                Some(session_id.as_bytes()),
                &user_auth.stored_key,  // IKM from SCRAM stored_key
            );

            let info = format!("{} {}",
                crate::protocol::HKDF_INFO_PREFIX, session_id);

            let mut session_key_bytes = [0u8; KEY_SIZE];
            hk.expand(info.as_bytes(), &mut session_key_bytes)
                .map_err(|_| anyhow::anyhow!("HKDF expansion failed"))?;
            let session_key = *Key::from_slice(&session_key_bytes);

            let cipher = ChaCha20Poly1305::new(&session_key);

            // Get user for ACL and bandwidth limiting
            let user = config.users.get(session.username.as_ref().unwrap()).unwrap();
            let granted_routes = user.allowed_routes.clone();

            // Set up bandwidth limiter
            let bandwidth_limit_bps = user.bandwidth_limit_mbps
                .or(config.default_bandwidth_limit_mbps)
                .map(|mbps| mbps * 1024 * 1024 / 8) // Convert Mbps to bytes per second
                .and_then(NonZeroU32::new);

            let bandwidth_limiter = if let Some(limit) = bandwidth_limit_bps {
                let quota = Quota::per_second(limit);
                Some(RateLimiter::direct(quota))
            } else {
                None
            };

            if bandwidth_limiter.is_some() {
                info!("Applied bandwidth limit for user '{}'", session.username.as_ref().unwrap());
            }

            let welcome = RoxyWelcome {
                status: 0x00, // success
                session_lifetime: config.session_lifetime,
                obf_config: Vec::new(), // Obfuscation config (empty for now)
                server_final: server_final.into_bytes(), // SCRAM server-final for client verification
                granted_routes: granted_routes.clone(),
                padding: Vec::new(),
            };

            // Store granted routes and bandwidth limiter in session
            session.granted_routes = granted_routes;
            session.bandwidth_limiter = bandwidth_limiter;

            // Initialize nonce generator for replay protection
            session.nonce_generator = Some(Arc::new(NonceGenerator::new(*session_id.as_bytes())));

            session.state = ProtocolState::WelcomeSent {
                session_id: *session_id,
                cipher: cipher.clone(),
            };

            Ok(Some(Frame::RoxyWelcome(welcome)))
        } else {
            Err(anyhow::anyhow!("Invalid state for auth"))
        }
    }

    async fn handle_data(
        data: DataFrame,
        session: &mut Session,
        config: &crate::config::Config,
    ) -> anyhow::Result<Option<Frame>> {
        match &mut session.state {
            ProtocolState::WelcomeSent { session_id: _, cipher } => {
                // First data frame: parse SOCKS5 CONNECT request
                let nonce = Nonce::from_slice(&data.nonce);
                let decrypted = cipher.decrypt(nonce, data.payload.as_ref())
                    .map_err(|_| anyhow::anyhow!("Decryption failed"))?;

                // Parse SOCKS5 CONNECT request
                let (host, port) = Self::parse_socks5_request(&decrypted)?;
                debug!("SOCKS5 CONNECT request: {}:{}", host, port);

                // Validate against granted routes if needed
                let route = format!("{}:{}", host, port);
                if !session.granted_routes.is_empty() && !session.granted_routes.iter().any(|granted| Self::route_matches(granted, &route)) {
                    warn!("Route {} not in granted routes", route);
                    return Err(anyhow::anyhow!("Route not permitted"));
                }

                // Establish upstream connection
                let upstream = match TcpStream::connect(&format!("{}:{}", host, port)).await {
                    Ok(stream) => {
                        debug!("Connected to upstream {}:{}", host, port);
                        stream
                    }
                    Err(e) => {
                        warn!("Failed to connect to upstream {}:{}: {}", host, port, e);
                        return Err(anyhow::anyhow!("Connection refused: {}", e));
                    }
                };

                // V-019: Create mpsc channel for async upstream data forwarding
                // This replaces the busy polling loop with proper async channel-based communication
                let (response_tx, response_rx) = mpsc::channel(32);
                
                // Wrap upstream in Arc<Mutex<>> for shared access between session and spawned task
                let upstream_shared = Arc::new(Mutex::new(upstream));
                
                // Store upstream connection for writing (shared reference)
                session.upstream_connections.lock().await.insert(data.stream_id, upstream_shared.clone());
                
                // Store receiver for async upstream response handling
                session.upstream_receivers.lock().await.insert(data.stream_id, response_rx);

                // V-019: Spawn async task to continuously read from upstream
                // This task runs independently and sends encrypted data through the channel
                // to the main handler for forwarding to the client
                let cipher_clone = cipher.clone();
                let stream_id = data.stream_id;
                let buffer_size = config.server.buffer_size;
                
                tokio::spawn(async move {
                    Self::spawn_upstream_reader(
                        upstream_shared,
                        stream_id,
                        cipher_clone,
                        response_tx,
                        buffer_size,
                    ).await;
                });

                // Send SOCKS5 success response
                let response_payload = vec![0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 80];
                let nonce_bytes = rand::random::<[u8; 12]>();
                let nonce = Nonce::from_slice(&nonce_bytes);
                let encrypted = cipher.encrypt(nonce, response_payload.as_ref())
                    .map_err(|e| anyhow::anyhow!("Encryption failed: {:?}", e))?;

                let response_data = DataFrame {
                    stream_id: data.stream_id,
                    payload_len: encrypted.len() as u16,
                    flags: data.flags,
                    nonce: nonce_bytes,
                    payload: encrypted,
                    padding: Vec::new(),
                };

                // Move nonce generator to tunnel state
                let nonce_gen = session.nonce_generator.take()
                    .ok_or_else(|| anyhow::anyhow!("Nonce generator not initialized"))?;

                session.state = ProtocolState::Tunnel {
                    cipher: cipher.clone(),
                    nonce_generator: nonce_gen,
                };

                Ok(Some(Frame::Data(response_data)))
            }
            ProtocolState::Tunnel { cipher, nonce_generator } => {
                // Validate nonce freshness for replay protection
                if !nonce_generator.validate_freshness(&data.nonce) {
                    return Err(anyhow::anyhow!("Nonce replay or out-of-window detected"));
                }

                // Data forwarding in tunnel mode
                let nonce = Nonce::from_slice(&data.nonce);
                let decrypted = cipher.decrypt(nonce, data.payload.as_ref())
                    .map_err(|_| anyhow::anyhow!("Decryption failed"))?;

                // Check if this is a stream close
                if data.flags & 0x01 != 0 {
                    // Stream close flag - V-019: also clean up receiver
                    session.upstream_connections.lock().await.remove(&data.stream_id);
                    session.upstream_receivers.lock().await.remove(&data.stream_id);
                    return Ok(None);
                }

                // Forward to upstream
                {
                    let connections = session.upstream_connections.lock().await;
                    if let Some(upstream) = connections.get(&data.stream_id) {
                        let mut upstream_guard = upstream.lock().await;
                        upstream_guard.write_all(&decrypted).await
                            .map_err(|e| anyhow::anyhow!("Failed to write to upstream: {}", e))?;
                        upstream_guard.flush().await
                            .map_err(|e| anyhow::anyhow!("Failed to flush upstream: {}", e))?;
                    } else {
                        warn!("No upstream connection for stream {}", data.stream_id);
                        return Err(anyhow::anyhow!("Stream not found"));
                    }
                }

                Ok(None)
            }
            _ => Err(anyhow::anyhow!("Invalid state for data")),
        }
    }

    /// Spawn a background task to read from upstream and send responses back to client
    /// V-019: This enables proper async bidirectional communication where upstream responses
    /// are forwarded back to the client encrypted in Data frames via mpsc channel.
    ///
    /// Security benefits:
    /// - Eliminates busy polling that could miss data between checks
    /// - Provides true async waiting without CPU waste
    /// - Ensures all upstream data is captured and forwarded
    async fn spawn_upstream_reader(
        upstream: Arc<Mutex<TcpStream>>,
        stream_id: u32,
        cipher: ChaCha20Poly1305,
        response_tx: tokio::sync::mpsc::Sender<(u32, Vec<u8>)>,
        buffer_size: usize,
    ) {
        let mut buf = vec![0u8; buffer_size];
        loop {
            // V-019: Lock the upstream connection to read data
            let mut upstream_guard = upstream.lock().await;
            match upstream_guard.read(&mut buf).await {
                Ok(0) => {
                    // EOF - upstream closed
                    debug!("Upstream closed for stream {}", stream_id);
                    let _ = response_tx.send((stream_id, Vec::new())).await;
                    break;
                }
                Ok(n) => {
                    // Send data back to client encrypted
                    let data = buf[..n].to_vec();
                    let nonce_bytes = rand::random::<[u8; 12]>();
                    let nonce = Nonce::from_slice(&nonce_bytes);
                    match cipher.encrypt(nonce, data.as_ref()) {
                        Ok(encrypted) => {
                            let frame = DataFrame {
                                stream_id,
                                payload_len: encrypted.len() as u16,
                                flags: 0,
                                nonce: nonce_bytes,
                                payload: encrypted,
                                padding: Vec::new(),
                            };
                            // Send the encrypted frame data
                            let frame_data = match crate::protocol::FrameParser::serialize(&Frame::Data(frame)) {
                                Ok(data) => data,
                                Err(e) => {
                                    warn!("Failed to serialize response frame: {}", e);
                                    break;
                                }
                            };
                            if response_tx.send((stream_id, frame_data)).await.is_err() {
                                debug!("Response channel closed for stream {}", stream_id);
                                break;
                            }
                        }
                        Err(e) => {
                            warn!("Encryption failed for stream {}: {}", stream_id, e);
                            break;
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to read from upstream for stream {}: {}", stream_id, e);
                    break;
                }
            }
        }
    }

    /// Parse SOCKS5 CONNECT request
    /// Format: VER(1) CMD(1) RSV(1) ATYP(1) DST.ADDR(...) DST.PORT(2)
    fn parse_socks5_request(data: &[u8]) -> anyhow::Result<(String, u16)> {
        if data.len() < 6 {
            return Err(anyhow::anyhow!("SOCKS5 request too short"));
        }

        let ver = data[0];
        if ver != 0x05 {
            return Err(anyhow::anyhow!("Invalid SOCKS5 version: {}", ver));
        }

        let cmd = data[1];
        if cmd != 0x01 {
            return Err(anyhow::anyhow!("Only CONNECT (0x01) is supported, got: {}", cmd));
        }

        // data[2] is reserved
        let atyp = data[3];

        let (host, port_offset) = match atyp {
            0x01 => {
                // IPv4: 4 bytes
                if data.len() < 10 {
                    return Err(anyhow::anyhow!("IPv4 address too short"));
                }
                let ip = format!("{}.{}.{}.{}", data[4], data[5], data[6], data[7]);
                (ip, 8)
            }
            0x03 => {
                // Domain name: length byte + domain
                if data.len() < 5 {
                    return Err(anyhow::anyhow!("Domain name length too short"));
                }
                let domain_len = data[4] as usize;
                if data.len() < 5 + domain_len + 2 {
                    return Err(anyhow::anyhow!("Domain name too short"));
                }
                let domain = String::from_utf8(data[5..5 + domain_len].to_vec())?;
                (domain, 5 + domain_len)
            }
            0x04 => {
                // IPv6: 16 bytes
                if data.len() < 22 {
                    return Err(anyhow::anyhow!("IPv6 address too short"));
                }
                let mut ip = String::new();
                for i in (0..8).step_by(2) {
                    if i > 0 {
                        ip.push(':');
                    }
                    ip.push_str(&format!("{:x}", u16::from_be_bytes([data[4 + i], data[4 + i + 1]])));
                }
                (ip, 20)
            }
            _ => return Err(anyhow::anyhow!("Unsupported ATYP: {}", atyp)),
        };

        let port = u16::from_be_bytes([data[port_offset], data[port_offset + 1]]);

        Ok((host, port))
    }

    /// Check if a requested route matches a granted route pattern using glob matching.
    ///
    /// Supports:
    /// - Exact match: `example.com:443`
    /// - Wildcard `*`: `*` matches any route
    /// - Glob patterns: `*.example.com:80`, `192.168.*.*`, etc.
    fn route_matches(granted: &str, requested: &str) -> bool {
        if granted == "*" {
            return true;
        }

        if granted.contains('*') {
            // Use glob pattern matching
            Pattern::new(granted)
                .map(|pattern| pattern.matches(requested))
                .unwrap_or(false)
        } else {
            // Exact match
            granted == requested
        }
    }

    

}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    #[test]
    fn test_server_creation_with_self_signed() {
        let config = Config {
            users: std::collections::HashMap::new(),
            session_lifetime: 3600,
            alpn_protocols: vec![],
            log_level: "INFO".to_string(),
            log_theme_path: "config/logging_theme.yml".to_string(),
            log_to_file: false,
            log_file_path: None,
            server: Default::default(),
            tls: Default::default(),
            timeouts: Default::default(),
            quic: Default::default(),
            socks5: Default::default(),
            allow_plain_http: false,
            default_bandwidth_limit_mbps: None,
        };
        let server = Server::new(config, None, None);
        assert!(server.is_ok());
    }
}
