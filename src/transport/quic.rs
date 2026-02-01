//! QUIC transport implementation
//!
//! Provides QUIC-based server functionality using the quinn crate,
//! with TLS integration reusing existing certificate configuration.
//!
//! # ⚠️ Experimental Feature
//! QUIC support is experimental and incomplete. Enable the "quic-experimental" feature to use it.
//! This module implements the full ROXY protocol state machine over QUIC transport.

#![cfg_attr(not(feature = "quic-experimental"), allow(dead_code))]

#[cfg(not(feature = "quic-experimental"))]
compile_error!("QUIC support is experimental and incomplete. Enable the \"quic-experimental\" feature to use it.");

#[cfg(feature = "quic-experimental")]
mod quic_impl {
    use crate::config::Config;
    use crate::protocol::{
        Frame, FrameParser, RoxyChallenge, RoxyWelcome, DataFrame,
        PROTOCOL_VERSION,
    };
    use crate::auth::{ScramServer, ScramAuth};
    use crate::crypto::NonceGenerator;
    use anyhow::{Result, anyhow, Context};
    use quinn::{Endpoint, ServerConfig, Connection};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use std::fs;
    use std::io::BufReader;
    use std::sync::Arc;
    use tokio::io::AsyncWriteExt;
    use tracing::{info, warn, debug, error};
    use uuid::Uuid;
    use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
    use hkdf::Hkdf;
    use sha2::Sha256;
    use rand::Rng;
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as Base64;

    /// QUIC server implementation with full ROXY protocol support
    pub struct QuicServer {
        config: Config,
    }

    /// Protocol state for QUIC connections (mirrors TLS transport state machine)
    enum ProtocolState {
        Init,
        ChallengeSent {
            session_id: Uuid,
            scram_server: ScramServer,
            client_nonce: [u8; 32],
            server_nonce: [u8; 32],
        },
        WelcomeSent {
            session_id: Uuid,
            #[allow(dead_code)]
            cipher: ChaCha20Poly1305,
        },
        Tunnel {
            session_id: Uuid,
            #[allow(dead_code)]
            cipher: ChaCha20Poly1305,
            #[allow(dead_code)]
            nonce_generator: Arc<NonceGenerator>,
        },
    }

    impl std::fmt::Debug for ProtocolState {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                ProtocolState::Init => write!(f, "Init"),
                ProtocolState::ChallengeSent { session_id, scram_server: _, client_nonce, server_nonce } => {
                    f.debug_struct("ChallengeSent")
                        .field("session_id", session_id)
                        .field("client_nonce", &format!("[..{} bytes..]", client_nonce.len()))
                        .field("server_nonce", &format!("[..{} bytes..]", server_nonce.len()))
                        .finish()
                }
                ProtocolState::WelcomeSent { session_id, cipher: _ } => {
                    f.debug_struct("WelcomeSent")
                        .field("session_id", session_id)
                        .finish()
                }
                ProtocolState::Tunnel { session_id, cipher: _, nonce_generator: _ } => {
                    f.debug_struct("Tunnel")
                        .field("session_id", session_id)
                        .finish()
                }
            }
        }
    }

    impl QuicServer {
        /// Create a new QUIC server instance
        pub fn new(config: Config) -> Self {
            Self { config }
        }

        /// Run the QUIC server
        pub async fn run(&self) -> Result<()> {
            let addr = format!("{}:{}", self.config.quic.bind_address, self.config.quic.port);
            let server_config = self.create_quic_config()?;
            let endpoint = Endpoint::server(server_config, addr.parse()?)?;

            info!("QUIC server listening on {}", addr);

            while let Some(conn) = endpoint.accept().await {
                let connection = conn.await?;
                let peer_addr = connection.remote_address();
                info!("Accepted QUIC connection from {}", peer_addr);

                let config = self.config.clone();
                tokio::spawn(async move {
                    if let Err(e) = Self::handle_connection(connection, config).await {
                        error!("QUIC connection error from {}: {}", peer_addr, e);
                    }
                });
            }

            Ok(())
        }

        /// Create QUIC server configuration with TLS
        fn create_quic_config(&self) -> Result<ServerConfig> {
            let (cert_chain, key_der) = self.load_or_generate_cert()?;

            // Convert CertificateDer to the format expected by quinn
            let rustls_certs: Vec<rustls::pki_types::CertificateDer<'static>> = cert_chain;
            let rustls_key = key_der;

            let mut server_config = ServerConfig::with_single_cert(rustls_certs, rustls_key)?;
            Arc::get_mut(&mut server_config.transport)
                .unwrap()
                .max_idle_timeout(Some(
                    std::time::Duration::from_millis(self.config.quic.idle_timeout_ms).try_into()?
                ));

            Ok(server_config)
        }

        /// Load certificate and key, or generate self-signed if not provided
        fn load_or_generate_cert(&self) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
            if let (Some(cert_path), Some(key_path)) = (&self.config.tls.cert_path, &self.config.tls.key_path) {
                // Load from files
                let cert_file = fs::File::open(cert_path)
                    .context("Failed to open certificate file")?;
                let mut cert_reader = BufReader::new(cert_file);
                let certs = rustls_pemfile::certs(&mut cert_reader)
                    .collect::<Result<Vec<_>, _>>()
                    .context("Failed to parse certificate")?;

                let key_file = fs::File::open(key_path)
                    .context("Failed to open private key file")?;
                let mut key_reader = BufReader::new(key_file);
                let key_der = rustls_pemfile::private_key(&mut key_reader)?
                    .ok_or_else(|| anyhow!("No private key found"))?;

                Ok((certs, key_der))
            } else {
                // Generate self-signed certificate
                self.generate_self_signed_cert()
            }
        }

        /// Generate a self-signed certificate for development
        fn generate_self_signed_cert(&self) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
            use rcgen::generate_simple_self_signed;

            let subject_alt_names = vec!["localhost".to_string(), "127.0.0.1".to_string()];
            let certified_key = generate_simple_self_signed(subject_alt_names)?;

            let cert_der = certified_key.cert.der().clone();
            let key_der = certified_key.signing_key.serialize_der();

            let cert_chain = vec![CertificateDer::from(cert_der)];

            Ok((cert_chain, PrivateKeyDer::Pkcs8(key_der.into())))
        }

        /// Handle a QUIC connection
        async fn handle_connection(connection: Connection, config: Config) -> Result<()> {
            debug!("Starting QUIC connection handler");

            loop {
                let stream = connection.accept_bi().await?;
                let (send, recv) = stream;

                debug!("Accepted bidirectional QUIC stream");

                let config_clone = config.clone();
                tokio::spawn(async move {
                    if let Err(e) = Self::handle_stream(send, recv, config_clone).await {
                        warn!("QUIC stream error: {}", e);
                    }
                });
            }
        }

        /// Handle a single QUIC stream with full ROXY protocol state machine
        async fn handle_stream(
            mut send: quinn::SendStream,
            mut recv: quinn::RecvStream,
            _config: Config,
        ) -> Result<()> {
            debug!("Starting ROXY protocol handshake on QUIC stream");

            // Initialize protocol state machine
            let mut state = ProtocolState::Init;

            let mut buf = [0u8; 8192];

            loop {
                let n = recv.read(&mut buf).await?;
                match n {
                    Some(n) if n > 0 => {
                        let frame_data = &buf[..n];

                        // Parse ROXY frame
                        let (frame, _) = FrameParser::parse(frame_data)
                            .context("Failed to parse ROXY frame")?;

                        debug!("Received frame: {:?}", frame);

                        // Process frame based on current state
                        match frame {
                            Frame::RoxyInit(init) => {
                                // Handle ROXY_INIT - transition from Init to ChallengeSent
                                if !matches!(state, ProtocolState::Init) {
                                    return Err(anyhow!("Unexpected ROXY_INIT in state {:?}", state));
                                }

                                // Validate protocol version
                                if init.version != PROTOCOL_VERSION {
                                    return Err(anyhow!(
                                        "Unsupported protocol version: {} (expected {})",
                                        init.version,
                                        PROTOCOL_VERSION
                                    ));
                                }

                                // Generate session and challenge
                                let new_session_id = Uuid::new_v4();
                                let mut server_nonce = [0u8; 32];
                                rand::thread_rng().fill(&mut server_nonce);

                                // Create a dummy user auth for QUIC (in production, look up from user database)
                                // Using dummy() to prevent timing attacks during initial auth
                                let user_auth = ScramAuth::dummy();

                                // Build SCRAM client-first message from ROXY_INIT
                                let client_first = format!(
                                    "n,,n=quic-client,r={}",
                                    Base64.encode(&init.client_nonce)
                                );

                                // Create SCRAM server for authentication
                                let scram_server = ScramServer::start(&client_first, &user_auth)
                                    .context("Failed to create SCRAM server")?;

                                // Get server-first message from SCRAM before moving scram_server
                                let server_first = scram_server.server_first_message().to_string();

                                state = ProtocolState::ChallengeSent {
                                    session_id: new_session_id,
                                    scram_server,
                                    client_nonce: init.client_nonce,
                                    server_nonce,
                                };

                                // Send ROXY_CHALLENGE response with SCRAM challenge data
                                let challenge_frame = Frame::RoxyChallenge(RoxyChallenge {
                                    session_id: new_session_id,
                                    server_nonce,
                                    auth_method: 0x01, // SCRAM-SHA-256
                                    challenge_data: server_first.into_bytes(),
                                    padding: Vec::new(),
                                });

                                let mut response_data = FrameParser::serialize(&challenge_frame)
                                    .context("Failed to serialize ROXY_CHALLENGE")?;
                                FrameParser::add_padding(&mut response_data, 255);
                                let new_len = (response_data.len() - 4) as u32;
                                response_data[0..4].copy_from_slice(&new_len.to_be_bytes());

                                send.write_all(&response_data).await?;
                                send.flush().await?;

                                debug!("Sent ROXY_CHALLENGE for session {}", new_session_id);
                            }

                            Frame::RoxyAuth(auth) => {
                                // Handle ROXY_AUTH - transition from ChallengeSent to WelcomeSent
                                let (session_id_val, scram_server, client_nonce, server_nonce) = match &mut state {
                                    ProtocolState::ChallengeSent {
                                        session_id,
                                        scram_server,
                                        client_nonce,
                                        server_nonce,
                                    } => {
                                        // Validate session ID
                                        if *session_id != auth.session_id {
                                            return Err(anyhow!(
                                                "Session ID mismatch: expected {}, got {}",
                                                session_id,
                                                auth.session_id
                                            ));
                                        }
                                        (
                                            *session_id,
                                            scram_server,
                                            *client_nonce,
                                            *server_nonce,
                                        )
                                    }
                                    _ => {
                                        return Err(anyhow!("Unexpected ROXY_AUTH in state {:?}", state));
                                    }
                                };

                                // Build SCRAM client-final message from ROXY_AUTH
                                // The auth_proof contains the client-final message
                                let client_final = String::from_utf8(auth.auth_proof.clone())
                                    .map_err(|e| anyhow!("Invalid UTF-8 in auth proof: {}", e))?;

                                // Verify SCRAM authentication
                                let server_final = scram_server
                                    .verify_client_final(&client_final)
                                    .context("SCRAM authentication failed")?;

                                // Derive session key for encryption
                                let session_key = derive_session_key(&client_nonce, &server_nonce)
                                    .context("Failed to derive session key")?;

                                let cipher = ChaCha20Poly1305::new_from_slice(&session_key)
                                    .map_err(|e| anyhow!("Failed to create cipher: {:?}", e))?;

                                // Send ROXY_WELCOME response
                                let welcome_frame = Frame::RoxyWelcome(RoxyWelcome {
                                    status: 0x00, // Success
                                    session_lifetime: 3600, // 1 hour
                                    obf_config: Vec::new(),
                                    server_final: server_final.into_bytes(),
                                    granted_routes: vec!["*".to_string()], // Grant all routes for now
                                    padding: Vec::new(),
                                });

                                let mut response_data = FrameParser::serialize(&welcome_frame)
                                    .context("Failed to serialize ROXY_WELCOME")?;
                                FrameParser::add_padding(&mut response_data, 255);
                                let new_len = (response_data.len() - 4) as u32;
                                response_data[0..4].copy_from_slice(&new_len.to_be_bytes());

                                send.write_all(&response_data).await?;
                                send.flush().await?;

                                debug!("Sent ROXY_WELCOME for session {}", session_id_val);

                                // Transition to WelcomeSent state
                                state = ProtocolState::WelcomeSent {
                                    session_id: session_id_val,
                                    cipher: cipher.clone(),
                                };
                            }

                            Frame::RoxyWelcome(_) => {
                                // Handle ROXY_WELCOME - transition from WelcomeSent to Tunnel
                                let (session_id_val, cipher) = match &mut state {
                                    ProtocolState::WelcomeSent {
                                        session_id,
                                        cipher,
                                    } => (*session_id, cipher.clone()),
                                    _ => {
                                        return Err(anyhow!("Unexpected ROXY_WELCOME in state {:?}", state));
                                    }
                                };

                                state = ProtocolState::Tunnel {
                                    session_id: session_id_val,
                                    cipher,
                                    nonce_generator: Arc::new(NonceGenerator::new(*session_id_val.as_bytes())),
                                };

                                debug!("Entered Tunnel state for session {}", session_id_val);
                            }

                            Frame::Data(data_frame) => {
                                // Handle Data frame - only valid in Tunnel state
                                if !matches!(state, ProtocolState::Tunnel { .. }) {
                                    return Err(anyhow!("Unexpected Data frame in state {:?}", state));
                                }

                                debug!(
                                    "Received Data frame: stream_id={}, payload_len={}",
                                    data_frame.stream_id,
                                    data_frame.payload_len
                                );

                                // TODO: Forward data to upstream connection
                                // For now, echo back a minimal response
                                let response = Frame::Data(DataFrame {
                                    stream_id: data_frame.stream_id,
                                    payload_len: 0,
                                    flags: 0,
                                    nonce: [0u8; 12],
                                    payload: Vec::new(),
                                    padding: Vec::new(),
                                });

                                let mut response_data = FrameParser::serialize(&response)
                                    .context("Failed to serialize Data response")?;
                                FrameParser::add_padding(&mut response_data, 255);
                                let new_len = (response_data.len() - 4) as u32;
                                response_data[0..4].copy_from_slice(&new_len.to_be_bytes());

                                send.write_all(&response_data).await?;
                                send.flush().await?;

                                debug!("Forwarded data for stream {}", data_frame.stream_id);
                            }

                            Frame::Ping => {
                                // Handle Ping - respond with Pong (same frame for simplicity)
                                let pong = Frame::Ping;
                                let mut response_data = FrameParser::serialize(&pong)
                                    .context("Failed to serialize Ping response")?;
                                FrameParser::add_padding(&mut response_data, 255);
                                let new_len = (response_data.len() - 4) as u32;
                                response_data[0..4].copy_from_slice(&new_len.to_be_bytes());

                                send.write_all(&response_data).await?;
                                send.flush().await?;

                                debug!("Responded to Ping");
                            }

                            Frame::Control(payload) => {
                                // Handle Control message
                                debug!("Received Control frame with {} bytes", payload.len());
                                // TODO: Implement control message handling
                            }

                            Frame::ControlAck => {
                                // Handle Control acknowledgment
                                debug!("Received ControlAck frame");
                                // TODO: Implement control ack handling
                            }

                            Frame::RoxyChallenge(_) => {
                                // Server should never receive RoxyChallenge - it's sent by server
                                return Err(anyhow!("Unexpected RoxyChallenge frame received"));
                            }

                            Frame::Close => {
                                // Handle Close frame
                                debug!("Received Close frame, closing connection");
                                break;
                            }
                        }
                    }
                    _ => break, // Stream closed
                }
            }

            send.finish().await?;
            debug!("QUIC stream closed");

            Ok(())
        }
    }

    /// Derive session key from nonces using HKDF
    fn derive_session_key(client_nonce: &[u8; 32], server_nonce: &[u8; 32]) -> Result<[u8; 32]> {
        let mut combined_nonce = [0u8; 64];
        combined_nonce[..32].copy_from_slice(client_nonce);
        combined_nonce[32..].copy_from_slice(server_nonce);

        let hkdf = Hkdf::<Sha256>::new(None, &combined_nonce);
        let mut session_key = [0u8; 32];
        hkdf.expand(b"ROXY session key", &mut session_key)
            .map_err(|e| anyhow!("HKDF expansion failed: {:?}", e))?;

        Ok(session_key)
    }
}

#[cfg(feature = "quic-experimental")]
pub use quic_impl::QuicServer;