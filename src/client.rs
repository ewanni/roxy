//! ROXY protocol client implementation
//!
//! Provides the `RoxyClient` struct for connecting to ROXY servers,
//! authenticating via SCRAM-SHA-256, and maintaining encrypted data tunnels
//! with ChaCha20-Poly1305 encryption.

use crate::protocol::{Frame, FrameParser, RoxyInit, RoxyAuth, DataFrame, PROTOCOL_VERSION};
use crate::auth::ScramClient;
use crate::crypto::{derive_session_key, NonceGenerator, SCRAM_NONCE_SIZE};
use crate::obfuscation::{TrafficShaper, PaddingStrategy, TimingObfuscator};
use anyhow::anyhow;
use chacha20poly1305::ChaCha20Poly1305;
use chacha20poly1305::KeyInit;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::RootCertStore;
use tokio_rustls::rustls::pki_types::CertificateDer;
use tokio_rustls::TlsConnector;
#[cfg(debug_assertions)]
use tracing::{debug, info, warn};

#[cfg(not(debug_assertions))]
use tracing::{debug, info};
use uuid::Uuid;

/// Client configuration for ROXY connections
#[derive(Debug, Clone)]
pub struct RoxyClientConfig {
    /// Server address (host:port)
    pub server_addr: String,
    /// Username for authentication
    pub username: String,
    /// Password for authentication
    pub password: String,
    /// Requested routes
    pub requested_routes: Vec<String>,
    /// Connection timeout in seconds
    pub connect_timeout: u64,
    /// Skip TLS certificate verification (testing only)
    pub skip_cert_verification: bool,
}

impl RoxyClientConfig {
    /// Create a new client configuration with defaults
    pub fn builder(server_addr: &str) -> RoxyClientConfigBuilder {
        RoxyClientConfigBuilder {
            server_addr: server_addr.to_string(),
            username: String::new(),
            password: String::new(),
            requested_routes: Vec::new(),
            connect_timeout: 30,
            skip_cert_verification: false,
        }
    }
}

/// Builder for RoxyClient configuration
pub struct RoxyClientConfigBuilder {
    server_addr: String,
    username: String,
    password: String,
    requested_routes: Vec<String>,
    connect_timeout: u64,
    skip_cert_verification: bool,
}

impl RoxyClientConfigBuilder {
    /// Set authentication credentials
    pub fn credentials(mut self, username: &str, password: &str) -> Self {
        self.username = username.to_string();
        self.password = password.to_string();
        self
    }

    /// Set requested routes
    pub fn routes(mut self, routes: Vec<String>) -> Self {
        self.requested_routes = routes;
        self
    }

    /// Set connection timeout in seconds
    pub fn timeout(mut self, seconds: u64) -> Self {
        self.connect_timeout = seconds;
        self
    }

    /// Skip TLS certificate verification (DANGEROUS - testing only)
    pub fn skip_verification(mut self) -> Self {
        self.skip_cert_verification = true;
        self
    }

    /// Build the configuration
    pub fn build(self) -> anyhow::Result<RoxyClientConfig> {
        if self.username.is_empty() || self.password.is_empty() {
            return Err(anyhow!("Username and password are required"));
        }
        if self.connect_timeout == 0 {
            return Err(anyhow!("Connect timeout must be > 0"));
        }

        Ok(RoxyClientConfig {
            server_addr: self.server_addr,
            username: self.username,
            password: self.password,
            requested_routes: self.requested_routes,
            connect_timeout: self.connect_timeout,
            skip_cert_verification: self.skip_cert_verification,
        })
    }
}

/// Session information after successful authentication
#[derive(Debug, Clone)]
pub struct SessionInfo {
    pub session_id: Uuid,
    pub granted_routes: Vec<String>,
    pub session_lifetime: u32,
}

/// Main ROXY client for encrypted tunnel communication
pub struct RoxyClient {
    config: RoxyClientConfig,
    tls_stream: Option<TlsStream<TcpStream>>,
    session_info: Option<SessionInfo>,
    cipher: Option<ChaCha20Poly1305>,
    nonce_generator: Option<Arc<NonceGenerator>>,
}

impl RoxyClient {
    /// Create a new client builder
    pub fn builder(server_addr: &str) -> RoxyClientConfigBuilder {
        RoxyClientConfig::builder(server_addr)
    }

    /// Create a client from configuration
    pub fn new(config: RoxyClientConfig) -> Self {
        Self {
            config,
            tls_stream: None,
            session_info: None,
            cipher: None,
            nonce_generator: None,
        }
    }

    /// Connect to the ROXY server and perform handshake
    pub async fn connect(&mut self) -> anyhow::Result<()> {
        info!("Initiating connection to {}", self.config.server_addr);

        // Phase 1: Establish TLS connection
        let tls_stream = self.establish_tls_connection().await?;
        self.tls_stream = Some(tls_stream);
        info!("TLS connection established");

        // Phase 2: Execute ROXY handshake
        self.execute_handshake().await?;
        info!("ROXY handshake completed");

        Ok(())
    }

    /// Establish TLS connection to server
    async fn establish_tls_connection(&self) -> anyhow::Result<TlsStream<TcpStream>> {
        debug!("Attempting to connect to server: {}", self.config.server_addr);
        
        // Parse host:port from server_addr
        // Split the address into host and port
        let (host, port_str) = self.config.server_addr
            .rsplit_once(':')
            .ok_or_else(|| anyhow!("Invalid server address format. Expected 'host:port'"))?;
        
        let port: u16 = port_str.parse()
            .map_err(|_| anyhow!("Invalid port number: {}", port_str))?;
        
        // Convert host to owned String for later use
        let host = host.to_string();
        
        debug!("Parsed host: '{}', port: {}", host, port);
        
        // Try to parse as IP address first, if fails then resolve DNS
        let addr: SocketAddr = if let Ok(ip_addr) = host.parse::<std::net::IpAddr>() {
            debug!("Host is an IP address: {}", ip_addr);
            SocketAddr::new(ip_addr, port)
        } else {
            // Perform DNS resolution
            debug!("Resolving DNS for host: {}", host);
            let addrs: Vec<SocketAddr> = tokio::net::lookup_host(&self.config.server_addr)
                .await
                .map_err(|e| anyhow!("DNS resolution failed for '{}': {}", host, e))?
                .collect();
            
            if addrs.is_empty() {
                return Err(anyhow!("DNS resolution returned no addresses for '{}'", host));
            }
            
            debug!("DNS resolved to {} address(es), using first: {}", addrs.len(), addrs[0]);
            addrs[0]
        };
        
        debug!("Connecting to resolved address: {}", addr);
        
        // Determine server name for SNI
        // If host is an IP address, we still need a domain name for proper certificate validation
        // For IP addresses, we cannot validate the certificate properly unless skip_cert_verification is true
        let server_name_str = if host.parse::<std::net::IpAddr>().is_ok() {
            // IP address - use it as-is, but certificate validation may fail
            debug!("Using IP address for SNI (certificate validation may fail)");
            host.clone()
        } else {
            // Domain name - use it for SNI
            debug!("Using domain name for SNI: {}", host);
            host.clone()
        };

        #[cfg(debug_assertions)]
        if self.config.skip_cert_verification {
            warn!("SKIPPING CERTIFICATE VERIFICATION - This is insecure!");
            // Accept any certificate (dangerous, for testing only)
            use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
            use rustls::pki_types::ServerName;
            use rustls::SignatureScheme;

            #[derive(Clone, Debug)]
            struct DangerousVerifier;

            impl ServerCertVerifier for DangerousVerifier {
                fn verify_server_cert(
                    &self,
                    _end_entity: &rustls::pki_types::CertificateDer<'_>,
                    _intermediates: &[rustls::pki_types::CertificateDer<'_>],
                    _server_name: &ServerName<'_>,
                    _ocsp_response: &[u8],
                    _now: rustls::pki_types::UnixTime,
                ) -> Result<ServerCertVerified, rustls::Error> {
                    Ok(ServerCertVerified::assertion())
                }

                fn verify_tls12_signature(
                    &self,
                    _message: &[u8],
                    _cert: &rustls::pki_types::CertificateDer<'_>,
                    _dss: &rustls::DigitallySignedStruct,
                ) -> Result<HandshakeSignatureValid, rustls::Error> {
                    Ok(HandshakeSignatureValid::assertion())
                }

                fn verify_tls13_signature(
                    &self,
                    _message: &[u8],
                    _cert: &rustls::pki_types::CertificateDer<'_>,
                    _dss: &rustls::DigitallySignedStruct,
                ) -> Result<HandshakeSignatureValid, rustls::Error> {
                    Ok(HandshakeSignatureValid::assertion())
                }

                fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
                    vec![
                        SignatureScheme::RSA_PKCS1_SHA256,
                        SignatureScheme::ECDSA_NISTP256_SHA256,
                        SignatureScheme::ED25519,
                    ]
                }
            }

            let config = tokio_rustls::rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(DangerousVerifier))
                .with_no_client_auth();

            let connector = TlsConnector::from(Arc::new(config));
            let tcp_stream = TcpStream::connect(addr).await?;
            debug!("TCP connection established to {}", addr);
            
            info!("Starting TLS handshake with SNI name: {}", server_name_str);
            let server_name = ServerName::try_from(server_name_str.to_owned())
                .map_err(|e| anyhow!("Invalid server name: {:?}", e))?;
            
            let tls_stream = connector
                .connect(server_name, tcp_stream)
                .await
                .map_err(|e| anyhow!("TLS connection failed: {}", e))?;

            info!("TLS connection established successfully");
            return Ok(tls_stream);
        }

        #[cfg(not(debug_assertions))]
        if self.config.skip_cert_verification {
            return Err(anyhow!(
                "skip_cert_verification is not allowed in release builds. \
                This option is only available for debugging and testing purposes. \
                Please use proper TLS certificate validation in production."
            ));
        }

        // Use system root certificates
        let mut root_store = RootCertStore::empty();
        for cert_der in rustls_native_certs::load_native_certs()? {
            root_store.add(CertificateDer::from(cert_der.as_ref()))
                .map_err(|_| anyhow!("Failed to add root cert"))?;
        }

        let config = tokio_rustls::rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let connector = TlsConnector::from(Arc::new(config));
        let tcp_stream = TcpStream::connect(addr).await?;
        debug!("TCP connection established to {}", addr);

        info!("Starting TLS handshake with SNI name: {}", server_name_str);
        let server_name = rustls::pki_types::ServerName::try_from(server_name_str.to_owned())
            .map_err(|e| anyhow!("Invalid server name: {:?}", e))?;

        let tls_stream = connector
            .connect(server_name, tcp_stream)
            .await
            .map_err(|e| anyhow!("TLS connection failed: {}", e))?;

        info!("TLS connection established successfully");
        Ok(tls_stream)
    }

    /// Execute the ROXY handshake protocol
    async fn execute_handshake(&mut self) -> anyhow::Result<()> {
        // Phase 2.1: Send RoxyInit
        debug!("Sending RoxyInit");
        let client_nonce: [u8; SCRAM_NONCE_SIZE] = rand::random();
        
        // Generate SCRAM client-first message
        let scram_client = ScramClient::new(&self.config.username, &self.config.password)?;
        let client_first = scram_client.client_first_message();
        
        let init_frame = Frame::RoxyInit(RoxyInit {
            version: PROTOCOL_VERSION,
            flags: 0,
            client_nonce,
            capabilities: 0x01,
            padding: client_first.as_bytes().to_vec(),
        });

        let stream = self.tls_stream.as_mut()
            .ok_or_else(|| anyhow!("TLS stream not established"))?;

        // Send init frame
        {
            let mut frame_data = FrameParser::serialize(&init_frame)?;
            FrameParser::add_padding(&mut frame_data, 255);
            stream.write_all(&frame_data).await?;
            stream.flush().await?;
        }

        // Phase 2.2: Receive RoxyChallenge
        debug!("Waiting for RoxyChallenge");
        let challenge_frame = {
            let mut buf = [0u8; 8192];
            let mut read_buf = Vec::new();
            loop {
                let n = stream.read(&mut buf).await?;
                if n == 0 {
                    return Err(anyhow!("Connection closed by server"));
                }
                read_buf.extend_from_slice(&buf[..n]);
                if read_buf.len() >= 4 {
                    match FrameParser::parse(&read_buf) {
                        Ok((frame, consumed)) => {
                            read_buf.drain(..consumed);
                            break Ok(frame);
                        }
                        Err(e) => {
                            if e.to_string().contains("Incomplete frame") {
                                continue;
                            } else {
                                break Err(e);
                            }
                        }
                    }
                }
            }
        }?;

        let (session_id, _server_nonce, challenge_data) = match challenge_frame {
            Frame::RoxyChallenge(challenge) => {
                if challenge.auth_method != 0x01 {
                    return Err(anyhow!("Unsupported authentication method"));
                }
                (challenge.session_id, challenge.server_nonce, challenge.challenge_data)
            }
            _ => return Err(anyhow!("Expected RoxyChallenge, got different frame")),
        };

        debug!("Received RoxyChallenge with session_id: {}", session_id);

        // Parse challenge data as SCRAM server-first message
        let server_first = String::from_utf8(challenge_data)?;
        debug!("Server-first message: {}", server_first);

        // Phase 2.3: Perform SCRAM authentication
        let mut scram_client = ScramClient::new(&self.config.username, &self.config.password)?;
        scram_client.process_server_first(&server_first)?;
        let client_final_without_proof = scram_client.client_final_message()?;

        debug!("Sending RoxyAuth");
        let auth_frame = Frame::RoxyAuth(RoxyAuth {
            session_id,
            auth_proof: client_final_without_proof.as_bytes().to_vec(),
            requested_routes: self.config.requested_routes.clone(),
            padding: Vec::new(),
        });

        {
            let mut frame_data = FrameParser::serialize(&auth_frame)?;
            FrameParser::add_padding(&mut frame_data, 255);
            stream.write_all(&frame_data).await?;
            stream.flush().await?;
        }

        // Phase 2.4: Receive RoxyWelcome
        debug!("Waiting for RoxyWelcome");
        let welcome_frame = {
            let mut buf = [0u8; 8192];
            let mut read_buf = Vec::new();
            loop {
                let n = stream.read(&mut buf).await?;
                if n == 0 {
                    return Err(anyhow!("Connection closed by server"));
                }
                read_buf.extend_from_slice(&buf[..n]);
                if read_buf.len() >= 4 {
                    match FrameParser::parse(&read_buf) {
                        Ok((frame, consumed)) => {
                            read_buf.drain(..consumed);
                            break Ok(frame);
                        }
                        Err(e) => {
                            if e.to_string().contains("Incomplete frame") {
                                continue;
                            } else {
                                break Err(e);
                            }
                        }
                    }
                }
            }
        }?;

        let (_server_final, session_lifetime, granted_routes) = match welcome_frame {
            Frame::RoxyWelcome(welcome) => {
                if welcome.status != 0x00 {
                    return Err(anyhow!("Authentication failed: status code {}", welcome.status));
                }
                // Extract server-final from dedicated field and verify server signature
                let server_final = std::str::from_utf8(&welcome.server_final)
                    .map_err(|_| anyhow!("Invalid server-final encoding"))?;
                scram_client.verify_server_final(server_final)
                    .map_err(|e| anyhow!("Server signature verification failed: {}", e))?;
                
                debug!("Server signature verified successfully");
                (welcome.server_final, welcome.session_lifetime, welcome.granted_routes)
            }
            _ => return Err(anyhow!("Expected RoxyWelcome, got different frame")),
        };

        debug!("Authentication successful, session_id: {}", session_id);

        // Derive session key using HKDF (must match server's derivation)
        // Server uses: salt = session_id, ikm = stored_key
        let session_key = derive_session_key(
            session_id.as_bytes(),
            scram_client.stored_key(),
            session_id.as_bytes(),
        )?;

        // Create cipher
        let cipher = ChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(&session_key));

        // Store session state
        self.cipher = Some(cipher);
        self.nonce_generator = Some(Arc::new(NonceGenerator::new(*session_id.as_bytes())));
        self.session_info = Some(SessionInfo {
            session_id,
            granted_routes,
            session_lifetime,
        });

        info!("ROXY handshake complete, session established");
        Ok(())
    }


    /// Send data on a stream
    pub async fn send_data(&mut self, stream_id: u32, data: &[u8]) -> anyhow::Result<()> {
        let cipher = self.cipher
            .as_ref()
            .ok_or_else(|| anyhow!("Not connected"))?;
        let nonce_gen = self.nonce_generator
            .as_ref()
            .ok_or_else(|| anyhow!("Not connected"))?;

        // Generate nonce using the proper nonce generator
        let nonce = nonce_gen.generate(stream_id);

        // Get session info to ensure session is established
        let _session_id = self.session_info
            .as_ref()
            .ok_or_else(|| anyhow!("Session not established"))?
            .session_id;

        // Encrypt using the cipher directly by wrapping it in our encryption function
        // Actually, we need to pass the key bytes to encrypt_data, but they're not exposed
        // Let me use the cipher's encrypt method directly
        use chacha20poly1305::aead::Aead;
        let cipher_obj = cipher;
        let nonce_obj = chacha20poly1305::Nonce::from_slice(&nonce);
        let encrypted = cipher_obj
            .encrypt(nonce_obj, data)
            .map_err(|e| anyhow!("Encryption failed: {}", e))?;

        let data_frame = Frame::Data(DataFrame {
            stream_id,
            payload_len: encrypted.len() as u16,
            flags: 0,
            nonce,
            payload: encrypted,
            padding: Vec::new(),
        });

        let stream = self.tls_stream.as_mut()
            .ok_or_else(|| anyhow!("TLS stream not available"))?;

        let mut frame_data = FrameParser::serialize(&data_frame)?;
        FrameParser::add_padding(&mut frame_data, 255);
        
        // Apply DPI bypass obfuscation: traffic shaping with padding
        let shaper = TrafficShaper::new();
        let _shaped_chunks = shaper.shape(&frame_data);
        // In production, shaped chunks would be sent with timing delays
        PaddingStrategy::new(1024).add_padding(&mut frame_data);
        // Optional: Add timing jitter before send
        TimingObfuscator::new(0, 10).add_jitter().await;
        
        stream.write_all(&frame_data).await?;
        stream.flush().await?;

        debug!("Sent {} bytes on stream {}", data.len(), stream_id);

        Ok(())
    }

    /// Receive data from a stream
    pub async fn receive_data(&mut self) -> anyhow::Result<(u32, Vec<u8>)> {
        let cipher = self.cipher
            .as_ref()
            .ok_or_else(|| anyhow!("Not connected"))?;

        let stream = self.tls_stream.as_mut()
            .ok_or_else(|| anyhow!("TLS stream not available"))?;

        loop {
            let frame = {
                let mut buf = [0u8; 8192];
                let mut read_buf = Vec::new();
                loop {
                    let n = stream.read(&mut buf).await?;
                    if n == 0 {
                        return Err(anyhow!("Connection closed by server"));
                    }
                    read_buf.extend_from_slice(&buf[..n]);
                    if read_buf.len() >= 4 {
                        match FrameParser::parse(&read_buf) {
                            Ok((frame, consumed)) => {
                                read_buf.drain(..consumed);
                                break Ok(frame);
                            }
                            Err(e) => {
                                if e.to_string().contains("Incomplete frame") {
                                    continue;
                                } else {
                                    break Err(e);
                                }
                            }
                        }
                    }
                }
            }?;

            if let Frame::Data(data_frame) = frame {
                // Decrypt using the established cipher with proper nonce
                use chacha20poly1305::aead::Aead;
                let cipher_obj = cipher;
                let nonce_obj = chacha20poly1305::Nonce::from_slice(&data_frame.nonce);
                let plaintext = cipher_obj
                    .decrypt(nonce_obj, data_frame.payload.as_ref())
                    .map_err(|e| anyhow!("Decryption failed: {}", e))?;

                debug!("Received {} bytes on stream {}", plaintext.len(), data_frame.stream_id);
                return Ok((data_frame.stream_id, plaintext));
            }
        }
    }

    /// Disconnect from the server
    pub async fn disconnect(&mut self) -> anyhow::Result<()> {
        if let Some(mut stream) = self.tls_stream.take() {
            let close_frame = Frame::Close;
            let frame_data = FrameParser::serialize(&close_frame)?;
            let _ = stream.write_all(&frame_data).await;
            let _ = stream.shutdown().await;
        }
        self.session_info = None;
        self.cipher = None;
        self.nonce_generator = None;
        info!("Disconnected from server");
        Ok(())
    }

    /// Get session information
    pub fn session_info(&self) -> Option<&SessionInfo> {
        self.session_info.as_ref()
    }

    /// Check if connected
    pub fn is_connected(&self) -> bool {
        self.tls_stream.is_some() && self.session_info.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_config_builder() {
        let config = RoxyClientConfig::builder("127.0.0.1:8443")
            .credentials("alice", "password123")
            .routes(vec!["/api/*".to_string()])
            .build();

        assert!(config.is_ok());
        let cfg = config.unwrap();
        assert_eq!(cfg.username, "alice");
        assert_eq!(cfg.requested_routes.len(), 1);
    }

    #[test]
    fn test_client_config_builder_missing_credentials() {
        let config = RoxyClientConfig::builder("127.0.0.1:8443")
            .build();

        assert!(config.is_err());
    }

    #[test]
    fn test_client_new() {
        let config = RoxyClientConfig::builder("127.0.0.1:8443")
            .credentials("alice", "password")
            .build()
            .unwrap();

        let client = RoxyClient::new(config);
        assert!(!client.is_connected());
    }
}
