//! Client-side SOCKS5 proxy implementation
//!
//! This module implements a local SOCKS5 listener that accepts connections,
//! performs SOCKS5 handshake (no-auth), reads CONNECT requests, and tunnels
//! traffic through ROXY using direct protocol frame handling with ChaCha20-Poly1305 encryption.

use super::protocol::{atyp, auth, commands, reply, SOCKS_VERSION};
use crate::auth::ScramClient;
use crate::crypto::{derive_session_key, SCRAM_NONCE_SIZE};
use crate::protocol::{Frame, FrameParser, RoxyInit, RoxyAuth, DataFrame, PROTOCOL_VERSION};
use anyhow::anyhow;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use chacha20poly1305::aead::Aead;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, tcp::{OwnedReadHalf, OwnedWriteHalf}};
use tokio::sync::Mutex;
use tracing::{debug, info, error};
use uuid::Uuid;

const STREAM_ID: u32 = 1;
const BUFFER_SIZE: usize = 8192;

/// Run the client-side SOCKS5 proxy
pub async fn run(config: &crate::config::Config) -> anyhow::Result<()> {
    let socks_config = &config.socks5;
    if !socks_config.enabled {
        return Err(anyhow!("SOCKS5 is not enabled"));
    }

    let listener_addr = format!("{}:{}", socks_config.bind_addr, socks_config.client_port);
    let listener = TcpListener::bind(&listener_addr).await
        .map_err(|e| anyhow!("Failed to bind SOCKS5 client listener on {}: {}", listener_addr, e))?;

    info!("SOCKS5 client proxy listening on {}", listener_addr);

    loop {
        let (socket, peer_addr) = listener.accept().await?;
        debug!("Accepted SOCKS5 connection from {}", peer_addr);

        let config_clone = config.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_socks5_client_conn(socket, peer_addr, &config_clone).await {
                debug!("SOCKS5 connection error from {}: {}", peer_addr, e);
            }
        });
    }
}

/// Handle a single SOCKS5 client connection
async fn handle_socks5_client_conn(
    mut socket: TcpStream,
    peer_addr: SocketAddr,
    config: &crate::config::Config,
) -> anyhow::Result<()> {
    let _span = tracing::info_span!("socks5_client", %peer_addr);

    // SOCKS5 handshake: VER NMETHODS [METHODS]
    let mut buf = [0u8; 2];
    socket.read_exact(&mut buf).await?;
    let version = buf[0];
    let nmethods = buf[1] as usize;

    if version != SOCKS_VERSION {
        return Err(anyhow!("Unsupported SOCKS version: {}", version));
    }

    let mut methods = vec![0u8; nmethods];
    socket.read_exact(&mut methods).await?;

    if !methods.contains(&auth::NO_AUTH) {
        socket.write_all(&[SOCKS_VERSION, auth::NO_ACCEPTABLE_METHODS]).await?;
        return Err(anyhow!("No acceptable authentication methods"));
    }

    // Reply with no authentication required
    socket.write_all(&[SOCKS_VERSION, auth::NO_AUTH]).await?;
    debug!("SOCKS5 handshake complete");

    // Read CONNECT request: VER CMD RSV ATYP DST.ADDR DST.PORT
    let mut buf = [0u8; 4];
    socket.read_exact(&mut buf).await?;
    let ver = buf[0];
    let cmd = buf[1];
    let _rsv = buf[2];
    let atyp = buf[3];

    if ver != SOCKS_VERSION {
        return Err(anyhow!("Invalid SOCKS version in request: {}", ver));
    }

    if cmd != commands::CONNECT {
        send_socks5_reply(&mut socket, reply::COMMAND_NOT_SUPPORTED).await?;
        return Err(anyhow!("Unsupported SOCKS command: {}", cmd));
    }

    // Parse destination address based on ATYP
    let (host, port) = parse_socks5_address(&mut socket, atyp).await?;
    info!("SOCKS5 CONNECT request to {}:{}", host, port);

    // Build SOCKS5 CONNECT request bytes to send to remote via ROXY
    let socks5_request = build_socks5_connect_request(&host, port)?;

    // Connect to ROXY server
    // TODO: Get server address from config - for now assume localhost
    let server_addr = "127.0.0.1:8443";
    let mut roxy_stream = TcpStream::connect(server_addr).await
        .map_err(|e| anyhow!("Failed to connect to ROXY server at {}: {}", server_addr, e))?;
    
    debug!("Connected to ROXY server at {}", server_addr);

    // Perform ROXY handshake
    let (cipher, _session_id) = perform_roxy_handshake(&mut roxy_stream, config).await?;
    debug!("ROXY handshake complete");

    // Send SOCKS5 CONNECT request as first DataFrame payload to ROXY
    send_data_frame(&mut roxy_stream, STREAM_ID, &socks5_request, &cipher).await?;
    debug!("Sent SOCKS5 CONNECT request via ROXY");

    // Receive SOCKS5 response from ROXY
    let response_payload = recv_data_frame(&mut roxy_stream, STREAM_ID, &cipher).await?;
    
    if response_payload.len() < 2 || response_payload[0] != SOCKS_VERSION {
        send_socks5_reply(&mut socket, reply::GENERAL_FAILURE).await?;
        return Err(anyhow!("Invalid SOCKS5 response from remote"));
    }

    let rep = response_payload[1];
    if rep != reply::SUCCESS {
        send_socks5_reply(&mut socket, rep).await?;
        return Err(anyhow!("Remote server rejected CONNECT"));
    }

    // Send success reply to local client
    send_socks5_reply(&mut socket, reply::SUCCESS).await?;
    debug!("Sent SOCKS5 success reply to local client");

    // Bidirectional pipe: local <-> ROXY
    let (mut client_read, mut client_write) = socket.into_split();
    let (mut roxy_read, roxy_write) = roxy_stream.into_split();

    let roxy_write = Arc::new(Mutex::new(roxy_write));
    let cipher = Arc::new(cipher);

    let roxy_write_clone = roxy_write.clone();
    let cipher_clone = cipher.clone();
    let client_to_roxy = tokio::spawn(async move {
        let mut buf = [0u8; BUFFER_SIZE];
        loop {
            match client_read.read(&mut buf).await {
                Ok(0) => break, // EOF
                Ok(n) => {
                    if let Err(e) = send_data_frame_async(
                        roxy_write_clone.clone(),
                        STREAM_ID,
                        &buf[..n],
                        &cipher_clone,
                    )
                    .await
                    {
                        error!("Failed to send data to ROXY: {}", e);
                        break;
                    }
                }
                Err(e) => {
                    debug!("Read from client failed: {}", e);
                    break;
                }
            }
        }
    });

    let cipher_clone = cipher.clone();
    let roxy_to_client = tokio::spawn(async move {
        loop {
            match recv_data_frame_async(&mut roxy_read, STREAM_ID, &cipher_clone).await {
                Ok(payload) => {
                    if let Err(e) = client_write.write_all(&payload).await {
                        error!("Failed to write to client: {}", e);
                        break;
                    }
                    if let Err(e) = client_write.flush().await {
                        error!("Failed to flush client: {}", e);
                        break;
                    }
                }
                Err(e) => {
                    debug!("Receive from ROXY failed: {}", e);
                    break;
                }
            }
        }
    });

    // Wait for either direction to close
    tokio::select! {
        _ = client_to_roxy => { info!("Client closed connection"); }
        _ = roxy_to_client => { info!("ROXY closed connection"); }
    }

    Ok(())
}

/// Perform ROXY handshake: ROXY_INIT -> ROXY_CHALLENGE -> ROXY_AUTH -> ROXY_WELCOME
async fn perform_roxy_handshake(
    stream: &mut TcpStream,
    config: &crate::config::Config,
) -> anyhow::Result<(ChaCha20Poly1305, Uuid)> {
    // Step 1: Send ROXY_INIT
    let mut client_nonce = [0u8; SCRAM_NONCE_SIZE];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut client_nonce);

    let init_frame = Frame::RoxyInit(RoxyInit {
        version: PROTOCOL_VERSION,
        flags: 0,
        client_nonce,
        capabilities: 0x01,
        padding: Vec::new(),
    });

    let mut init_data = FrameParser::serialize(&init_frame)?;
    FrameParser::add_padding(&mut init_data, 255);
    let new_len = (init_data.len() - 4) as u32;
    init_data[0..4].copy_from_slice(&new_len.to_be_bytes());
    stream.write_all(&init_data).await?;
    stream.flush().await?;
    debug!("Sent ROXY_INIT");

    // Step 2: Receive ROXY_CHALLENGE
    let mut frame_len_buf = [0u8; 4];
    stream.read_exact(&mut frame_len_buf).await?;
    let frame_len = u32::from_be_bytes(frame_len_buf) as usize;
    let mut frame_buf = vec![0u8; frame_len];
    stream.read_exact(&mut frame_buf).await?;

    let mut challenge_data = frame_len_buf.to_vec();
    challenge_data.extend_from_slice(&frame_buf);

    let (challenge_frame, _) = FrameParser::parse(&challenge_data)?;
    let (session_id, server_nonce, _auth_method, challenge_bytes) = match challenge_frame {
        Frame::RoxyChallenge(ch) => (ch.session_id, ch.server_nonce, ch.auth_method, ch.challenge_data),
        _ => return Err(anyhow!("Expected ROXY_CHALLENGE")),
    };
    debug!("Received ROXY_CHALLENGE for session {}", session_id);

    // Step 3: Perform SCRAM authentication
    // Get first user for testing; in production, this would be configured
    let (username, _password) = config
        .users
        .iter()
        .next()
        .map(|(u, u_data)| (u.clone(), u_data.clone()))
        .ok_or_else(|| anyhow!("No users configured"))?;

    let mut scram = ScramClient::new(&username, "dummy_password")?;
    
    // Process server's SCRAM challenge
    let challenge_str = String::from_utf8(challenge_bytes)?;
    scram.process_server_first(&challenge_str)?;
    
    // Generate client final message (with proof)
    let auth_proof = scram.client_final_message()?.into_bytes();

    // Step 4: Send ROXY_AUTH
    let auth_frame = Frame::RoxyAuth(RoxyAuth {
        session_id,
        auth_proof,
        requested_routes: vec!["*".to_string()],
        padding: Vec::new(),
    });

    let mut auth_data = FrameParser::serialize(&auth_frame)?;
    FrameParser::add_padding(&mut auth_data, 255);
    let new_len = (auth_data.len() - 4) as u32;
    auth_data[0..4].copy_from_slice(&new_len.to_be_bytes());
    stream.write_all(&auth_data).await?;
    stream.flush().await?;
    debug!("Sent ROXY_AUTH");

    // Step 5: Receive ROXY_WELCOME
    let mut frame_len_buf = [0u8; 4];
    stream.read_exact(&mut frame_len_buf).await?;
    let frame_len = u32::from_be_bytes(frame_len_buf) as usize;
    let mut frame_buf = vec![0u8; frame_len];
    stream.read_exact(&mut frame_buf).await?;

    let mut welcome_data = frame_len_buf.to_vec();
    welcome_data.extend_from_slice(&frame_buf);

    let (welcome_frame, _) = FrameParser::parse(&welcome_data)?;
    let (status, _obf_config, _server_final) = match welcome_frame {
        Frame::RoxyWelcome(w) => (w.status, w.obf_config, w.server_final),
        _ => return Err(anyhow!("Expected ROXY_WELCOME")),
    };

    if status != 0 {
        return Err(anyhow!("Authentication failed: status {}", status));
    }

    debug!("Received ROXY_WELCOME, establishing cipher");

    // Derive session key from client_nonce + server_nonce
    let mut salt = client_nonce.to_vec();
    salt.extend_from_slice(&server_nonce);

    // Use stored_key from config user for key derivation
    let user = config
        .users
        .get(&username)
        .ok_or_else(|| anyhow!("User not found"))?;
    
    let session_key = derive_session_key(&salt, &user.stored_key, session_id.as_bytes())?;
    let cipher = ChaCha20Poly1305::new_from_slice(&session_key)?;

    Ok((cipher, session_id))
}

/// Send a DataFrame with encrypted payload
async fn send_data_frame(
    stream: &mut TcpStream,
    stream_id: u32,
    payload: &[u8],
    cipher: &ChaCha20Poly1305,
) -> anyhow::Result<()> {
    let mut nonce_bytes = [0u8; 12];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let encrypted = cipher
        .encrypt(nonce, payload)
        .map_err(|e| anyhow!("Encryption failed: {}", e))?;

    let data_frame = DataFrame {
        stream_id,
        payload_len: encrypted.len() as u16,
        flags: 0,
        nonce: nonce_bytes,
        payload: encrypted,
        padding: Vec::new(),
    };

    let frame = Frame::Data(data_frame);
    let mut frame_data = FrameParser::serialize(&frame)?;
    FrameParser::add_padding(&mut frame_data, 255);
    let new_len = (frame_data.len() - 4) as u32;
    frame_data[0..4].copy_from_slice(&new_len.to_be_bytes());
    stream.write_all(&frame_data).await?;
    stream.flush().await?;

    Ok(())
}

/// Send DataFrame from async context with Mutex-protected write half
async fn send_data_frame_async(
    roxy_write: Arc<Mutex<OwnedWriteHalf>>,
    stream_id: u32,
    payload: &[u8],
    cipher: &ChaCha20Poly1305,
) -> anyhow::Result<()> {
    let mut nonce_bytes = [0u8; 12];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let encrypted = cipher
        .encrypt(nonce, payload)
        .map_err(|e| anyhow!("Encryption failed: {}", e))?;

    let data_frame = DataFrame {
        stream_id,
        payload_len: encrypted.len() as u16,
        flags: 0,
        nonce: nonce_bytes,
        payload: encrypted,
        padding: Vec::new(),
    };

    let frame = Frame::Data(data_frame);
    let mut frame_data = FrameParser::serialize(&frame)?;
    FrameParser::add_padding(&mut frame_data, 255);
    let new_len = (frame_data.len() - 4) as u32;
    frame_data[0..4].copy_from_slice(&new_len.to_be_bytes());

    let mut write_guard = roxy_write.lock().await;
    write_guard.write_all(&frame_data).await?;
    write_guard.flush().await?;

    Ok(())
}

/// Receive a DataFrame and decrypt payload
async fn recv_data_frame(
    stream: &mut TcpStream,
    _expected_stream_id: u32,
    cipher: &ChaCha20Poly1305,
) -> anyhow::Result<Vec<u8>> {
    let mut frame_len_buf = [0u8; 4];
    stream.read_exact(&mut frame_len_buf).await?;
    let frame_len = u32::from_be_bytes(frame_len_buf) as usize;
    let mut frame_buf = vec![0u8; frame_len];
    stream.read_exact(&mut frame_buf).await?;

    let mut frame_data = frame_len_buf.to_vec();
    frame_data.extend_from_slice(&frame_buf);

    let (frame, _) = FrameParser::parse(&frame_data)?;
    match frame {
        Frame::Data(df) => {
            let nonce = Nonce::from_slice(&df.nonce);
            let decrypted = cipher
                .decrypt(nonce, df.payload.as_ref())
                .map_err(|e| anyhow!("Decryption failed: {}", e))?;
            Ok(decrypted)
        }
        _ => Err(anyhow!("Expected Data frame")),
    }
}

/// Receive DataFrame from async context with OwnedReadHalf
async fn recv_data_frame_async(
    stream: &mut OwnedReadHalf,
    _expected_stream_id: u32,
    cipher: &Arc<ChaCha20Poly1305>,
) -> anyhow::Result<Vec<u8>> {
    let mut frame_len_buf = [0u8; 4];
    stream.read_exact(&mut frame_len_buf).await?;
    let frame_len = u32::from_be_bytes(frame_len_buf) as usize;
    let mut frame_buf = vec![0u8; frame_len];
    stream.read_exact(&mut frame_buf).await?;

    let mut frame_data = frame_len_buf.to_vec();
    frame_data.extend_from_slice(&frame_buf);

    let (frame, _) = FrameParser::parse(&frame_data)?;
    match frame {
        Frame::Data(df) => {
            let nonce = Nonce::from_slice(&df.nonce);
            let decrypted = cipher
                .decrypt(nonce, df.payload.as_ref())
                .map_err(|e| anyhow!("Decryption failed: {}", e))?;
            Ok(decrypted)
        }
        _ => Err(anyhow!("Expected Data frame")),
    }
}

/// Parse SOCKS5 address from the request
async fn parse_socks5_address(
    socket: &mut TcpStream,
    atyp: u8,
) -> anyhow::Result<(String, u16)> {
    match atyp {
        atyp::IPV4 => {
            let mut buf = [0u8; 6];
            socket.read_exact(&mut buf).await?;
            let ip = format!("{}.{}.{}.{}", buf[0], buf[1], buf[2], buf[3]);
            let port = u16::from_be_bytes([buf[4], buf[5]]);
            Ok((ip, port))
        }
        atyp::DOMAIN => {
            let mut len_buf = [0u8; 1];
            socket.read_exact(&mut len_buf).await?;
            let len = len_buf[0] as usize;
            let mut domain_buf = vec![0u8; len + 2];
            socket.read_exact(&mut domain_buf).await?;
            let domain = String::from_utf8(domain_buf[..len].to_vec())?;
            let port = u16::from_be_bytes([domain_buf[len], domain_buf[len + 1]]);
            Ok((domain, port))
        }
        atyp::IPV6 => {
            let mut buf = [0u8; 18];
            socket.read_exact(&mut buf).await?;
            let mut ip = String::new();
            for i in (0..16).step_by(2) {
                if i > 0 {
                    ip.push(':');
                }
                ip.push_str(&format!(
                    "{:x}",
                    u16::from_be_bytes([buf[i], buf[i + 1]])
                ));
            }
            let port = u16::from_be_bytes([buf[16], buf[17]]);
            Ok((ip, port))
        }
        _ => Err(anyhow!("Unsupported address type: {}", atyp)),
    }
}

/// Send SOCKS5 reply: VER REP RSV ATYP BND.ADDR BND.PORT
async fn send_socks5_reply(socket: &mut TcpStream, rep: u8) -> anyhow::Result<()> {
    let reply = [SOCKS_VERSION, rep, 0x00, atyp::IPV4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    socket.write_all(&reply).await?;
    socket.flush().await?;
    Ok(())
}

/// Build SOCKS5 CONNECT request: VER CMD RSV ATYP DST.ADDR DST.PORT
fn build_socks5_connect_request(host: &str, port: u16) -> anyhow::Result<Vec<u8>> {
    let mut request = vec![SOCKS_VERSION, commands::CONNECT, 0x00];

    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        match ip {
            std::net::IpAddr::V4(ipv4) => {
                request.push(atyp::IPV4);
                request.extend_from_slice(&ipv4.octets());
            }
            std::net::IpAddr::V6(ipv6) => {
                request.push(atyp::IPV6);
                request.extend_from_slice(&ipv6.octets());
            }
        }
    } else {
        request.push(atyp::DOMAIN);
        let domain_bytes = host.as_bytes();
        if domain_bytes.len() > 255 {
            return Err(anyhow!(
                "Domain name too long: {} bytes (max 255)",
                domain_bytes.len()
            ));
        }
        request.push(domain_bytes.len() as u8);
        request.extend_from_slice(domain_bytes);
    }

    request.extend_from_slice(&port.to_be_bytes());
    Ok(request)
}