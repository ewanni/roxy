//! Server-side SOCKS5 endpoint implementation
//!
//! This module implements a local SOCKS5 server that accepts connections
//! and routes them through the existing ROXY server handling logic.

use super::protocol::{
    atyp, auth, commands, reply, SOCKS_VERSION,
};
use crate::config::Config;
use anyhow::anyhow;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, info, warn};

/// Maximum number of SOCKS5 authentication methods allowed
const MAX_SOCKS5_METHODS: usize = 10;

/// Run the server-side SOCKS5 endpoint
pub async fn run(config: &Config) -> anyhow::Result<()> {
    let bind_addr = format!("{}:{}", config.socks5.bind_addr, config.socks5.server_port);
    let listener = TcpListener::bind(&bind_addr).await
        .map_err(|e| anyhow!("Failed to bind SOCKS5 server listener on {}: {}", bind_addr, e))?;

    info!("SOCKS5 server endpoint listening on {}", bind_addr);

    loop {
        let (socket, peer_addr) = listener.accept().await?;
        info!("Accepted SOCKS5 connection from {} to {} at {}", peer_addr, bind_addr, chrono::Utc::now());

        tokio::spawn(async move {
            if let Err(e) = handle_socks5_connection(socket, peer_addr).await {
                warn!("SOCKS5 connection error from {}: {}", peer_addr, e);
            }
        });
    }
}

/// Handle a single SOCKS5 connection
async fn handle_socks5_connection(mut socket: TcpStream, peer_addr: SocketAddr) -> anyhow::Result<()> {
    // SOCKS5 handshake
    let mut buf = [0u8; 2];
    socket.read_exact(&mut buf).await?;
    let version = buf[0];
    let nmethods = buf[1] as usize;

    if version != SOCKS_VERSION {
        return Err(anyhow!("Unsupported SOCKS version: {}", version));
    }

    if nmethods > MAX_SOCKS5_METHODS {
        return Err(anyhow!("Too many SOCKS5 auth methods: {}", nmethods));
    }

    let mut methods = vec![0u8; nmethods];
    socket.read_exact(&mut methods).await?;

    // We don't support authentication
    if !methods.contains(&auth::NO_AUTH) {
        socket.write_all(&[SOCKS_VERSION, auth::NO_ACCEPTABLE_METHODS]).await?;
        return Err(anyhow!("No acceptable authentication methods"));
    }

    // Reply with no authentication required
    socket.write_all(&[SOCKS_VERSION, auth::NO_AUTH]).await?;

    // Read CONNECT request
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

    // Parse destination address
    let (host, port) = parse_socks5_address(&mut socket, atyp).await?;

    info!("SOCKS5 CONNECT request from {} to {}:{} at {}", peer_addr, host, port, chrono::Utc::now());

    // Here we would route through ROXY server logic
    // For now, simulate by connecting directly
    match TcpStream::connect(format!("{}:{}", host, port)).await {
        Ok(mut upstream) => {
            // Send success reply
            send_socks5_reply(&mut socket, reply::SUCCESS).await?;

            // Forward data bidirectionally
            let (mut client_read, mut client_write) = socket.split();
            let (mut upstream_read, mut upstream_write) = upstream.split();

            let client_to_upstream = tokio::io::copy(&mut client_read, &mut upstream_write);
            let upstream_to_client = tokio::io::copy(&mut upstream_read, &mut client_write);

            tokio::select! {
                result = client_to_upstream => {
                    if let Err(e) = result {
                        debug!("Client to upstream copy failed: {}", e);
                    }
                }
                result = upstream_to_client => {
                    if let Err(e) = result {
                        debug!("Upstream to client copy failed: {}", e);
                    }
                }
            }

            info!("SOCKS5 connection from {} ended at {}", peer_addr, chrono::Utc::now());
        }
        Err(e) => {
            warn!("Failed to connect to {}:{}: {}", host, port, e);
            send_socks5_reply(&mut socket, reply::GENERAL_FAILURE).await?;
            return Err(anyhow!("Connection failed: {}", e));
        }
    }

    Ok(())
}

/// Parse SOCKS5 address from the request
async fn parse_socks5_address(socket: &mut TcpStream, atyp: u8) -> anyhow::Result<(String, u16)> {
    match atyp {
        atyp::IPV4 => {
            // IPv4
            let mut buf = [0u8; 6]; // 4 bytes IP + 2 bytes port
            socket.read_exact(&mut buf).await?;
            let ip = format!("{}.{}.{}.{}", buf[0], buf[1], buf[2], buf[3]);
            let port = u16::from_be_bytes([buf[4], buf[5]]);
            Ok((ip, port))
        }
        atyp::DOMAIN => {
            // Domain name
            let mut len_buf = [0u8; 1];
            socket.read_exact(&mut len_buf).await?;
            let len = len_buf[0] as usize;
            let mut domain_buf = vec![0u8; len + 2]; // domain + port
            socket.read_exact(&mut domain_buf).await?;
            let domain = String::from_utf8(domain_buf[..len].to_vec())?;
            let port = u16::from_be_bytes([domain_buf[len], domain_buf[len + 1]]);
            Ok((domain, port))
        }
        atyp::IPV6 => {
            // IPv6
            let mut buf = [0u8; 18]; // 16 bytes IP + 2 bytes port
            socket.read_exact(&mut buf).await?;
            let mut ip = String::new();
            for i in (0..16).step_by(2) {
                if i > 0 {
                    ip.push(':');
                }
                ip.push_str(&format!("{:x}", u16::from_be_bytes([buf[i], buf[i + 1]])));
            }
            let port = u16::from_be_bytes([buf[16], buf[17]]);
            Ok((ip, port))
        }
        _ => Err(anyhow!("Unsupported address type: {}", atyp)),
    }
}

/// Send SOCKS5 reply
async fn send_socks5_reply(socket: &mut TcpStream, rep: u8) -> anyhow::Result<()> {
    // VER REP RSV ATYP BND.ADDR BND.PORT
    let reply = [SOCKS_VERSION, rep, 0x00, atyp::IPV4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    socket.write_all(&reply).await?;
    Ok(())
}