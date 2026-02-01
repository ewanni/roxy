//! Protocol frame definitions and parsing
//!
//! Implements the ROXY protocol frames for obfuscated communication,
//! including handshake phases and data transmission.

use crate::crypto::{NONCE_SIZE, SESSION_ID_SIZE, SCRAM_NONCE_SIZE};
use std::io::{Cursor, Read};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use thiserror::Error;
use rand::Rng;
use rand::RngCore;
use anyhow::anyhow;

/// Errors that can occur during ROXY protocol parsing and serialization.
///
/// These errors cover IO failures, invalid frame formats, length violations,
/// and unsupported command types encountered during protocol operations.
#[derive(Error, Debug)]
pub enum ProtocolError {
    /// Underlying IO error from reading or writing frame data.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    /// Frame parsing failed due to malformed data or unexpected format.
    #[error("Parse error: {0}")]
    Parse(String),
    /// Frame serialization failed (e.g., field too large for wire format).
    #[error("Serialization error: {0}")]
    Serialization(String),
    /// Field or frame violates length constraints (security boundary).
    #[error("Invalid length")]
    InvalidLength,
    /// Unrecognized control command byte.
    #[error("Invalid command")]
    InvalidCommand,
}

/// Protocol version (raw byte value)
pub const PROTOCOL_VERSION: u8 = 0x01;

/// HKDF info string prefix for session key derivation
/// Format: "ROXY/<semantic-version> session-key"
pub const HKDF_INFO_PREFIX: &str = "ROXY/1.0 session-key";

/// Maximum frame size (64KB)
pub const MAX_FRAME_SIZE: usize = 65536;

/// Maximum buffer size (64KB)
pub const MAX_BUFFER_SIZE: usize = 65536;

/// Maximum variable-length field size (16KB, same as frame)
pub const MAX_FIELD_SIZE: usize = 16384;

/// Maximum number of routes in a single frame
pub const MAX_ROUTES: usize = 256;

/// Maximum padding size for non-data frames
pub const MAX_PADDING_SIZE: usize = 4096;

/// Maximum frame padding size for obfuscation
pub const MAX_FRAME_PADDING: usize = 255;

/// Maximum cumulative size for all routes in a single frame (640KB)
pub const MAX_TOTAL_ROUTE_SIZE: usize = 640_000;

/// Maximum connections
pub const MAX_CONNECTIONS: usize = 10000;

/// Frame types in the ROXY protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameType {
    /// ROXY_INIT: Client handshake initiation
    RoxyInit = 0x01,
    /// ROXY_CHALLENGE: Server authentication challenge
    RoxyChallenge = 0x02,
    /// ROXY_AUTH: Client authentication response
    RoxyAuth = 0x03,
    /// ROXY_WELCOME: Server welcome and session params
    RoxyWelcome = 0x04,
    /// Data frame
    Data = 0x10,
    /// Ping/keepalive
    Ping = 0x11,
    /// Control message
    Control = 0x12,
    /// Control acknowledgement
    ControlAck = 0x13,
    /// Close
    Close = 0xFF,
}

impl TryFrom<u8> for FrameType {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(FrameType::RoxyInit),
            0x02 => Ok(FrameType::RoxyChallenge),
            0x03 => Ok(FrameType::RoxyAuth),
            0x04 => Ok(FrameType::RoxyWelcome),
            0x10 => Ok(FrameType::Data),
            0x11 => Ok(FrameType::Ping),
            0x12 => Ok(FrameType::Control),
            0x13 => Ok(FrameType::ControlAck),
            0xFF => Ok(FrameType::Close),
            _ => Err(anyhow!("Unknown frame type: 0x{:02x}", value)),
        }
    }
}

/// Ping message for keepalive
#[derive(Debug, Clone)]
pub struct PingMessage {
    pub timestamp: u64,
    pub nonce: [u8; 16],
}

impl Default for PingMessage {
    fn default() -> Self {
        Self::new()
    }
}

impl PingMessage {
    /// Create a new ping message with current timestamp and random nonce
    pub fn new() -> Self {
        let mut nonce = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut nonce);
        Self {
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_millis() as u64),
            nonce,
        }
    }

    /// Serialize ping message to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(24);
        buf.extend_from_slice(&self.timestamp.to_le_bytes());
        buf.extend_from_slice(&self.nonce);
        buf
    }

    /// Deserialize ping message from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self, ProtocolError> {
        if data.len() < 24 {
            return Err(ProtocolError::InvalidLength);
        }
        let timestamp = u64::from_le_bytes(data[0..8].try_into().map_err(|_| ProtocolError::InvalidLength)?);
        let nonce = data[8..24].try_into().map_err(|_| ProtocolError::InvalidLength)?;
        Ok(Self { timestamp, nonce })
    }
}

/// Control command types
#[derive(Debug, Clone)]
pub enum ControlCommand {
    /// Establish new tunnel to destination
    NewTunnel { destination: String },
    /// Close existing tunnel
    CloseTunnel { tunnel_id: u32 },
    /// Update bandwidth limit in Mbps
    UpdateBandwidth { limit_mbps: u32 },
}

/// Control message for tunnel management
#[derive(Debug, Clone)]
pub struct ControlMessage {
    pub command: ControlCommand,
}

impl ControlMessage {
    /// Serialize control message to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        match &self.command {
            ControlCommand::NewTunnel { destination } => {
                buf.push(0);
                let dest_bytes = destination.as_bytes();
                buf.extend_from_slice(&(dest_bytes.len() as u32).to_le_bytes());
                buf.extend_from_slice(dest_bytes);
            }
            ControlCommand::CloseTunnel { tunnel_id } => {
                buf.push(1);
                buf.extend_from_slice(&tunnel_id.to_le_bytes());
            }
            ControlCommand::UpdateBandwidth { limit_mbps } => {
                buf.push(2);
                buf.extend_from_slice(&limit_mbps.to_le_bytes());
            }
        }
        buf
    }

    /// Deserialize control message from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self, ProtocolError> {
        if data.is_empty() {
            return Err(ProtocolError::InvalidLength);
        }
        match data[0] {
            0 => {
                if data.len() < 5 {
                    return Err(ProtocolError::InvalidLength);
                }
                let len = u32::from_le_bytes(
                    data[1..5].try_into().map_err(|_| ProtocolError::InvalidLength)?
                ) as usize;
                if data.len() < 5 + len {
                    return Err(ProtocolError::InvalidLength);
                }
                let destination = String::from_utf8_lossy(&data[5..5 + len]).to_string();
                Ok(Self {
                    command: ControlCommand::NewTunnel { destination },
                })
            }
            1 => {
                if data.len() < 5 {
                    return Err(ProtocolError::InvalidLength);
                }
                let tunnel_id = u32::from_le_bytes(
                    data[1..5].try_into().map_err(|_| ProtocolError::InvalidLength)?
                );
                Ok(Self {
                    command: ControlCommand::CloseTunnel { tunnel_id },
                })
            }
            2 => {
                if data.len() < 5 {
                    return Err(ProtocolError::InvalidLength);
                }
                let limit_mbps = u32::from_le_bytes(
                    data[1..5].try_into().map_err(|_| ProtocolError::InvalidLength)?
                );
                Ok(Self {
                    command: ControlCommand::UpdateBandwidth { limit_mbps },
                })
            }
            _ => Err(ProtocolError::InvalidCommand),
        }
    }
}

/// ROXY_INIT frame payload
#[derive(Debug, Clone)]
pub struct RoxyInit {
    pub version: u8,
    pub flags: u16,
    pub client_nonce: [u8; SCRAM_NONCE_SIZE],
    pub capabilities: u32,
    pub padding: Vec<u8>,
}

/// ROXY_CHALLENGE frame payload
#[derive(Debug, Clone)]
pub struct RoxyChallenge {
    pub session_id: uuid::Uuid,
    pub server_nonce: [u8; SCRAM_NONCE_SIZE],
    pub auth_method: u8,
    pub challenge_data: Vec<u8>, // SCRAM challenge
    pub padding: Vec<u8>,
}

/// ROXY_AUTH frame payload
#[derive(Debug, Clone)]
pub struct RoxyAuth {
    pub session_id: uuid::Uuid,
    pub auth_proof: Vec<u8>, // SCRAM proof
    pub requested_routes: Vec<String>,
    pub padding: Vec<u8>,
}

/// ROXY_WELCOME frame payload
#[derive(Debug, Clone)]
pub struct RoxyWelcome {
    pub status: u8,
    pub session_lifetime: u32,
    pub obf_config: Vec<u8>, // Obfuscation config
    pub server_final: Vec<u8>, // SCRAM server-final message (base64-encoded)
    pub granted_routes: Vec<String>,
    pub padding: Vec<u8>,
}

/// Data frame payload
#[derive(Debug, Clone)]
pub struct DataFrame {
    pub stream_id: u32,
    pub payload_len: u16,
    pub flags: u8,
    pub nonce: [u8; NONCE_SIZE],
    pub payload: Vec<u8>,
    pub padding: Vec<u8>,
}

/// Protocol frame structure
#[derive(Debug, Clone)]
pub enum Frame {
    RoxyInit(RoxyInit),
    RoxyChallenge(RoxyChallenge),
    RoxyAuth(RoxyAuth),
    RoxyWelcome(RoxyWelcome),
    Data(DataFrame),
    Ping,
    Control(Vec<u8>),
    ControlAck,
    Close,
}

/// Parser for ROXY protocol frames
pub struct FrameParser;

impl FrameParser {
    /// Parse a frame from bytes (length-prefixed), returning the frame and consumed bytes
    pub fn parse(data: &[u8]) -> anyhow::Result<(Frame, usize)> {
        if data.len() < 4 {
            return Err(anyhow!("Frame too short"));
        }

        let frame_len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
        if frame_len > MAX_FRAME_SIZE {
            return Err(anyhow!("Frame exceeds maximum size: {} > {}", frame_len, MAX_FRAME_SIZE));
        }

        if data.len() < 4 + frame_len {
            return Err(anyhow!("Incomplete frame"));
        }

        let frame_data = &data[4..4 + frame_len];
        let mut cursor = Cursor::new(frame_data);
        let frame_type_byte = cursor.read_u8()?;
        let frame_type = FrameType::try_from(frame_type_byte)?;

        let frame = match frame_type {
            FrameType::RoxyInit => Self::parse_roxy_init(&mut cursor),
            FrameType::RoxyChallenge => Self::parse_roxy_challenge(&mut cursor),
            FrameType::RoxyAuth => Self::parse_roxy_auth(&mut cursor),
            FrameType::RoxyWelcome => Self::parse_roxy_welcome(&mut cursor),
            FrameType::Data => Self::parse_data_frame(&mut cursor),
            FrameType::Ping => Ok(Frame::Ping),
            FrameType::Control => {
                let mut payload = Vec::new();
                cursor.read_to_end(&mut payload)?;
                // ✅ SECURITY: Validate control payload size
                if payload.len() > MAX_FIELD_SIZE {
                    return Err(anyhow!("Control payload too large: {} > {}", payload.len(), MAX_FIELD_SIZE));
                }
                Ok(Frame::Control(payload))
            }
            FrameType::ControlAck => Ok(Frame::ControlAck),
            FrameType::Close => Ok(Frame::Close),
        }?;

        Ok((frame, 4 + frame_len))
    }

    fn parse_roxy_init(cursor: &mut Cursor<&[u8]>) -> anyhow::Result<Frame> {
        let version = cursor.read_u8()?;
        let flags = cursor.read_u16::<BigEndian>()?;
        let mut client_nonce = [0u8; SCRAM_NONCE_SIZE];
        cursor.read_exact(&mut client_nonce)?;
        let capabilities = cursor.read_u32::<BigEndian>()?;
        let mut padding = Vec::new();
        cursor.read_to_end(&mut padding)?;

        // ✅ SECURITY: Validate padding
        if padding.len() > MAX_PADDING_SIZE {
            return Err(anyhow!("Excessive padding: {} > {}", padding.len(), MAX_PADDING_SIZE));
        }

        Ok(Frame::RoxyInit(RoxyInit {
            version,
            flags,
            client_nonce,
            capabilities,
            padding,
        }))
    }

    fn parse_roxy_challenge(cursor: &mut Cursor<&[u8]>) -> anyhow::Result<Frame> {
        let mut session_id_bytes = [0u8; SESSION_ID_SIZE];
        cursor.read_exact(&mut session_id_bytes)?;
        let session_id = uuid::Uuid::from_bytes(session_id_bytes);
        let mut server_nonce = [0u8; SCRAM_NONCE_SIZE];
        cursor.read_exact(&mut server_nonce)?;
        let auth_method = cursor.read_u8()?;
        let challenge_data_len = cursor.read_u16::<BigEndian>()? as usize;

        // ✅ SECURITY: Validate against maximum field size
        if challenge_data_len > MAX_FIELD_SIZE {
            return Err(anyhow!("challenge_data exceeds maximum size: {} > {}", challenge_data_len, MAX_FIELD_SIZE));
        }

        let mut challenge_data = vec![0u8; challenge_data_len];
        cursor.read_exact(&mut challenge_data)?;
        let mut padding = Vec::new();
        cursor.read_to_end(&mut padding)?;

        // ✅ SECURITY: Validate padding size
        if padding.len() > MAX_PADDING_SIZE {
            return Err(anyhow!("Excessive padding: {} > {}", padding.len(), MAX_PADDING_SIZE));
        }

        Ok(Frame::RoxyChallenge(RoxyChallenge {
            session_id,
            server_nonce,
            auth_method,
            challenge_data,
            padding,
        }))
    }

    fn parse_roxy_auth(cursor: &mut Cursor<&[u8]>) -> anyhow::Result<Frame> {
        let mut session_id_bytes = [0u8; SESSION_ID_SIZE];
        cursor.read_exact(&mut session_id_bytes)?;
        let session_id = uuid::Uuid::from_bytes(session_id_bytes);

        let auth_proof_len = cursor.read_u16::<BigEndian>()? as usize;
        // ✅ SECURITY: Validate proof length
        if auth_proof_len > MAX_FIELD_SIZE {
            return Err(anyhow!("auth_proof exceeds maximum size: {} > {}", auth_proof_len, MAX_FIELD_SIZE));
        }

        let mut auth_proof = vec![0u8; auth_proof_len];
        cursor.read_exact(&mut auth_proof)?;

        let num_routes = cursor.read_u16::<BigEndian>()? as usize;
        // ✅ SECURITY: Validate route count
        if num_routes > MAX_ROUTES {
            return Err(anyhow!("Too many routes: {} > {}", num_routes, MAX_ROUTES));
        }

        let mut requested_routes = Vec::with_capacity(num_routes);
        let mut total_route_size: usize = 0;
        
        for _ in 0..num_routes {
            let route_len = cursor.read_u16::<BigEndian>()? as usize;
            // ✅ SECURITY: Validate individual route length
            if route_len > MAX_FIELD_SIZE {
                return Err(anyhow!("Route length exceeds maximum: {} > {}", route_len, MAX_FIELD_SIZE));
            }

            // ✅ SECURITY: Validate cumulative route size
            total_route_size = total_route_size
                .checked_add(route_len)
                .ok_or_else(|| anyhow!("Total route size overflow"))?;
            
            if total_route_size > MAX_TOTAL_ROUTE_SIZE {
                return Err(anyhow!(
                    "Cumulative route size {} exceeds limit of {}",
                    total_route_size,
                    MAX_TOTAL_ROUTE_SIZE
                ));
            }

            let mut route_bytes = vec![0u8; route_len];
            cursor.read_exact(&mut route_bytes)?;
            let route = String::from_utf8(route_bytes)
                .map_err(|e| anyhow!("Invalid UTF-8 in route: {}", e))?;
            requested_routes.push(route);
        }

        let mut padding = Vec::new();
        cursor.read_to_end(&mut padding)?;
        // ✅ SECURITY: Validate padding
        if padding.len() > MAX_PADDING_SIZE {
            return Err(anyhow!("Excessive padding: {} > {}", padding.len(), MAX_PADDING_SIZE));
        }

        Ok(Frame::RoxyAuth(RoxyAuth {
            session_id,
            auth_proof,
            requested_routes,
            padding,
        }))
    }

    fn parse_roxy_welcome(cursor: &mut Cursor<&[u8]>) -> anyhow::Result<Frame> {
        let status = cursor.read_u8()?;
        let session_lifetime = cursor.read_u32::<BigEndian>()?;

        let obf_config_len = cursor.read_u16::<BigEndian>()? as usize;
        // ✅ SECURITY: Validate config length
        if obf_config_len > MAX_FIELD_SIZE {
            return Err(anyhow!("obf_config exceeds maximum size: {} > {}", obf_config_len, MAX_FIELD_SIZE));
        }

        let mut obf_config = vec![0u8; obf_config_len];
        cursor.read_exact(&mut obf_config)?;

        // Read server_final field (SCRAM server-final message)
        let server_final_len = cursor.read_u16::<BigEndian>()? as usize;
        // ✅ SECURITY: Validate server_final length
        if server_final_len > MAX_FIELD_SIZE {
            return Err(anyhow!("server_final exceeds maximum size: {} > {}", server_final_len, MAX_FIELD_SIZE));
        }

        let mut server_final = vec![0u8; server_final_len];
        cursor.read_exact(&mut server_final)?;

        let num_routes = cursor.read_u16::<BigEndian>()? as usize;
        // ✅ SECURITY: Validate route count
        if num_routes > MAX_ROUTES {
            return Err(anyhow!("Too many routes: {} > {}", num_routes, MAX_ROUTES));
        }

        let mut granted_routes = Vec::with_capacity(num_routes);
        for _ in 0..num_routes {
            let route_len = cursor.read_u16::<BigEndian>()? as usize;
            // ✅ SECURITY: Validate route length
            if route_len > MAX_FIELD_SIZE {
                return Err(anyhow!("Route length exceeds maximum: {} > {}", route_len, MAX_FIELD_SIZE));
            }

            let mut route_bytes = vec![0u8; route_len];
            cursor.read_exact(&mut route_bytes)?;
            let route = String::from_utf8(route_bytes)
                .map_err(|e| anyhow!("Invalid UTF-8 in route: {}", e))?;
            granted_routes.push(route);
        }

        let mut padding = Vec::new();
        cursor.read_to_end(&mut padding)?;
        // ✅ SECURITY: Validate padding
        if padding.len() > MAX_PADDING_SIZE {
            return Err(anyhow!("Excessive padding: {} > {}", padding.len(), MAX_PADDING_SIZE));
        }

        Ok(Frame::RoxyWelcome(RoxyWelcome {
            status,
            session_lifetime,
            obf_config,
            server_final,
            granted_routes,
            padding,
        }))
    }

    fn parse_data_frame(cursor: &mut Cursor<&[u8]>) -> anyhow::Result<Frame> {
        let stream_id = cursor.read_u32::<BigEndian>()?;
        let payload_len = cursor.read_u16::<BigEndian>()?;
        let flags = cursor.read_u8()?;
        let mut nonce = [0u8; NONCE_SIZE];
        cursor.read_exact(&mut nonce)?;

        if payload_len as usize > MAX_FRAME_SIZE {
            return Err(anyhow!("Frame too large"));
        }

        // Check if cursor has enough bytes remaining for payload
        let remaining = cursor.get_ref().len() - cursor.position() as usize;
        if payload_len as usize > remaining {
            return Err(anyhow!("Insufficient data for payload"));
        }

        let mut payload = vec![0u8; payload_len as usize];
        cursor.read_exact(&mut payload)?;
        let mut padding = Vec::new();
        cursor.read_to_end(&mut padding)?;

        // Enforce maximum padding size to prevent DoS
        // Removed duplicate MAX_PADDING_SIZE constant - using module-level constant instead
        if padding.len() > MAX_PADDING_SIZE {
            return Err(anyhow!("Excessive padding"));
        }

        Ok(Frame::Data(DataFrame {
            stream_id,
            payload_len,
            flags,
            nonce,
            payload,
            padding,
        }))
    }

    /// Serialize a frame to bytes (with length prefix)
    pub fn serialize(frame: &Frame) -> anyhow::Result<Vec<u8>> {
        let mut data = Vec::new();

        match frame {
            Frame::RoxyInit(init) => {
                data.write_u8(FrameType::RoxyInit as u8)?;
                data.write_u8(init.version)?;
                data.write_u16::<BigEndian>(init.flags)?;
                data.extend_from_slice(&init.client_nonce);
                data.write_u32::<BigEndian>(init.capabilities)?;
                data.extend_from_slice(&init.padding);
            }
            Frame::RoxyChallenge(challenge) => {
                data.write_u8(FrameType::RoxyChallenge as u8)?;
                data.extend_from_slice(challenge.session_id.as_bytes());
                data.extend_from_slice(&challenge.server_nonce);
                data.write_u8(challenge.auth_method)?;
                if challenge.challenge_data.len() > u16::MAX as usize {
                    return Err(anyhow!("challenge_data too large for u16 length field"));
                }
                data.write_u16::<BigEndian>(challenge.challenge_data.len() as u16)?;
                data.extend_from_slice(&challenge.challenge_data);
                data.extend_from_slice(&challenge.padding);
            }
            Frame::RoxyAuth(auth) => {
                data.write_u8(FrameType::RoxyAuth as u8)?;
                data.extend_from_slice(auth.session_id.as_bytes());
                if auth.auth_proof.len() > u16::MAX as usize {
                    return Err(anyhow!("auth_proof too large for u16 length field"));
                }
                data.write_u16::<BigEndian>(auth.auth_proof.len() as u16)?;
                data.extend_from_slice(&auth.auth_proof);
                if auth.requested_routes.len() > u16::MAX as usize {
                    return Err(anyhow!("Too many routes for u16 count field"));
                }
                data.write_u16::<BigEndian>(auth.requested_routes.len() as u16)?;
                for route in &auth.requested_routes {
                    let route_bytes = route.as_bytes();
                    if route_bytes.len() > u16::MAX as usize {
                        return Err(anyhow!("Route too large for u16 length field"));
                    }
                    data.write_u16::<BigEndian>(route_bytes.len() as u16)?;
                    data.extend_from_slice(route_bytes);
                }
                data.extend_from_slice(&auth.padding);
            }
            Frame::RoxyWelcome(welcome) => {
                data.write_u8(FrameType::RoxyWelcome as u8)?;
                data.write_u8(welcome.status)?;
                data.write_u32::<BigEndian>(welcome.session_lifetime)?;
                if welcome.obf_config.len() > u16::MAX as usize {
                    return Err(anyhow!("obf_config too large for u16 length field"));
                }
                data.write_u16::<BigEndian>(welcome.obf_config.len() as u16)?;
                data.extend_from_slice(&welcome.obf_config);
                if welcome.server_final.len() > u16::MAX as usize {
                    return Err(anyhow!("server_final too large for u16 length field"));
                }
                data.write_u16::<BigEndian>(welcome.server_final.len() as u16)?;
                data.extend_from_slice(&welcome.server_final);
                if welcome.granted_routes.len() > u16::MAX as usize {
                    return Err(anyhow!("Too many routes for u16 count field"));
                }
                data.write_u16::<BigEndian>(welcome.granted_routes.len() as u16)?;
                for route in &welcome.granted_routes {
                    let route_bytes = route.as_bytes();
                    if route_bytes.len() > u16::MAX as usize {
                        return Err(anyhow!("Route too large for u16 length field"));
                    }
                    data.write_u16::<BigEndian>(route_bytes.len() as u16)?;
                    data.extend_from_slice(route_bytes);
                }
                data.extend_from_slice(&welcome.padding);
            }
            Frame::Data(data_frame) => {
                data.write_u8(FrameType::Data as u8)?;
                data.write_u32::<BigEndian>(data_frame.stream_id)?;
                data.write_u16::<BigEndian>(data_frame.payload_len)?;
                data.write_u8(data_frame.flags)?;
                data.extend_from_slice(&data_frame.nonce);
                data.extend_from_slice(&data_frame.payload);
                data.extend_from_slice(&data_frame.padding);
            }
            Frame::Ping => {
                data.write_u8(FrameType::Ping as u8)?;
            }
            Frame::Control(payload) => {
                data.write_u8(FrameType::Control as u8)?;
                data.extend_from_slice(payload);
            }
            Frame::ControlAck => {
                data.write_u8(FrameType::ControlAck as u8)?;
            }
            Frame::Close => {
                data.write_u8(FrameType::Close as u8)?;
            }
        }

        // Prepend length prefix (big-endian u32)
        if data.len() > u32::MAX as usize {
            return Err(anyhow!("Frame too large for u32 length prefix"));
        }
        let mut result = Vec::with_capacity(4 + data.len());
        result.write_u32::<BigEndian>(data.len() as u32)?;
        result.extend_from_slice(&data);

        Ok(result)
    }

    /// Add random padding to a frame
    pub fn add_padding(frame_data: &mut Vec<u8>, max_padding: usize) {
        // ✅ SECURITY: Clamp to safe maximum
        let safe_max = max_padding.min(MAX_PADDING_SIZE);
        let padding_len = rand::thread_rng().gen_range(0..=safe_max);
        let padding: Vec<u8> = (0..padding_len).map(|_| rand::random()).collect();
        frame_data.extend_from_slice(&padding);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_frame_type_from_u8() {
        assert!(matches!(FrameType::try_from(0x01), Ok(FrameType::RoxyInit)));
        assert!(matches!(FrameType::try_from(0xFF), Ok(FrameType::Close)));
        assert!(FrameType::try_from(0x99).is_err());
    }

    #[test]
    fn test_serialize_deserialize_roxy_init() {
        let init = RoxyInit {
            version: PROTOCOL_VERSION,
            flags: 0,
            client_nonce: [1u8; SCRAM_NONCE_SIZE],
            capabilities: 0x01,
            padding: vec![2, 3, 4],
        };
        let frame = Frame::RoxyInit(init);
        let data = FrameParser::serialize(&frame).unwrap();
        let (parsed, consumed) = FrameParser::parse(&data).unwrap();
        assert_eq!(consumed, data.len());

        if let Frame::RoxyInit(parsed_init) = parsed {
            assert_eq!(parsed_init.version, PROTOCOL_VERSION);
            assert_eq!(parsed_init.client_nonce, [1u8; SCRAM_NONCE_SIZE]);
        } else {
            panic!("Wrong frame type");
        }
    }

    #[test]
    fn test_serialize_deserialize_data_frame() {
        let data_frame = DataFrame {
            stream_id: 42,
            payload_len: 5,
            flags: 0,
            nonce: [0u8; NONCE_SIZE],
            payload: vec![1, 2, 3, 4, 5],
            padding: vec![6, 7],
        };
        let frame = Frame::Data(data_frame);
        let data = FrameParser::serialize(&frame).unwrap();
        let (parsed, consumed) = FrameParser::parse(&data).unwrap();
        assert_eq!(consumed, data.len());

        if let Frame::Data(parsed_data) = parsed {
            assert_eq!(parsed_data.stream_id, 42);
            assert_eq!(parsed_data.payload, vec![1, 2, 3, 4, 5]);
        } else {
            panic!("Wrong frame type");
        }
    }

    #[test]
    fn test_reject_oversized_challenge_data() {
        let mut frame_data = vec![FrameType::RoxyChallenge as u8];
        frame_data.extend_from_slice(&[0u8; SESSION_ID_SIZE]); // session_id
        frame_data.extend_from_slice(&[0u8; SCRAM_NONCE_SIZE]); // server_nonce
        frame_data.push(0x01); // auth_method
        frame_data.extend_from_slice(&(MAX_FIELD_SIZE as u16 + 1).to_be_bytes()); // oversized
        frame_data.extend_from_slice(&vec![0u8; MAX_FIELD_SIZE + 1]);

        let frame_len = frame_data.len();
        let mut data = Vec::new();
        data.extend_from_slice(&(frame_len as u32).to_be_bytes());
        data.extend_from_slice(&frame_data);

        let result = FrameParser::parse(&data);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("exceeds maximum"));
    }

    #[test]
    fn test_reject_too_many_routes() {
        let mut frame_data = vec![FrameType::RoxyAuth as u8];
        frame_data.extend_from_slice(&[0u8; SESSION_ID_SIZE]); // session_id
        frame_data.extend_from_slice(&(10u16).to_be_bytes()); // auth_proof_len
        frame_data.extend_from_slice(&vec![0u8; 10]); // auth_proof
        frame_data.extend_from_slice(&(MAX_ROUTES as u16 + 1).to_be_bytes()); // too many routes

        let frame_len = frame_data.len();
        let mut data = Vec::new();
        data.extend_from_slice(&(frame_len as u32).to_be_bytes());
        data.extend_from_slice(&frame_data);

        let result = FrameParser::parse(&data);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Too many routes"));
    }

    #[test]
    fn test_reject_excessive_padding() {
        let mut frame_data = vec![FrameType::RoxyInit as u8];
        frame_data.push(PROTOCOL_VERSION);
        frame_data.extend_from_slice(&0u16.to_be_bytes()); // flags
        frame_data.extend_from_slice(&[0u8; SCRAM_NONCE_SIZE]); // client_nonce
        frame_data.extend_from_slice(&0u32.to_be_bytes()); // capabilities
        frame_data.extend_from_slice(&vec![0u8; MAX_PADDING_SIZE + 1]); // excessive padding

        let frame_len = frame_data.len();
        let mut data = Vec::new();
        data.extend_from_slice(&(frame_len as u32).to_be_bytes());
        data.extend_from_slice(&frame_data);

        let result = FrameParser::parse(&data);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Excessive padding"));
    }

    #[test]
    fn test_reject_integer_truncation() {
        let oversized_data = vec![0u8; 70000];
        let auth = RoxyAuth {
            session_id: uuid::Uuid::new_v4(),
            auth_proof: oversized_data, // Would truncate to 4464
            requested_routes: vec![],
            padding: vec![],
        };
        let result = FrameParser::serialize(&Frame::RoxyAuth(auth));
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too large for u16"));
    }

    #[test]
    fn test_reject_oversized_frame() {
        let mut data = Vec::new();
        data.extend_from_slice(&((MAX_FRAME_SIZE + 1) as u32).to_be_bytes());
        data.push(FrameType::Ping as u8); // minimal frame
        let result = FrameParser::parse(&data);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("exceeds maximum size"));
    }

    #[test]
    fn test_reject_oversized_control_payload() {
        let payload = vec![0u8; MAX_FIELD_SIZE + 1];
        let frame_len = 1 + payload.len(); // frame_type + payload
        let mut data = Vec::new();
        data.extend_from_slice(&(frame_len as u32).to_be_bytes()); // length prefix
        data.push(FrameType::Control as u8);
        data.extend_from_slice(&payload);

        let result = FrameParser::parse(&data);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too large"));
    }

    #[test]
    fn test_ping_message_roundtrip() {
        let ping = PingMessage::new();
        let bytes = ping.to_bytes();
        assert_eq!(bytes.len(), 24);
        
        let parsed = PingMessage::from_bytes(&bytes).expect("Failed to parse ping");
        assert_eq!(parsed.timestamp, ping.timestamp);
        assert_eq!(parsed.nonce, ping.nonce);
    }

    #[test]
    fn test_ping_message_invalid_length() {
        let short_data = vec![0u8; 10];
        let result = PingMessage::from_bytes(&short_data);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ProtocolError::InvalidLength));
    }

    #[test]
    fn test_control_message_new_tunnel() {
        let cmd = ControlCommand::NewTunnel { 
            destination: "example.com:443".to_string() 
        };
        let msg = ControlMessage { command: cmd };
        let bytes = msg.to_bytes();
        
        let parsed = ControlMessage::from_bytes(&bytes).expect("Failed to parse control");
        if let ControlCommand::NewTunnel { destination } = parsed.command {
            assert_eq!(destination, "example.com:443");
        } else {
            panic!("Wrong command type");
        }
    }

    #[test]
    fn test_control_message_close_tunnel() {
        let cmd = ControlCommand::CloseTunnel { tunnel_id: 42 };
        let msg = ControlMessage { command: cmd };
        let bytes = msg.to_bytes();
        
        let parsed = ControlMessage::from_bytes(&bytes).expect("Failed to parse control");
        if let ControlCommand::CloseTunnel { tunnel_id } = parsed.command {
            assert_eq!(tunnel_id, 42);
        } else {
            panic!("Wrong command type");
        }
    }

    #[test]
    fn test_control_message_update_bandwidth() {
        let cmd = ControlCommand::UpdateBandwidth { limit_mbps: 100 };
        let msg = ControlMessage { command: cmd };
        let bytes = msg.to_bytes();
        
        let parsed = ControlMessage::from_bytes(&bytes).expect("Failed to parse control");
        if let ControlCommand::UpdateBandwidth { limit_mbps } = parsed.command {
            assert_eq!(limit_mbps, 100);
        } else {
            panic!("Wrong command type");
        }
    }

    #[test]
    fn test_control_message_invalid_command() {
        let invalid_data = vec![0xFFu8]; // Invalid command code
        let result = ControlMessage::from_bytes(&invalid_data);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ProtocolError::InvalidCommand));
    }

    #[test]
    fn test_control_message_invalid_length() {
        let short_data = vec![0u8, 1, 2]; // Too short for any command
        let result = ControlMessage::from_bytes(&short_data);
        assert!(result.is_err());
    }

    #[test]
    fn test_frame_control_ack_roundtrip() {
        let frame = Frame::ControlAck;
        let data = FrameParser::serialize(&frame).expect("Failed to serialize");
        let (parsed, consumed) = FrameParser::parse(&data).expect("Failed to parse");
        assert_eq!(consumed, data.len());
        assert!(matches!(parsed, Frame::ControlAck));
    }

    #[test]
    fn test_frame_type_control_ack() {
        let result = FrameType::try_from(0x13);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), FrameType::ControlAck);
    }

    // Property-based tests for robustness against malformed input

    proptest! {
        #[test]
        fn test_parse_arbitrary_data_doesnt_panic(data in prop::collection::vec(any::<u8>(), 0..1000)) {
            // This should never panic, even with completely random data
            let _ = FrameParser::parse(&data);
        }

        #[test]
        fn test_frame_type_from_arbitrary_u8(value in any::<u8>()) {
            // Should return Ok for valid values, Err for invalid
            let result = FrameType::try_from(value);
            match value {
                0x01 | 0x02 | 0x03 | 0x04 | 0x10 | 0x11 | 0x12 | 0x13 | 0xFF => {
                    prop_assert!(result.is_ok());
                }
                _ => {
                    prop_assert!(result.is_err());
                }
            }
        }

        #[test]
        fn test_serialize_deserialize_roundtrip_roxy_init(
            version in 0u8..,
            flags in any::<u16>(),
            client_nonce in prop::array::uniform32(any::<u8>()),
            capabilities in any::<u32>(),
            padding in prop::collection::vec(any::<u8>(), 0..MAX_PADDING_SIZE)
        ) {
            let init = RoxyInit {
                version,
                flags,
                client_nonce,
                capabilities,
                padding: padding.clone(),
            };
            let frame = Frame::RoxyInit(init);
            let data = FrameParser::serialize(&frame).expect("serialize failed");
            let (parsed, consumed) = FrameParser::parse(&data).expect("parse failed");
            prop_assert_eq!(consumed, data.len());

            match parsed {
                Frame::RoxyInit(parsed_init) => {
                    prop_assert_eq!(parsed_init.version, version);
                    prop_assert_eq!(parsed_init.flags, flags);
                    prop_assert_eq!(parsed_init.client_nonce, client_nonce);
                    prop_assert_eq!(parsed_init.capabilities, capabilities);
                    prop_assert_eq!(parsed_init.padding, padding);
                }
                _ => panic!("Wrong frame type"),
            }
        }

        #[test]
        fn test_serialize_deserialize_roundtrip_data_frame(
            stream_id in any::<u32>(),
            flags in any::<u8>(),
            nonce in prop::array::uniform12(any::<u8>()),
            payload in prop::collection::vec(any::<u8>(), 0..MAX_FIELD_SIZE),
            padding in prop::collection::vec(any::<u8>(), 0..MAX_FRAME_PADDING as usize)
        ) {
            let payload_len = payload.len() as u16;
            let data_frame = DataFrame {
                stream_id,
                payload_len,
                flags,
                nonce,
                payload: payload.clone(),
                padding: padding.clone(),
            };
            let frame = Frame::Data(data_frame);
            let data = FrameParser::serialize(&frame).expect("serialize failed");
            let (parsed, consumed) = FrameParser::parse(&data).expect("parse failed");
            prop_assert_eq!(consumed, data.len());

            match parsed {
                Frame::Data(parsed_data) => {
                    prop_assert_eq!(parsed_data.stream_id, stream_id);
                    prop_assert_eq!(parsed_data.payload_len, payload_len);
                    prop_assert_eq!(parsed_data.flags, flags);
                    prop_assert_eq!(parsed_data.nonce, nonce);
                    prop_assert_eq!(parsed_data.payload, payload);
                    prop_assert_eq!(parsed_data.padding, padding);
                }
                _ => panic!("Wrong frame type"),
            }
        }
    }
}