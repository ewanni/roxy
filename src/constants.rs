//! Global constants for ROXY protocol and networking

// ============================================================================
// BUFFER SIZES
// ============================================================================

/// Default network buffer size (8KB)
pub const DEFAULT_BUFFER_SIZE: usize = 8192;

/// Maximum buffer size (64KB)
pub const MAX_BUFFER_SIZE: usize = 65536;

// ============================================================================
// IP ADDRESS SIZES
// ============================================================================

/// IPv4 address size (32 bits)
pub const IPV4_SIZE: usize = 4;

/// IPv6 address size (128 bits)
pub const IPV6_SIZE: usize = 16;

// ============================================================================
// CHANNEL SIZES
// ============================================================================

/// Upstream response channel buffer size
pub const UPSTREAM_CHANNEL_SIZE: usize = 32;

// ============================================================================
// END OF CONSTANTS
// ============================================================================