//! SOCKS5 proxy implementation for ROXY
//!
//! Provides both client-side and server-side SOCKS5 proxy functionality
//! to enable local proxying through the ROXY tunnel.

pub mod client;
pub mod protocol;
pub mod server;
pub use client::run as run_client;
pub use server::run as run_server;
pub use protocol::*;