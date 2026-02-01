//! SOCKS5 protocol constants (RFC 1928)

pub const SOCKS_VERSION: u8 = 0x05;

pub mod commands {
    pub const CONNECT: u8 = 0x01;
    pub const BIND: u8 = 0x02;
    pub const UDP_ASSOCIATE: u8 = 0x03;
}

pub mod atyp {
    pub const IPV4: u8 = 0x01;
    pub const DOMAIN: u8 = 0x03;
    pub const IPV6: u8 = 0x04;
}

pub mod reply {
    pub const SUCCESS: u8 = 0x00;
    pub const GENERAL_FAILURE: u8 = 0x01;
    pub const CONNECTION_NOT_ALLOWED: u8 = 0x02;
    pub const NETWORK_UNREACHABLE: u8 = 0x03;
    pub const HOST_UNREACHABLE: u8 = 0x04;
    pub const CONNECTION_REFUSED: u8 = 0x05;
    pub const TTL_EXPIRED: u8 = 0x06;
    pub const COMMAND_NOT_SUPPORTED: u8 = 0x07;
    pub const ADDRESS_TYPE_NOT_SUPPORTED: u8 = 0x08;
}

pub mod auth {
    pub const NO_AUTH: u8 = 0x00;
    pub const GSSAPI: u8 = 0x01;
    pub const USERNAME_PASSWORD: u8 = 0x02;
    pub const NO_ACCEPTABLE_METHODS: u8 = 0xFF;
}