# ROXY - DPI Bypass Proxy

[![Rust](https://img.shields.io/badge/rust-1.75+-orange)](https://rust-lang.org)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

**ROXY** is a high-performance DPI (Deep Packet Inspection) bypass proxy server written in Rust, featuring SOCKS5 support, TLS 1.3 encryption, QUIC protocol (experimental), and an advanced Terminal UI for real-time monitoring and management.

[🇷🇺 Русская версия]([`README_ru.md`](README_ru.md))

## 🌟 Features

- **🔐 Strong Security**
  - TLS 1.3 with ChaCha20-Poly1305 encryption
  - SCRAM-SHA-256 authentication
  - Certificate-based authentication support
  - Per-session encryption keys with perfect forward secrecy

- **🚀 DPI Evasion**
  - Traffic obfuscation and padding
  - Timing pattern mimicry
  - TLS fingerprint customization
  - Protocol polymorphism

- **🔌 Multiple Protocols**
  - Native ROXY protocol
  - SOCKS5 client/server
  - QUIC transport (experimental, opt-in via `quic-experimental` feature)
  - Transparent proxying

- **📊 Advanced Monitoring**
  - Real-time Terminal UI (TUI) dashboard
  - User session tracking
  - Bandwidth monitoring
  - Connection metrics
  - Remote monitoring via HTTP API (with `tui-remote` feature)

- **⚡ High Performance**
  - Async I/O with Tokio runtime
  - Multi-threaded connection handling
  - Zero-copy optimizations
  - Efficient memory usage

- **🛡️ Security Hardening**
  - Rate limiting and DoS protection
  - Per-user access control
  - Bandwidth throttling
  - Connection limits

## 📋 Table of Contents

- [Quick Start](#-quick-start)
- [Installation](#-installation)
- [Configuration](#-configuration)
- [Usage](#-usage)
- [Docker Deployment](#-docker-deployment)
- [Architecture](#-architecture)
- [Development](#-development)
- [Security](#-security)
- [FAQ](#-faq)
- [Contributing](#-contributing)
- [License](#-license)

## 🚀 Quick Start

### Prerequisites

- Rust 1.75+ ([install](https://rustup.rs/))
- Linux, macOS, or Windows (WSL recommended)

### Build from Source

```bash
# Build with default features
cargo build --release

# Or build with all features enabled
cargo build --release --features quic-experimental,tui-remote

# The binary will be at target/release/roxy
```

### Generate TLS Certificates

```bash
# Create certificates directory
mkdir -p certs

# Generate self-signed certificate (for testing)
openssl req -x509 -newkey rsa:4096 -nodes \
  -keyout certs/server.key \
  -out certs/server.crt \
  -days 365 \
  -subj "/CN=localhost"

# For production, use Let's Encrypt or your CA
```

### Create Configuration and Add Your First User

```bash
# Create configuration directory
mkdir -p config

# Add a user interactively
./target/release/roxy user --config config/config.yml add --name alice
# Enter password when prompted
```

### Start the Server

```bash
# Start with default config
./target/release/roxy server --config config/config.yml

# Or specify TLS certificates
./target/release/roxy server \
  --config config/config.yml \
  --tls-cert certs/server.crt \
  --tls-key certs/server.key \
  --port 8443
```

### Launch the TUI Dashboard

```bash
# Monitor local server
./target/release/roxy tui --config config/config.yml

# Or monitor remote server (requires tui-remote feature)
./target/release/roxy tui --remote http://server:9090
```

### Connect as a Client

```bash
# Connect to the server
./target/release/roxy client \
  --server localhost:8443 \
  --user alice \
  --password <your-password>

# Or use environment variable for password
export ROXY_PASSWORD=<your-password>
./target/release/roxy client --server localhost:8443 --user alice
```

## 📦 Installation

### From Source

```bash
cargo install --path . --features quic-experimental,tui-remote
```

### Using Docker

```bash
# Build the image
docker build -t roxy:latest .

# Run the server
docker run -d \
  -p 8443:8443 \
  -p 4433:4433/udp \
  -v $(pwd)/config:/app/config \
  -v $(pwd)/certs:/app/certs \
  --name roxy-server \
  roxy:latest
```

### Using Docker Compose

```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

See [Docker Deployment](#-docker-deployment) for more details.

## ⚙️ Configuration

ROXY uses YAML configuration files for server and user management.

### Server Configuration ([`config/config.yml`](config/config.yml))

```yaml
# ROXY Configuration
users: {}
session_lifetime: 3600
alpn_protocols: ["h2", "http/1.1"]
log_level: "INFO"
log_theme_path: "config/logging_theme.yml"
log_to_file: false
log_file_path: null

server:
  bind_address: "0.0.0.0"
  port: 8443
  max_concurrent_connections: 1000
  buffer_size: 8192

tls:
  enabled: true
  cert_path: "certs/server.crt"
  key_path: "certs/server.key"
  versions: ["1.3", "1.2"]

timeouts:
  connect_timeout: 10
  read_timeout: 30
  write_timeout: 30
  idle_timeout: 300

quic:
  enabled: false
  bind_address: "0.0.0.0"
  port: 4433
  idle_timeout_ms: 30000

socks5:
  enabled: true
  bind_addr: "0.0.0.0:1080"
  server_addr: "roxy-server:1081"
  username: ""
  password: ""
  server_enabled: true
  server_bind_addr: "0.0.0.0:1081"

allow_plain_http: true
default_bandwidth_limit_mbps: null
```

### User Configuration

Users are stored in `config/config.yml` with SCRAM credentials:

```yaml
users:
  alice:
    scram:
      salt: "a1b2c3d4..."
      iterations: 100000
      stored_key: "..."
      server_key: "..."
    permissions:
      allowed_routes:
        - "tcp:*:443"
        - "tcp:example.com:80"
      bandwidth_limit_mbps: 10
    active: true
    expires_at: null  # ISO 8601 datetime or null
```

**Note:** Use `roxy user add` to generate proper credentials. Never edit SCRAM fields manually.

## 🎮 Usage

### Server Mode

```bash
# Start with custom config
roxy server --config config/config.yml --port 8443

# With custom TLS certificates
roxy server \
  --config config/config.yml \
  --tls-cert /path/to/cert.pem \
  --tls-key /path/to/key.pem
```

### Client Mode

```bash
# Basic connection
roxy client --server example.com:8443 --user alice --password secret

# Request specific routes
roxy client \
  --server example.com:8443 \
  --user alice \
  --routes "tcp:google.com:443,tcp:github.com:443"

# Skip certificate verification (DANGEROUS - testing only)
roxy client --server localhost:8443 --user alice --skip-cert-verification
```

### TUI (Terminal UI) Mode

```bash
# Monitor local server
roxy tui --config config/config.yml

# Monitor remote server (requires tui-remote feature)
roxy tui --remote http://server.example.com:9090
```

**TUI Controls:**
- `Tab` / `Shift+Tab` - Switch between screens
- `↑/↓` or `j/k` - Navigate lists
- `Enter` - Select item
- `q` or `Esc` - Quit
- `r` - Refresh metrics

### User Management

```bash
# Add a new user
roxy user --config config/config.yml add --name bob

# Users are stored in config/config.yml with SCRAM credentials
# Edit permissions, expiry dates manually in YAML (not SCRAM fields!)
```

## 🐳 Docker Deployment

### Using Dockerfile

The project includes a multi-stage Dockerfile optimized for small image size and security.

```bash
# Build the image
docker build -t roxy:latest .

# Run the server
docker run -d \
  -p 8443:8443 \
  -p 4433:4433/udp \
  -v $(pwd)/config:/app/config:ro \
  -v $(pwd)/certs:/app/certs:ro \
  --restart unless-stopped \
  --name roxy-server \
  roxy:latest
```

### Using Docker Compose

[`docker-compose.yml`]([`docker-compose.yml`](docker-compose.yml)) provides a complete deployment setup:

```yaml
version: '3.8'

services:
  roxy-server:
    build:
      context: .
      dockerfile: Dockerfile
      args:
        FEATURES: "tui-remote,quic-experimental"
    ports:
      - "8443:8443"      # ROXY server
      - "4433:4433/udp"  # QUIC (optional)
      - "9090:9090"      # Metrics API (tui-remote)
    volumes:
      - ./config:/app/config:ro
      - ./certs:/app/certs:ro
    environment:
      - RUST_LOG=info
    restart: unless-stopped
```

**Deploy:**

```bash
docker-compose up -d
docker-compose logs -f roxy-server
docker-compose exec roxy-server roxy user --config /app/config.yml add --name alice
```

## 🏗️ Architecture

ROXY implements a custom DPI-resistant protocol with multiple layers of security and obfuscation:

```
┌─────────────────────────────────────┐
│   Application Data (HTTP, etc.)     │ ← User traffic
├─────────────────────────────────────┤
│      ROXY Application Protocol      │ ← Auth, framing, obfuscation
├─────────────────────────────────────┤
│         TLS 1.3 Encryption          │ ← ChaCha20-Poly1305
├─────────────────────────────────────┤
│         TCP (Port 8443)             │ ← Transport
└─────────────────────────────────────┘
```

### Key Components

- [`src/server.rs`](src/server.rs) - Async TLS server with connection handling
- [`src/client.rs`](src/client.rs) - Client implementation with SCRAM auth
- [`src/protocol.rs`](src/protocol.rs) - ROXY protocol frame definitions
- [`src/auth.rs`](src/auth.rs) - SCRAM-SHA-256 authentication
- [`src/crypto.rs`](src/crypto.rs) - Cryptographic primitives
- [`src/obfuscation/`](src/obfuscation/) - Traffic shaping and obfuscation
- [`src/transport/`](src/transport/) - SOCKS5 and QUIC implementations
- [`src/tui/`](src/tui/) - Terminal UI dashboard

### Protocol Flow

1. **TLS Handshake** - Standard TLS 1.3 (mimics HTTPS)
2. **ROXY Handshake** - Client auth via SCRAM-SHA-256
3. **Session Establishment** - Derive session keys, negotiate obfuscation
4. **Data Tunnel** - Encrypted data frames with obfuscation padding
5. **Teardown** - Graceful connection closure

For detailed protocol specification, see [`docs/protocol-design.md`](docs/protocol-design.md).

## 🔧 Development

### Building

```bash
# Debug build
cargo build

# Release build (optimized)
cargo build --release

# With all features
cargo build --release --all-features

# Check code without building
cargo check
```

### Testing

```bash
# Run all tests
cargo test

# Run tests with output
cargo test -- --nocapture

# Run specific test
cargo test test_scram_authentication

# Run with features
cargo test --features quic-experimental
```

### Linting

```bash
# Check code style
cargo clippy -- -D warnings

# Format code
cargo fmt

# Check formatting
cargo fmt -- --check
```

### Documentation

```bash
# Generate and open documentation
cargo doc --open --no-deps

# Include private items
cargo doc --open --document-private-items
```

### Benchmarking

```bash
# Run benchmarks (requires nightly)
cargo +nightly bench
```

## 🔒 Security

### Security Features

- **Encryption:** TLS 1.3 + application-layer ChaCha20-Poly1305
- **Authentication:** SCRAM-SHA-256 with salted password hashing
- **Forward Secrecy:** Ephemeral session keys via HKDF
- **Rate Limiting:** DoS protection with token bucket algorithm
- **Access Control:** Per-user route permissions
- **Auditing:** Comprehensive logging of auth events

### Security Best Practices

1. **Never use in production without legitimate TLS certificates**
2. **Rotate user passwords regularly**
3. **Enable rate limiting and connection limits**
4. **Monitor logs for suspicious activity**
5. **Keep dependencies updated** (`cargo update`)
6. **Use strong, unique passwords for each user**
7. **Restrict `allowed_routes` to minimum required**

### Reporting Vulnerabilities

Report security issues privately to the project maintainer.

Please do **not** open public issues for security vulnerabilities.

## ❓ FAQ

**Q: What is DPI and why bypass it?**
A: Deep Packet Inspection (DPI) analyzes network traffic to detect and block certain protocols. ROXY disguises traffic as normal HTTPS to evade detection.

**Q: Is ROXY a VPN?**
A: No, ROXY is a proxy server. It requires a ROXY client or compatible SOCKS5 client to connect.

**Q: Can I use ROXY with existing applications?**
A: Yes, via SOCKS5 proxy mode. Configure your application to use `localhost:1080` as SOCKS5 proxy.

**Q: What's the difference between ROXY protocol and SOCKS5?**
A: ROXY protocol includes DPI evasion, authentication, and encryption. SOCKS5 is a standard proxy protocol with optional integration.

**Q: Is QUIC support stable?**
A: QUIC is experimental (`quic-experimental` feature). Use TCP+TLS for production.

**Q: How do I update user permissions?**
A: Edit [`config/config.yml`](config/config.yml) and restart the server. Don't modify SCRAM credential fields.

**Q: Can I run multiple servers?**
A: Yes, use different ports or IP addresses in the config.

**Q: What logging levels are available?**
A: `TRACE`, `DEBUG`, `INFO` (default), `WARN`, `ERROR`. Set via `log_level` in [`config/config.yml`](config/config.yml).

## 🤝 Contributing

Contributions are welcome! Please follow these guidelines:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Guidelines

- Follow Rust coding conventions
- Add tests for new features
- Update documentation
- Run `cargo clippy` and `cargo fmt` before committing
- Write clear commit messages

## 📄 License

This project is licensed under the MIT License - see [Cargo.toml](Cargo.toml) for details.

## 🙏 Acknowledgments

- [Tokio](https://tokio.rs/) - Async runtime
- [rustls](https://github.com/rustls/rustls) - TLS implementation
- [ratatui](https://github.com/ratatui-org/ratatui) - Terminal UI framework
- [Tor Project](https://www.torproject.org/) - Inspiration for obfuscation techniques

---
**⚠️ Disclaimer:** This software is provided for educational and research purposes. Users are responsible for compliance with local laws and regulations. The authors assume no liability for misuse.
