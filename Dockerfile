# ========================================
# Multi-stage Dockerfile for ROXY
# Optimized for Linux & Windows AMD64
# ========================================

# Build arguments
ARG RUST_VERSION=1.75
ARG FEATURES="tui-remote,quic-experimental"
ARG PLATFORM=x86_64-unknown-linux-musl

# ========================================
# Stage 1: Dependencies & Build Tools
# ========================================
FROM rustlang/rust:nightly-slim AS deps-setup

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    musl-tools \
    musl-dev \
    pkg-config \
    libssl-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Add target architecture
ARG PLATFORM
RUN rustup target add ${PLATFORM}

# Create non-root user for security
RUN useradd -m -u 1000 -s /bin/bash roxy

# ========================================
# Stage 2: Dependency Cache Builder
# ========================================
FROM deps-setup AS cache-builder

WORKDIR /app

# Pre-build dependencies (cached layer)
# This significantly speeds up rebuilds when only source code changes
RUN cargo init --name roxy

# Copy dependency manifests
COPY Cargo.toml Cargo.lock ./

# Build dependencies only (ignore errors, we just want the cache)
ARG PLATFORM
ARG FEATURES
RUN cargo build --release \
    --target ${PLATFORM} \
    --features "${FEATURES}" \
    2>&1 || true

# Clean up the dummy binary
RUN rm -rf src/

# ========================================
# Stage 3: Application Builder
# ========================================
FROM cache-builder AS builder

# Copy actual source code
COPY src ./src
COPY .cargo ./.cargo

# Set build environment variables
ENV PKG_CONFIG_ALLOW_CROSS=1
ENV OPENSSL_STATIC=1
ENV CARGO_INCREMENTAL=0
ENV CARGO_NET_RETRY=10
ENV RUSTFLAGS="-C target-cpu=native"

# Build the application
ARG PLATFORM
ARG FEATURES
RUN cargo build --release \
    --target ${PLATFORM} \
    --features "${FEATURES}" \
    && strip target/${PLATFORM}/release/roxy || true

# Verify binary is properly built
RUN ls -lh target/${PLATFORM}/release/roxy

# ========================================
# Stage 4: Runtime Image (Alpine-based)
# ========================================
FROM alpine:latest AS runtime

# Install runtime dependencies
RUN apk add --no-cache \
    ca-certificates \
    libgcc \
    wget \
    && rm -rf /var/cache/apk/*

# Create non-root user
RUN addgroup -g 1000 roxy \
    && adduser -D -u 1000 -G roxy roxy

# Create application directories
RUN mkdir -p /app/config /app/certs /app/logs \
    && chown -R roxy:roxy /app

# Copy binary from builder
ARG PLATFORM
COPY --from=builder /app/target/${PLATFORM}/release/roxy /usr/local/bin/roxy

# Verify binary works
RUN /usr/local/bin/roxy --help > /dev/null && echo "✓ Binary verification successful"

# Set working directory
WORKDIR /app

# Switch to non-root user
USER roxy

# Expose ports
# 8443 - ROXY server (TLS/TCP)
# 4433 - QUIC (UDP, experimental)
# 9090 - Metrics API (tui-remote feature)
# 1080 - SOCKS5 client
# 1081 - SOCKS5 server
EXPOSE 8443 4433/udp 9090 1080 1081

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD wget --quiet --tries=1 --spider http://localhost:9090/health || exit 1

# Default command
CMD ["roxy", "server", "--config", "/app/config/config.yml"]

# ========================================
# Stage 5: Alternative Windows Runtime
# (Use with: docker build --target windows-runtime)
# ========================================
FROM mcr.microsoft.com/windows/servercore:ltsc2022 AS windows-runtime

# Copy binary (requires cross-compilation)
# Note: For Windows, build with: cargo build --target x86_64-pc-windows-msvc
# COPY --from=builder /app/target/x86_64-pc-windows-msvc/release/roxy.exe C:/roxy/roxy.exe

# Create directories
# RUN mkdir C:\roxy\config C:\roxy\certs C:\roxy\logs

# Set working directory
# WORKDIR C:/roxy

# Expose ports
# EXPOSE 8443 4433 9090

# Default command
# CMD ["C:/roxy/roxy.exe", "server", "--config", "C:/roxy/config/config.yml"]

# ========================================
# Labels
# ========================================
LABEL maintainer="ROXY Team <support@yourproject.com>"
LABEL description="ROXY DPI Bypass Proxy - High-performance Rust proxy server"
LABEL version="0.1.1"
LABEL org.opencontainers.image.source="https://github.com/yourusername/roxy"
LABEL org.opencontainers.image.licenses="MIT"
