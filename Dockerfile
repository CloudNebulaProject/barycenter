# Multi-stage build for Barycenter OpenID Connect IdP
# Build stage
FROM rust:1.92-bookworm AS builder

WORKDIR /build

# Copy manifests
COPY Cargo.toml Cargo.lock ./

# Copy source code
COPY src ./src
COPY migration ./migration
COPY client-wasm ./client-wasm

# Build release binary with platform-specific caches to avoid race conditions
ARG TARGETPLATFORM
RUN --mount=type=cache,target=/usr/local/cargo/registry,id=cargo-registry-${TARGETPLATFORM} \
    --mount=type=cache,target=/build/target,id=build-target-${TARGETPLATFORM} \
    cargo build --release && \
    cp target/release/barycenter /barycenter

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -r -u 1000 -s /bin/false barycenter && \
    mkdir -p /app/data /app/config && \
    chown -R barycenter:barycenter /app

WORKDIR /app

# Copy binary from builder
COPY --from=builder /barycenter /usr/local/bin/barycenter

# Copy default configuration
COPY config.toml /app/config/config.toml

# Set ownership
RUN chown -R barycenter:barycenter /app

# Switch to non-root user
USER barycenter

# Expose default port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/bin/sh", "-c", "test -f /proc/self/exe || exit 1"]

# Default command
ENTRYPOINT ["/usr/local/bin/barycenter"]
CMD ["--config", "/app/config/config.toml"]
