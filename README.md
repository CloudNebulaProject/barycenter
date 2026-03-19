# Barycenter

An OpenID Connect Identity Provider (IdP) implementing OAuth 2.0 Authorization Code flow with PKCE.

## Overview

Barycenter is a lightweight, standards-compliant OpenID Connect Identity Provider written in Rust. It implements the OAuth 2.0 Authorization Code flow with Proof Key for Code Exchange (PKCE), making it suitable for modern web and mobile applications.

## Features

- **OAuth 2.0 Authorization Code Flow** with PKCE (S256)
- **Dynamic Client Registration** - RFC 7591 compliant
- **Token Endpoint** - Multiple authentication methods (client_secret_basic, client_secret_post)
- **ID Token Signing** - RS256 with proper at_hash and nonce support
- **UserInfo Endpoint** - Bearer token authentication
- **Discovery** - OpenID Connect Discovery and JWKS publication
- **Property Storage** - Simple key-value storage for user properties

## Technology Stack

- **Language**: Rust
- **Web Framework**: [axum](https://github.com/tokio-rs/axum)
- **Database**: SQLite via [SeaORM](https://www.sea-ql.org/SeaORM/)
- **Cryptography**: [josekit](https://github.com/hidekatsu-izuno/josekit-rs) for JOSE/JWT operations
- **Configuration**: [config-rs](https://github.com/mehcode/config-rs) with TOML support

## Quick Start

### Prerequisites

- Rust 1.70 or later
- SQLite 3

### Installation

```bash
# Clone the repository
git clone https://github.com/CloudNebulaProject/barycenter.git
cd barycenter

# Build the project
cargo build --release
```

### Configuration

Create a `config.toml` file (see `config.toml` for example):

```toml
[server]
host = "127.0.0.1"
port = 8080
public_base_url = "http://localhost:8080"

[database]
connection_string = "sqlite://barycenter.db?mode=rwc"

[keys]
jwks_path = "data/jwks.json"
private_key_path = "data/private_key.pem"
signing_algorithm = "RS256"
```

### Running

```bash
# Run with default config
cargo run

# Run with custom config
cargo run -- --config path/to/config.toml

# Run with debug logging
RUST_LOG=debug cargo run
```

## Development

### Building

```bash
# Debug build
cargo build

# Release build
cargo build --release

# Check without building
cargo check
```

### Testing

**This project uses [cargo-nextest](https://nexte.st/) for running tests.**

```bash
# Install nextest (one-time setup)
cargo install cargo-nextest

# Run all tests
cargo nextest run

# Run tests with logging
RUST_LOG=debug cargo nextest run
```

### Logging

Set the `RUST_LOG` environment variable to control logging levels:

```bash
# Debug level for all modules
RUST_LOG=debug cargo run

# Trace level for barycenter only
RUST_LOG=barycenter=trace cargo run
```

## API Endpoints

### Discovery
- `GET /.well-known/openid-configuration` - OpenID Provider metadata
- `GET /.well-known/jwks.json` - Public signing keys

### OAuth/OIDC
- `GET /authorize` - Authorization endpoint
- `POST /token` - Token endpoint
- `GET /userinfo` - UserInfo endpoint
- `POST /connect/register` - Dynamic client registration

### Properties (Non-standard)
- `GET /properties/:owner/:key` - Get property value
- `PUT /properties/:owner/:key` - Set property value

## Project Status

This is an early-stage implementation. See `docs/next-iteration-plan.md` for planned features and `docs/oidc-conformance.md` for OpenID Connect compliance details.

**Currently Implemented:**
- Authorization Code flow with PKCE (S256)
- Dynamic client registration
- Token issuance with RS256 ID Token signing (at_hash, nonce, auth_time, AMR, ACR)
- UserInfo endpoint
- Token endpoint with client_secret_basic and client_secret_post
- User authentication with sessions (password + passkey/WebAuthn)
- Two-factor authentication (admin-enforced, context-based)
- Consent flow with database persistence
- Refresh token grant with rotation
- Token revocation (RFC 7009) and introspection (RFC 7662)
- Device Authorization Grant (RFC 8628)
- Admin GraphQL API

**Pending Implementation:**
- OpenID Federation trust chain validation
- User account management UI
- Key rotation and multi-key JWKS

## Deployment

Barycenter supports multiple deployment platforms:

- **Docker**: Pre-built images available at `ghcr.io/[owner]/barycenter`
- **Kubernetes**: Helm chart with Ingress and Gateway API support
- **Linux**: systemd service with security hardening
- **FreeBSD**: rc.d init script
- **illumos/Solaris**: SMF manifest

See [DEPLOYMENT.md](DEPLOYMENT.md) for detailed installation instructions for each platform.

### Quick Start with Docker

```bash
docker pull ghcr.io/[owner]/barycenter:latest
docker run -p 8080:8080 -v barycenter-data:/app/data ghcr.io/[owner]/barycenter:latest
```

### Quick Start with Helm

```bash
helm install barycenter ./deploy/helm/barycenter \
  --namespace barycenter \
  --create-namespace
```

## Releases

For maintainers: see [RELEASE.md](RELEASE.md) for the release process.

To create a new release:
```bash
cargo install cargo-release
cargo release minor --execute  # Bumps version and creates release
```

## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on our code of conduct, development workflow, and the process for submitting pull requests.

## License

[Add your license here]

## Acknowledgments

Built with support from the OpenID Connect and OAuth 2.0 communities.
