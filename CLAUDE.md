# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Barycenter is an OpenID Connect Identity Provider (IdP) implementing OAuth 2.0 Authorization Code flow with PKCE. The project is written in Rust using axum for the web framework, SeaORM for database access (SQLite), and josekit for JOSE/JWT operations.

## Build and Development Commands

```bash
# Build the project
cargo build

# Run the application (defaults to config.toml)
cargo run

# Run with custom config
cargo run -- --config path/to/config.toml

# Run in release mode
cargo build --release
cargo run --release

# Check code without building
cargo check

# Run tests (IMPORTANT: use cargo nextest, not cargo test)
cargo nextest run

# Run with logging (uses RUST_LOG environment variable)
RUST_LOG=debug cargo run
RUST_LOG=barycenter=trace cargo run
```

## Testing

**CRITICAL: Always use `cargo nextest run` instead of `cargo test`.**

This project uses [cargo-nextest](https://nexte.st/) for running tests because:
- Tests run in separate processes, preventing port conflicts in integration tests
- Better test isolation and reliability
- Cleaner output and better performance

Install nextest if you don't have it:
```bash
cargo install cargo-nextest
```

Run tests:
```bash
# Run all tests
cargo nextest run

# Run with verbose output
cargo nextest run --verbose

# Run specific test
cargo nextest run test_name
```

## Configuration

The application loads configuration from:
1. Default values (defined in `src/settings.rs`)
2. Configuration file (default: `config.toml`)
3. Environment variables with prefix `CRABIDP__` (e.g., `CRABIDP__SERVER__PORT=9090`)

Environment variables use double underscores as separators for nested keys.

## Architecture and Module Structure

### Entry Point (`src/main.rs`)
The application initializes in this order:
1. Parse CLI arguments for config file path
2. Load settings from config file and environment
3. Initialize database connection and create tables via `storage::init()`
4. Initialize JWKS manager (generates or loads RSA keys)
5. Start web server with `web::serve()`

### Settings (`src/settings.rs`)
Manages configuration with four main sections:
- `Server`: listen address and public base URL (issuer)
- `Database`: SQLite connection string
- `Keys`: JWKS and private key paths, signing algorithm
- `Federation`: trust anchor URLs (future use)

The `issuer()` method returns the OAuth issuer URL, preferring `public_base_url` or falling back to `http://{host}:{port}`.

### Storage (`src/storage.rs`)
Database layer with raw SQL using SeaORM's `DatabaseConnection`. Tables:
- `clients`: OAuth client registrations (client_id, client_secret, redirect_uris)
- `auth_codes`: Authorization codes with PKCE challenge, subject, scope, nonce
- `access_tokens`: Bearer tokens with subject, scope, expiration
- `properties`: Key-value store for arbitrary user properties (owner, key, value)

All IDs and tokens are generated via `random_id()` (24 random bytes, base64url-encoded).

### JWKS Manager (`src/jwks.rs`)
Handles RSA key generation, persistence, and JWT signing:
- Generates 2048-bit RSA key on first run
- Persists private key as JSON to `private_key_path`
- Publishes public key set to `jwks_path`
- Provides `sign_jwt_rs256()` for ID Token signing with kid header

### Web Endpoints (`src/web.rs`)
Implements OpenID Connect and OAuth 2.0 endpoints:

**Discovery & Registration:**
- `GET /.well-known/openid-configuration` - OpenID Provider metadata
- `GET /.well-known/jwks.json` - Public signing keys
- `POST /connect/register` - Dynamic client registration

**OAuth/OIDC Flow:**
- `GET /authorize` - Authorization endpoint (issues authorization code with PKCE)
  - Currently uses fixed subject "demo-user" (pending login flow implementation per docs/next-iteration-plan.md)
  - Validates client_id, redirect_uri, scope (must include "openid"), PKCE S256
  - Returns redirect with code and state
- `POST /token` - Token endpoint (exchanges code for tokens)
  - Supports `client_secret_basic` (Authorization header) and `client_secret_post` (form body)
  - Validates PKCE S256 code_verifier
  - Returns access_token, id_token (JWT), token_type, expires_in
- `GET /userinfo` - UserInfo endpoint (returns claims for Bearer token)

**Non-Standard:**
- `GET /properties/:owner/:key` - Get property value
- `PUT /properties/:owner/:key` - Set property value
- `GET /federation/trust-anchors` - List trust anchors

### Error Handling (`src/errors.rs`)
Defines `CrabError` for internal error handling with conversions from common error types.

## Key Implementation Details

### PKCE Flow
- Only S256 code challenge method is supported (plain is rejected)
- Code challenge stored with auth code
- Code verifier validated at token endpoint by hashing and comparing

### Client Authentication
Token endpoint accepts two methods:
1. `client_secret_basic`: HTTP Basic auth (client_id:client_secret base64-encoded)
2. `client_secret_post`: Form parameters (client_id and client_secret in body)

### ID Token Claims
Generated ID tokens include:
- Standard claims: iss, sub, aud, exp, iat
- Optional: nonce (if provided in authorize request)
- at_hash: hash of access token per OIDC spec (left 128 bits of SHA-256, base64url)
- Signed with RS256, includes kid header matching JWKS

### State Management
- Authorization codes: 5 minute TTL, single-use (marked consumed)
- Access tokens: 1 hour TTL, checked for expiration and revoked flag
- Both stored in SQLite with timestamps

## Current Implementation Status

See `docs/oidc-conformance.md` for detailed OIDC compliance requirements.

**Implemented:**
- Authorization Code flow with PKCE (S256)
- Dynamic client registration
- Token endpoint with client_secret_basic and client_secret_post
- ID Token signing (RS256) with at_hash and nonce
- UserInfo endpoint with Bearer token authentication
- Discovery and JWKS publication
- Property storage API

**Pending (see docs/next-iteration-plan.md):**
- User authentication and session management (currently uses fixed "demo-user" subject)
- auth_time claim in ID Token (requires session tracking)
- Cache-Control headers on token endpoint
- Consent flow (currently auto-consents)
- Refresh tokens
- Token revocation and introspection
- OpenID Federation trust chain validation

## Testing and Validation

No automated tests currently exist. Manual testing can be done with curl commands following the OAuth 2.0 Authorization Code + PKCE flow:

1. Register a client via `POST /connect/register`
2. Generate PKCE verifier and challenge
3. Navigate to `/authorize` with required parameters
4. Exchange authorization code at `/token` with code_verifier
5. Access `/userinfo` with Bearer access_token

Example PKCE generation (bash):
```bash
verifier=$(openssl rand -base64 32 | tr -d '=' | tr '+/' '-_')
challenge=$(echo -n "$verifier" | openssl dgst -binary -sha256 | base64 | tr -d '=' | tr '+/' '-_')
```
