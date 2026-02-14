# Architecture

Barycenter is an OpenID Connect Identity Provider built in Rust. This page provides a high-level overview of the system architecture and links to detailed documentation for each subsystem.

## System Overview

Barycenter runs as a single binary that serves two HTTP interfaces:

- **Main server** (default port 9090): Handles all OpenID Connect, OAuth 2.0, WebAuthn, and user-facing endpoints.
- **Admin server** (default port 9091): Serves the GraphQL management API for administrative operations.

Both servers share the same application state, database connection, and background job scheduler.

```text
                    ┌─────────────────────────────────────────┐
                    │              Barycenter                  │
                    │                                         │
  Clients ────────► │  :9090  Main Server (OIDC/OAuth/WebAuthn) │
                    │                                         │
  Admins ─────────► │  :9091  Admin Server (GraphQL)           │
                    │                                         │
                    │  Background Jobs (scheduled)             │
                    │                                         │
                    │         ┌──────────────────┐            │
                    │         │   AppState        │            │
                    │         │  ┌─────────────┐  │            │
                    │         │  │ Settings     │  │            │
                    │         │  │ Database     │  │            │
                    │         │  │ JwksManager  │  │            │
                    │         │  │ WebAuthn     │  │            │
                    │         │  └─────────────┘  │            │
                    │         └──────────────────┘            │
                    │                  │                       │
                    │         ┌────────▼────────┐             │
                    │         │   Database       │             │
                    │         │ SQLite / Postgres │             │
                    │         └─────────────────┘             │
                    └─────────────────────────────────────────┘
```

## Application State

The `AppState` struct is shared across all request handlers via Axum's state extraction. It contains:

| Field | Type | Purpose |
|-------|------|---------|
| `settings` | `Arc<Settings>` | Application configuration (server, database, keys, federation) |
| `db` | `DatabaseConnection` | SeaORM database connection (SQLite or PostgreSQL) |
| `jwks` | `JwksManager` | RSA key management, JWT signing, JWKS publication |
| `webauthn` | `WebAuthnManager` | WebAuthn/passkey operations (registration, authentication, 2FA) |

## Startup Sequence

The application initializes in a specific order, where each step depends on the previous:

1. **Parse CLI arguments** -- Read the config file path from command-line arguments.
2. **Load settings** -- Merge configuration from the config file, environment variables, and defaults.
3. **Initialize database** -- Connect to SQLite or PostgreSQL and run pending migrations via `Migrator::up()`.
4. **Initialize JWKS** -- Generate or load RSA keys for JWT signing.
5. **Initialize WebAuthn** -- Configure the WebAuthn manager with the application's origin and relying party ID.
6. **Start background jobs** -- Schedule cleanup jobs for sessions, tokens, and WebAuthn challenges.
7. **Start HTTP servers** -- Bind the main server and admin server to their configured ports.

## Key Subsystems

### Module Structure

The codebase is organized into focused modules, each handling a specific concern. See [Module Structure](module-structure.md) for the complete list with descriptions and a dependency graph.

### Database Schema

Barycenter uses SeaORM with 12 entity tables covering clients, users, tokens, sessions, passkeys, and administrative records. See [Database Schema](database-schema.md) for table definitions.

### Error Handling

Errors are handled through the `CrabError` enum with miette diagnostics for developer-facing messages and OAuth-compliant error responses for client-facing errors. See [Error Handling](error-handling.md) for details.

### Security

Security is enforced at multiple layers: transport (TLS), browser (security headers), protocol (PKCE, nonce), and infrastructure (hardening). See the [Security](../security/security-model.md) section for comprehensive documentation.

## Request Flow

A typical OpenID Connect Authorization Code flow passes through these components:

```text
1. GET /authorize
   └─► web module
       └─► Validate client_id, redirect_uri, scope, PKCE
       └─► Check session (session module)
       └─► If not authenticated: redirect to /login
       └─► Store auth code (storage module)
       └─► Redirect to client with code + state

2. POST /token
   └─► web module
       └─► Authenticate client (Basic auth or POST body)
       └─► Validate authorization code + PKCE verifier (storage module)
       └─► Generate access token (storage module)
       └─► Sign ID token (jwks module)
       └─► Return JSON response

3. GET /userinfo
   └─► web module
       └─► Validate Bearer token (storage module)
       └─► Return user claims as JSON
```

## Technology Stack

| Component | Technology |
|-----------|-----------|
| Language | Rust |
| Web framework | Axum |
| Database ORM | SeaORM |
| Database backends | SQLite, PostgreSQL |
| JWT/JOSE | josekit |
| Password hashing | argon2 |
| WebAuthn | webauthn-rs |
| GraphQL | async-graphql |
| WASM tooling | wasm-pack, wasm-bindgen |
| Serialization | serde, serde_json |
| Configuration | config-rs |
