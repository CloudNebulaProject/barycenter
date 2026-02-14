# Overview

Barycenter is a lightweight OpenID Connect Identity Provider written in Rust. It provides a complete OAuth 2.0 and OIDC implementation suitable for organizations that need a self-hosted identity provider without the operational overhead of larger platforms like Keycloak or the limited scope of token-only services like Dex.

## Purpose

Barycenter exists to fill a gap between minimal token issuers and full-featured identity management suites. It provides a standards-compliant OIDC implementation with modern authentication methods, a built-in authorization policy engine, and a small operational footprint -- all in a single statically-compiled binary.

## Capabilities

- **OpenID Connect Authorization Code Flow** with mandatory PKCE (S256) for all clients
- **Dynamic Client Registration** via the `/connect/register` endpoint
- **WebAuthn/Passkey Authentication** supporting single-factor passwordless login and two-factor verification
- **Device Authorization Grant** (RFC 8628) for input-constrained devices such as smart TVs and CLI tools
- **Token Management** including access tokens, ID tokens with full claim sets, and refresh tokens with rotation
- **Token Revocation** for access and refresh tokens
- **Consent Flow** with per-client, per-scope tracking and remembering user decisions
- **KDL-Based Authorization Policy Engine** combining Relationship-Based Access Control (ReBAC) and Attribute-Based Access Control (ABAC)
- **Admin GraphQL API** for user management, 2FA enforcement, and operational job control
- **Background Job Scheduler** for automatic cleanup of expired sessions, tokens, and challenges
- **Dual Database Support** with SQLite for development and PostgreSQL for production, with automatic migrations
- **Security Headers** applied to all responses (CSP, X-Frame-Options, referrer policy, and more)

## Positioning

| | Barycenter | Keycloak | Dex |
|---|---|---|---|
| Language | Rust | Java | Go |
| Binary size | Small, single binary | Large (JVM) | Small, single binary |
| Database | SQLite or PostgreSQL | PostgreSQL (required) | Various connectors |
| Authentication | Passwords, passkeys, 2FA | Passwords, OTP, WebAuthn, social | Delegates to upstream IdPs |
| Authorization | Built-in policy engine (ReBAC + ABAC) | Role-based, fine-grained authz | None |
| Admin interface | GraphQL API | Web console + REST API | gRPC API |
| Memory footprint | Low | High | Low |
| Target use case | Self-hosted IdP with authz | Enterprise IAM | Federated connector |

Barycenter is best suited for teams that want a self-contained identity provider they can compile, configure, and deploy without managing a JVM runtime, external policy engines, or complex clustering setups.

## Key Features at a Glance

- **Standards compliant**: OIDC Core, OAuth 2.0, PKCE (RFC 7636), Device Authorization (RFC 8628)
- **Modern authentication**: WebAuthn/FIDO2 passkeys with conditional UI and autofill support
- **Three-port architecture**: Public OIDC endpoints, admin GraphQL API, and authorization policy service each on dedicated ports
- **Configuration layers**: Defaults, TOML configuration file, and environment variable overrides
- **Automatic key management**: RSA key pair generated on first run and persisted for subsequent starts
- **Zero-downtime migrations**: Database schema migrations run automatically on startup
