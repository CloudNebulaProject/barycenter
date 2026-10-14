# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- Include the sign-in username in Admin CLI emails and on invitation password setup and activation confirmation pages.

### Added
- Initial release of Barycenter OpenID Connect Identity Provider
- OAuth 2.0 Authorization Code flow with PKCE (S256)
- Dynamic client registration
- ID Token signing (RS256) with at_hash and nonce support
- UserInfo endpoint with Bearer token authentication
- OpenID Discovery and JWKS publication
- User registration and authentication with session management
- Property storage API for arbitrary user properties
- Comprehensive deployment configurations:
  - Docker and Docker Compose
  - Kubernetes Helm chart with Ingress support
  - Kubernetes Gateway API support
  - systemd service for Linux
  - FreeBSD rc.d script
  - illumos/Solaris SMF manifest
- Security headers and Cache-Control for token endpoint
- Rate limiting for authentication endpoints
- Integration tests with openidconnect-rs and oauth2-rs libraries

### Security
- Password hashing with Argon2
- PKCE S256 enforcement
- CSRF protection with state parameter
- Security headers (X-Frame-Options, CSP, etc.)
- Non-root user execution in containers
- Extensive systemd security hardening

## [0.2.0-beta.22] - 2026-10-14

### Fixed
- Disable the Continue link before automatic navigation so it cannot start a duplicate federation callback (#13).
- Explain already-used, expired and mismatched federation callbacks with actionable messages and diagnostic logs (#13).
- Bound peer connection and token-exchange timeouts so failures are reported before gateway timeouts (#13).
- Make strict Clippy checks pass on Rust 1.99 and ignore Python cache artifacts (#14).

### Deployment
- No database schema migrations since beta.18; existing PostgreSQL databases, signing keys and issuer URLs remain compatible.
- Invitation onboarding improvements from beta.20 and beta.21 are included when upgrading beta.18. The optional `server.onboarding_app_url` defaults to unset.

## [0.1.0] - 2025-11-29

Initial development version.
