# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

## [0.1.0] - 2025-11-29

Initial development version.
