# Barycenter

Barycenter is a lightweight, Rust-based OpenID Connect Identity Provider (IdP) that implements the OAuth 2.0 Authorization Code flow with PKCE, WebAuthn/passkey authentication, device authorization grants, and a KDL-based authorization policy engine.

Built on top of [axum](https://github.com/tokio-rs/axum) and [SeaORM](https://www.sea-ql.org/SeaORM/), Barycenter is designed to be fast, self-contained, and straightforward to operate -- whether you are deploying it as a standalone identity provider or integrating it into a larger distributed system.

## Who This Book Is For

- **Operators** looking to deploy and configure Barycenter in development or production environments.
- **Application Developers** integrating their services with Barycenter as an OIDC provider.
- **Identity Engineers** evaluating Barycenter's authentication and authorization capabilities.
- **Contributors** who want to understand the internals and extend the project.

## How This Book Is Organized

| Section | Description |
|---------|-------------|
| [Getting Started](./getting-started/overview.md) | Project overview, installation, configuration, and a quickstart guide to get tokens flowing. |
| Authentication | Password login, WebAuthn/passkey authentication, two-factor enforcement, and session management. |
| OpenID Connect | Client registration, authorization code flow, token exchange, ID token claims, and discovery. |
| Authorization | KDL-based policy engine combining Relationship-Based Access Control (ReBAC) and Attribute-Based Access Control (ABAC). |
| Admin | GraphQL admin API for user management, background jobs, and operational tasks. |
| Deployment | Docker images, Kubernetes manifests, database choices, and production hardening. |
| Security | Security headers, PKCE enforcement, key management, and threat model considerations. |
| Development | Building from source, running tests, WASM client compilation, and contributing guidelines. |
| Reference | Endpoint reference, configuration keys, entity schemas, and error codes. |
