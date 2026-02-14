[Introduction](README.md)

# Getting Started

- [Overview](getting-started/overview.md)
  - [Architecture](getting-started/architecture.md)
  - [Key Concepts](getting-started/key-concepts.md)
- [Installation](getting-started/installation.md)
  - [Prerequisites](getting-started/prerequisites.md)
  - [Building from Source](getting-started/building-from-source.md)
  - [Docker](getting-started/docker.md)
- [Quick Start](getting-started/quickstart.md)
- [Configuration](getting-started/configuration.md)
  - [Configuration File](getting-started/config-file.md)
  - [Environment Variables](getting-started/env-variables.md)
  - [Database Setup](getting-started/database-setup.md)

# Authentication

- [Password Authentication](authentication/password.md)
- [Passkey / WebAuthn](authentication/passkeys.md)
  - [How Passkeys Work](authentication/passkeys-how.md)
  - [Registering a Passkey](authentication/passkey-registration.md)
  - [Authenticating with a Passkey](authentication/passkey-authentication.md)
  - [Conditional UI / Autofill](authentication/conditional-ui.md)
- [Two-Factor Authentication](authentication/two-factor.md)
  - [Admin-Enforced 2FA](authentication/2fa-admin-enforced.md)
  - [Context-Based 2FA](authentication/2fa-context-based.md)
  - [User-Optional 2FA](authentication/2fa-user-optional.md)
  - [2FA Flow Walkthrough](authentication/2fa-flow.md)
- [Sessions](authentication/sessions.md)
  - [AMR and ACR Claims](authentication/amr-acr.md)
  - [Session Lifecycle](authentication/session-lifecycle.md)
- [Consent Flow](authentication/consent.md)

# OAuth 2.0 & OpenID Connect

- [Authorization Code Flow with PKCE](oidc/authorization-code-flow.md)
- [Dynamic Client Registration](oidc/client-registration.md)
- [Token Endpoint](oidc/token-endpoint.md)
  - [Authorization Code Grant](oidc/grant-authorization-code.md)
  - [Refresh Token Grant](oidc/grant-refresh-token.md)
  - [Device Authorization Grant](oidc/grant-device-authorization.md)
  - [Client Authentication Methods](oidc/client-authentication.md)
- [ID Token](oidc/id-token.md)
- [UserInfo Endpoint](oidc/userinfo.md)
- [Discovery and JWKS](oidc/discovery-jwks.md)
- [Token Revocation](oidc/token-revocation.md)

# Authorization Policy Engine

- [Overview](authz/overview.md)
- [KDL Policy Language](authz/kdl-policy-language.md)
  - [Resources and Permissions](authz/resources-permissions.md)
  - [Roles and Inheritance](authz/roles-inheritance.md)
  - [Grants and Relationship Tuples](authz/grants-tuples.md)
  - [ABAC Rules and Conditions](authz/abac-rules.md)
- [Authz REST API](authz/rest-api.md)
- [Configuration and Deployment](authz/configuration.md)

# Administration

- [Admin GraphQL API](admin/graphql-api.md)
  - [Entity CRUD (Seaography)](admin/entity-crud.md)
  - [Job Management](admin/job-management.md)
  - [User 2FA Management](admin/user-2fa.md)
  - [GraphQL Playground](admin/playground.md)
- [User Management](admin/user-management.md)
  - [Creating Users](admin/creating-users.md)
  - [User Sync from JSON](admin/user-sync.md)
  - [Public Registration](admin/public-registration.md)
- [Passkey Management](admin/passkey-management.md)
- [Background Jobs](admin/background-jobs.md)
  - [Available Jobs](admin/available-jobs.md)
  - [Job Scheduling](admin/job-scheduling.md)
  - [Monitoring Job Executions](admin/job-monitoring.md)

# Deployment

- [Docker](deployment/docker.md)
- [Docker Compose](deployment/docker-compose.md)
- [Kubernetes with Helm](deployment/kubernetes-helm.md)
  - [Helm Chart Values](deployment/helm-values.md)
  - [Ingress Configuration](deployment/helm-ingress.md)
  - [Gateway API](deployment/gateway-api.md)
  - [User Sync in Kubernetes](deployment/k8s-user-sync.md)
  - [Authorization Policies in Kubernetes](deployment/k8s-authz-policies.md)
- [Linux systemd](deployment/systemd.md)
- [FreeBSD rc.d](deployment/freebsd.md)
- [illumos / Solaris SMF](deployment/illumos-smf.md)
- [Reverse Proxy and TLS](deployment/reverse-proxy-tls.md)
- [Production Checklist](deployment/production-checklist.md)
- [Backup and Recovery](deployment/backup-recovery.md)

# Security

- [Security Model](security/security-model.md)
- [PKCE Enforcement](security/pkce.md)
- [Security Headers](security/headers.md)
- [Session Security](security/session-security.md)
- [Rate Limiting](security/rate-limiting.md)
- [File Permissions and Hardening](security/hardening.md)

# Development

- [Building from Source](development/building.md)
- [Running Tests](development/testing.md)
- [Building the WASM Client](development/wasm-client.md)
- [Architecture Deep Dive](development/architecture.md)
  - [Module Structure](development/module-structure.md)
  - [Database Schema and Migrations](development/database-schema.md)
  - [Error Handling](development/error-handling.md)
- [Contributing](development/contributing.md)
- [Release Process](development/release-process.md)

# Reference

- [API Endpoint Reference](reference/api-endpoints.md)
- [Configuration Reference](reference/configuration.md)
- [Database Schema Reference](reference/database-schema.md)
- [OIDC Conformance Status](reference/oidc-conformance.md)
- [Glossary](reference/glossary.md)
