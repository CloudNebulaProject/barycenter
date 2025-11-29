### OpenID Connect OP conformance plan (context7 summary)

This project is an OpenID Provider (OP) scaffold. This document summarizes what must be implemented to align with OpenID Connect 1.0 (and adjacent OAuth2/OAuth 2.1 guidance), what we already have, and the minimal viable roadmap.

Scope references (context7 up-to-date pointers):
- OpenID Connect Core 1.0 (final)
- OpenID Connect Discovery 1.0 (/.well-known/openid-configuration)
- OAuth 2.0 (RFC 6749) + PKCE (RFC 7636) and OAuth 2.1 draft guidance + OAuth 2.0 Security BCP (RFC 6819 successor BCPs)
- OpenID Connect Dynamic Client Registration 1.0
- OpenID Federation 1.0 (for later phases)


1) Endpoints required for a basic, interoperable OP
- Authorization endpoint: GET/POST /authorize
  - Response type: code (Authorization Code Flow)
  - Required request params: client_id, redirect_uri, response_type=code, scope (includes openid), state; Recommended: nonce; If PKCE is used: code_challenge, code_challenge_method=S256
  - Validations: registered redirect_uri match, scope contains openid, client is known, response_type supported, PKCE required for public clients
  - Output: HTTP redirect to redirect_uri with code and state

- Token endpoint: POST /token (application/x-www-form-urlencoded)
  - Grant type: authorization_code
  - Parameters: grant_type, code, redirect_uri, client authentication
    - Client auth: client_secret_post (initial support); consider client_secret_basic later
  - PKCE verification: code_verifier must match stored code_challenge (S256)
  - Output: JSON with access_token, token_type=bearer, expires_in, id_token (JWT), possibly refresh_token
  - Error model: RFC 6749 + OIDC specific where applicable

- UserInfo endpoint: GET/POST /userinfo (Bearer token)
  - Input: Authorization: Bearer <access_token>
  - Output: JSON claims for the subject consistent with scopes (profile, email, etc.)

- Discovery endpoint: GET /.well-known/openid-configuration
  - Must publish: issuer, authorization_endpoint, token_endpoint, jwks_uri, response_types_supported, subject_types_supported, id_token_signing_alg_values_supported
  - Should publish: registration_endpoint (if supported), scopes_supported, claims_supported, grant_types_supported, token_endpoint_auth_methods_supported, code_challenge_methods_supported

- JWKS endpoint: GET /.well-known/jwks.json
  - Publish public keys used to sign ID Tokens; include kid values

- Dynamic Client Registration endpoint: POST /connect/register
  - Accept a subset of metadata: redirect_uris (required), client_name, token_endpoint_auth_method, etc.
  - Output per spec: client_id, client_secret (for confidential clients), client_id_issued_at, token_endpoint_auth_method, and echoed metadata
  - Later: registration access token and client configuration endpoint


2) Tokens and claims
- ID Token (JWT, JWS RS256 initially)
  - Required claims: iss, sub, aud, exp, iat, auth_time (if max_age requested), nonce (if provided in auth request), at_hash (if access token issued), c_hash (optional if code returned from token endpoint)
  - kid header must match a key in JWKS; alg consistent with discovery

- Access Token
  - Can be opaque initially; include reference in DB; expires_in typically 3600s
  - Optionally JWT access tokens later

- Refresh Token (optional in MVP)
  - Issue for offline_access scope; secure storage; rotation recommended


3) Storage additions (DB)
- auth_codes: code, client_id, redirect_uri, scope, subject, nonce, code_challenge (S256), created_at, expires_at, consumed
- access_tokens: token, client_id, subject, scope, created_at, expires_at, revoked
- refresh_tokens (optional initially)


4) Security requirements (minimum)
- Enforce PKCE S256 for public clients; allow confidential without PKCE only if policy allows (recommended: require for all)
- Validate redirect_uri exact match against one of the client’s registered URIs
- Validate aud (client_id) and iss in ID Token; use correct exp/iat skew bounds
- Use state and nonce to prevent CSRF and token replay
- Use HTTPS in production; publish an https issuer in discovery via server.public_base_url


5) Discovery metadata we should publish once endpoints exist
- issuer: <base URL>
- authorization_endpoint: <issuer>/authorize
- token_endpoint: <issuer>/token
- jwks_uri: <issuer>/.well-known/jwks.json
- registration_endpoint: <issuer>/connect/register
- response_types_supported: ["code"]
- grant_types_supported: ["authorization_code"]
- subject_types_supported: ["public"]
- id_token_signing_alg_values_supported: ["RS256"]
- token_endpoint_auth_methods_supported: ["client_secret_post"]
- code_challenge_methods_supported: ["S256"]
- scopes_supported: ["openid", "profile", "email"]
- claims_supported: ["sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "name", "given_name", "family_name", "email", "email_verified"]
- userinfo_endpoint: <issuer>/userinfo (once implemented)


6) Current status in this repository
- Implemented:
  - Discovery endpoint (basic subset)
  - JWKS publication with key generation and persistence
  - Dynamic client auto-registration (basic)
  - Simple property storage API (non-standard)
  - Federation trust anchors stub

- Missing for OIDC Core compliance:
  - /authorize (Authorization Code + PKCE)
  - /token (code exchange, ID Token signing)
  - /userinfo
  - Storage for auth codes and tokens
  - Full error models and input validation across endpoints
  - Robust client registration validation + optional configuration endpoint


7) Minimal viable roadmap (incremental)
Step 1: Data model and discovery metadata
- Add DB tables for auth_codes and access_tokens
- Extend discovery to include grant_types_supported, token_endpoint_auth_methods_supported, code_challenge_methods_supported, claims_supported

Step 2: Authorization Code + PKCE
- Implement /authorize to issue short-lived codes; validate redirect_uri, scope, client, state, nonce, PKCE

Step 3: Token endpoint and ID Token
- Implement /token; client_secret_post, PKCE verification; sign ID Token with RS256 using current JWK; include required claims

Step 4: UserInfo
- Implement /userinfo backed by properties or a user table; authorize via access token

Step 5: Hardening and cleanup
- Proper errors per specs; input validation; token lifetimes; background pruning of consumed/expired artifacts
- Optional: client_secret_basic, refresh tokens, rotation, revocation, introspection

Step 6: Federation (later)
- Entity statement issuance, publication, and trust chain verification; policy application to registration


Implementation notes
- Keep issuer stable and correct in settings.server.public_base_url for production
- Ensure JWKS kid selection and alg entry match discovery
- Prefer S256 for PKCE; do not support plain
- Add tests or curl scripts to verify end-to-end flows
