# OIDC Conformance

This document tracks Barycenter's conformance with OpenID Connect and OAuth 2.0 specifications. Each item references the relevant RFC or specification section and indicates whether it is implemented.

Legend:
- [x] Implemented
- [ ] Not yet implemented

---

## OpenID Connect Core 1.0

**Specification:** [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)

### Flows

| Status | Feature | Reference |
|--------|---------|-----------|
| [x] | Authorization Code flow | [OIDC Core 3.1](https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth) |
| [x] | Implicit flow (`id_token` response type) | [OIDC Core 3.2](https://openid.net/specs/openid-connect-core-1_0.html#ImplicitFlowAuth) |
| [x] | Implicit flow (`id_token token` response type) | [OIDC Core 3.2](https://openid.net/specs/openid-connect-core-1_0.html#ImplicitFlowAuth) |
| [ ] | Hybrid flow (`code id_token`, `code token`, `code id_token token`) | [OIDC Core 3.3](https://openid.net/specs/openid-connect-core-1_0.html#HybridFlowAuth) |

### ID Token

| Status | Feature | Reference |
|--------|---------|-----------|
| [x] | ID Token issuance with required claims (`iss`, `sub`, `aud`, `exp`, `iat`) | [OIDC Core 2](https://openid.net/specs/openid-connect-core-1_0.html#IDToken) |
| [x] | `nonce` claim (when provided in authorization request) | [OIDC Core 3.1.2.1](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest) |
| [x] | `auth_time` claim | [OIDC Core 2](https://openid.net/specs/openid-connect-core-1_0.html#IDToken) |
| [x] | `at_hash` claim (left 128 bits of SHA-256 of access token, base64url) | [OIDC Core 3.1.3.6](https://openid.net/specs/openid-connect-core-1_0.html#CodeIDToken) |
| [x] | `amr` claim (Authentication Methods References) | [RFC 8176](https://www.rfc-editor.org/rfc/rfc8176) |
| [x] | `acr` claim (Authentication Context Class Reference) | [OIDC Core 2](https://openid.net/specs/openid-connect-core-1_0.html#IDToken) |
| [x] | RS256 signing | [OIDC Core 3.1.3.7](https://openid.net/specs/openid-connect-core-1_0.html#TokenResponseValidation) |
| [x] | `kid` header in signed JWTs matching JWKS | [JWS (RFC 7515) 4.1.4](https://www.rfc-editor.org/rfc/rfc7515#section-4.1.4) |

### Endpoints

| Status | Feature | Reference |
|--------|---------|-----------|
| [x] | Authorization endpoint | [OIDC Core 3.1.2](https://openid.net/specs/openid-connect-core-1_0.html#AuthorizationEndpoint) |
| [x] | Token endpoint | [OIDC Core 3.1.3](https://openid.net/specs/openid-connect-core-1_0.html#TokenEndpoint) |
| [x] | UserInfo endpoint | [OIDC Core 5.3](https://openid.net/specs/openid-connect-core-1_0.html#UserInfo) |

### Claims

| Status | Feature | Reference |
|--------|---------|-----------|
| [x] | `sub` claim in UserInfo | [OIDC Core 5.3.2](https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse) |
| [x] | Standard claims (`name`, `email`) | [OIDC Core 5.1](https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims) |
| [ ] | Full standard claims set (`given_name`, `family_name`, `picture`, etc.) | [OIDC Core 5.1](https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims) |
| [ ] | Claims request parameter | [OIDC Core 5.5](https://openid.net/specs/openid-connect-core-1_0.html#ClaimsParameter) |

---

## OpenID Connect Discovery 1.0

**Specification:** [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)

| Status | Feature | Reference |
|--------|---------|-----------|
| [x] | Provider metadata at `/.well-known/openid-configuration` | [Discovery 4](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata) |
| [x] | `issuer` in metadata | Discovery 3 |
| [x] | `authorization_endpoint` in metadata | Discovery 3 |
| [x] | `token_endpoint` in metadata | Discovery 3 |
| [x] | `userinfo_endpoint` in metadata | Discovery 3 |
| [x] | `jwks_uri` in metadata | Discovery 3 |
| [x] | `registration_endpoint` in metadata | Discovery 3 |
| [x] | `response_types_supported` in metadata | Discovery 3 |
| [x] | `grant_types_supported` in metadata | Discovery 3 |
| [x] | `token_endpoint_auth_methods_supported` in metadata | Discovery 3 |
| [x] | `subject_types_supported` in metadata | Discovery 3 |
| [x] | `id_token_signing_alg_values_supported` in metadata | Discovery 3 |

---

## JSON Web Key Set (JWKS)

**Specification:** [RFC 7517 - JSON Web Key](https://www.rfc-editor.org/rfc/rfc7517)

| Status | Feature | Reference |
|--------|---------|-----------|
| [x] | JWKS publication at `/.well-known/jwks.json` | [RFC 7517 5](https://www.rfc-editor.org/rfc/rfc7517#section-5) |
| [x] | RSA public key parameters (`n`, `e`, `kty`, `use`, `kid`) | [RFC 7517 4](https://www.rfc-editor.org/rfc/rfc7517#section-4) |
| [x] | Key ID (`kid`) matching JWT headers | [RFC 7515 4.1.4](https://www.rfc-editor.org/rfc/rfc7515#section-4.1.4) |

---

## OAuth 2.0 Authorization Framework

**Specification:** [RFC 6749 - The OAuth 2.0 Authorization Framework](https://www.rfc-editor.org/rfc/rfc6749)

### Grant Types

| Status | Feature | Reference |
|--------|---------|-----------|
| [x] | Authorization Code grant | [RFC 6749 4.1](https://www.rfc-editor.org/rfc/rfc6749#section-4.1) |
| [x] | Refresh Token grant | [RFC 6749 6](https://www.rfc-editor.org/rfc/rfc6749#section-6) |
| [x] | Device Authorization grant | [RFC 8628](https://www.rfc-editor.org/rfc/rfc8628) |
| [x] | Implicit grant (`token` response type via OIDC implicit) | [RFC 6749 4.2](https://www.rfc-editor.org/rfc/rfc6749#section-4.2) |
| [ ] | Client Credentials grant | [RFC 6749 4.3](https://www.rfc-editor.org/rfc/rfc6749#section-4.3) |

### Client Authentication

| Status | Feature | Reference |
|--------|---------|-----------|
| [x] | `client_secret_basic` (HTTP Basic with client_id:client_secret) | [RFC 6749 2.3.1](https://www.rfc-editor.org/rfc/rfc6749#section-2.3.1) |
| [x] | `client_secret_post` (client_id and client_secret in form body) | [RFC 6749 2.3.1](https://www.rfc-editor.org/rfc/rfc6749#section-2.3.1) |
| [ ] | `private_key_jwt` | [OIDC Core 9](https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication) |
| [ ] | `client_secret_jwt` | [OIDC Core 9](https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication) |
| [ ] | `none` (public clients) | [RFC 6749 2.3](https://www.rfc-editor.org/rfc/rfc6749#section-2.3) |

### Security

| Status | Feature | Reference |
|--------|---------|-----------|
| [x] | `state` parameter support | [RFC 6749 4.1.1](https://www.rfc-editor.org/rfc/rfc6749#section-4.1.1) |
| [x] | Redirect URI exact matching | [RFC 6749 3.1.2.3](https://www.rfc-editor.org/rfc/rfc6749#section-3.1.2.3) |
| [x] | Authorization code single-use enforcement | [RFC 6749 4.1.2](https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2) |
| [x] | Authorization code 5-minute expiration | [RFC 6749 4.1.2](https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2) |
| [ ] | `Cache-Control: no-store` on token endpoint responses | [RFC 6749 5.1](https://www.rfc-editor.org/rfc/rfc6749#section-5.1) |

---

## PKCE (Proof Key for Code Exchange)

**Specification:** [RFC 7636 - Proof Key for Code Exchange](https://www.rfc-editor.org/rfc/rfc7636)

| Status | Feature | Reference |
|--------|---------|-----------|
| [x] | S256 code challenge method | [RFC 7636 4.2](https://www.rfc-editor.org/rfc/rfc7636#section-4.2) |
| [x] | Code challenge stored with authorization code | [RFC 7636 4.4](https://www.rfc-editor.org/rfc/rfc7636#section-4.4) |
| [x] | Code verifier validation at token endpoint | [RFC 7636 4.6](https://www.rfc-editor.org/rfc/rfc7636#section-4.6) |
| [x] | Rejection of `plain` code challenge method | Security best practice |

---

## OAuth 2.0 Dynamic Client Registration

**Specification:** [RFC 7591 - OAuth 2.0 Dynamic Client Registration](https://www.rfc-editor.org/rfc/rfc7591)

| Status | Feature | Reference |
|--------|---------|-----------|
| [x] | Registration endpoint (`POST /connect/register`) | [RFC 7591 3](https://www.rfc-editor.org/rfc/rfc7591#section-3) |
| [x] | `redirect_uris` in registration request | [RFC 7591 2](https://www.rfc-editor.org/rfc/rfc7591#section-2) |
| [x] | `client_name` in registration request | [RFC 7591 2](https://www.rfc-editor.org/rfc/rfc7591#section-2) |
| [x] | Return of `client_id` and `client_secret` in response | [RFC 7591 3.2](https://www.rfc-editor.org/rfc/rfc7591#section-3.2) |
| [ ] | Client registration access token for management | [RFC 7592](https://www.rfc-editor.org/rfc/rfc7592) |

---

## OAuth 2.0 Token Revocation

**Specification:** [RFC 7009 - OAuth 2.0 Token Revocation](https://www.rfc-editor.org/rfc/rfc7009)

| Status | Feature | Reference |
|--------|---------|-----------|
| [x] | Revocation endpoint (`POST /revoke`) | [RFC 7009 2](https://www.rfc-editor.org/rfc/rfc7009#section-2) |
| [x] | Access token revocation | [RFC 7009 2.1](https://www.rfc-editor.org/rfc/rfc7009#section-2.1) |
| [x] | Refresh token revocation | [RFC 7009 2.1](https://www.rfc-editor.org/rfc/rfc7009#section-2.1) |
| [x] | `token_type_hint` parameter support | [RFC 7009 2.1](https://www.rfc-editor.org/rfc/rfc7009#section-2.1) |

---

## OAuth 2.0 Token Introspection

**Specification:** [RFC 7662 - OAuth 2.0 Token Introspection](https://www.rfc-editor.org/rfc/rfc7662)

| Status | Feature | Reference |
|--------|---------|-----------|
| [ ] | Introspection endpoint | [RFC 7662 2](https://www.rfc-editor.org/rfc/rfc7662#section-2) |
| [ ] | `active` field in introspection response | [RFC 7662 2.2](https://www.rfc-editor.org/rfc/rfc7662#section-2.2) |

---

## OAuth 2.0 Device Authorization Grant

**Specification:** [RFC 8628 - OAuth 2.0 Device Authorization Grant](https://www.rfc-editor.org/rfc/rfc8628)

| Status | Feature | Reference |
|--------|---------|-----------|
| [x] | Device authorization endpoint (`POST /device_authorization`) | [RFC 8628 3.1](https://www.rfc-editor.org/rfc/rfc8628#section-3.1) |
| [x] | `device_code` and `user_code` issuance | [RFC 8628 3.2](https://www.rfc-editor.org/rfc/rfc8628#section-3.2) |
| [x] | `verification_uri` and `verification_uri_complete` | [RFC 8628 3.2](https://www.rfc-editor.org/rfc/rfc8628#section-3.2) |
| [x] | User verification page (`GET /device`) | [RFC 8628 3.3](https://www.rfc-editor.org/rfc/rfc8628#section-3.3) |
| [x] | Token endpoint support for `urn:ietf:params:oauth:grant-type:device_code` | [RFC 8628 3.4](https://www.rfc-editor.org/rfc/rfc8628#section-3.4) |
| [x] | Polling with `slow_down` and `authorization_pending` errors | [RFC 8628 3.5](https://www.rfc-editor.org/rfc/rfc8628#section-3.5) |
| [x] | Consent flow for device authorization | [RFC 8628 3.3](https://www.rfc-editor.org/rfc/rfc8628#section-3.3) |

---

## Refresh Token Rotation

| Status | Feature | Reference |
|--------|---------|-----------|
| [x] | Refresh token issuance with authorization code grant | [RFC 6749 6](https://www.rfc-editor.org/rfc/rfc6749#section-6) |
| [x] | Refresh token rotation (new token on each use) | Security best practice |
| [x] | Revocation of parent token on rotation | Security best practice |

---

## Consent Flow

| Status | Feature | Reference |
|--------|---------|-----------|
| [x] | Consent page with scope display | [RFC 6749 4.1.1](https://www.rfc-editor.org/rfc/rfc6749#section-4.1.1) |
| [x] | Persistent consent records (skip prompt for previously consented scopes) | Implementation choice |
| [x] | `prompt=consent` forces consent screen | [OIDC Core 3.1.2.1](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest) |

---

## WebAuthn / FIDO2

**Specification:** [Web Authentication Level 2](https://www.w3.org/TR/webauthn-2/)

| Status | Feature | Reference |
|--------|---------|-----------|
| [x] | Passkey registration ceremony | [WebAuthn 7.1](https://www.w3.org/TR/webauthn-2/#sctn-registering-a-new-credential) |
| [x] | Passkey authentication ceremony | [WebAuthn 7.2](https://www.w3.org/TR/webauthn-2/#sctn-verifying-assertion) |
| [x] | Signature counter verification (clone detection) | [WebAuthn 7.2.20](https://www.w3.org/TR/webauthn-2/#sctn-sign-counter) |
| [x] | Backup state tracking | [WebAuthn 6.3.3](https://www.w3.org/TR/webauthn-2/#sctn-authenticator-data) |
| [x] | Conditional UI / autofill mediation | [WebAuthn Conditional UI](https://github.com/niccolocase/webauthn-conditional-ui) |
| [x] | WASM client for browser-side WebAuthn operations | Implementation detail |

---

## Authentication Assurance

**Specifications:** [RFC 8176 - AMR Values](https://www.rfc-editor.org/rfc/rfc8176), [NIST SP 800-63B](https://pages.nist.gov/800-63-3/sp800-63b.html)

| Status | Feature | Reference |
|--------|---------|-----------|
| [x] | AMR `"pwd"` for password authentication | [RFC 8176](https://www.rfc-editor.org/rfc/rfc8176) |
| [x] | AMR `"hwk"` for hardware-bound passkeys | [RFC 8176](https://www.rfc-editor.org/rfc/rfc8176) |
| [x] | AMR `"swk"` for cloud-synced passkeys | [RFC 8176](https://www.rfc-editor.org/rfc/rfc8176) |
| [x] | ACR `"aal1"` for single-factor authentication | [NIST SP 800-63B](https://pages.nist.gov/800-63-3/sp800-63b.html) |
| [x] | ACR `"aal2"` for two-factor authentication | [NIST SP 800-63B](https://pages.nist.gov/800-63-3/sp800-63b.html) |
| [x] | Admin-enforced 2FA per user | Implementation feature |
| [x] | Context-based 2FA (high-value scopes, `max_age`) | Implementation feature |
| [x] | Session-based AMR/ACR tracking | Implementation feature |

---

## OpenID Federation

**Specification:** [OpenID Federation 1.0](https://openid.net/specs/openid-federation-1_0.html)

| Status | Feature | Reference |
|--------|---------|-----------|
| [ ] | Trust anchor configuration | [Federation 3](https://openid.net/specs/openid-federation-1_0.html) |
| [ ] | Trust chain resolution | [Federation 4](https://openid.net/specs/openid-federation-1_0.html) |
| [ ] | Entity statement publication | [Federation 5](https://openid.net/specs/openid-federation-1_0.html) |
| [x] | Trust anchor URL configuration (data model only) | Configuration support |

---

## Summary

| Category | Implemented | Pending | Total |
|----------|:-----------:|:-------:|:-----:|
| OIDC Core (flows, ID token, endpoints, claims) | 14 | 3 | 17 |
| OIDC Discovery | 11 | 0 | 11 |
| JWKS | 3 | 0 | 3 |
| OAuth 2.0 (grants, client auth, security) | 14 | 4 | 18 |
| PKCE | 4 | 0 | 4 |
| Dynamic Client Registration | 4 | 1 | 5 |
| Token Revocation | 4 | 0 | 4 |
| Token Introspection | 0 | 2 | 2 |
| Device Authorization Grant | 7 | 0 | 7 |
| Refresh Token Rotation | 3 | 0 | 3 |
| Consent Flow | 3 | 0 | 3 |
| WebAuthn / FIDO2 | 6 | 0 | 6 |
| Authentication Assurance | 8 | 0 | 8 |
| OpenID Federation | 1 | 3 | 4 |
| **Total** | **82** | **13** | **95** |
