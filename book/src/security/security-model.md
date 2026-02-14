# Security Model

Barycenter employs a defense-in-depth strategy where multiple independent security mechanisms overlap to protect the system. No single layer is assumed to be sufficient on its own. If one control fails, additional layers continue to provide protection.

## Threat Model Overview

Barycenter is an OpenID Connect Identity Provider that manages user authentication and token issuance. The primary threats it defends against include:

| Threat | Impact | Mitigations |
|--------|--------|-------------|
| Authorization code interception | Attacker exchanges stolen code for tokens | PKCE (S256 required), single-use codes, short TTL (5 min) |
| Session hijacking | Attacker impersonates authenticated user | HttpOnly cookies, SameSite=Lax, Secure flag, random session IDs |
| Cross-site request forgery (CSRF) | Attacker triggers unintended actions | SameSite cookie attribute, OAuth `state` parameter |
| Replay attacks | Attacker reuses captured tokens or codes | Single-use authorization codes, nonce claim in ID tokens, token expiration |
| Clickjacking | Attacker embeds login page in iframe | X-Frame-Options: DENY, Content-Security-Policy frame-ancestors |
| Token theft | Attacker steals access or refresh tokens | Short-lived access tokens (1 hour), refresh token rotation, revocation |
| Credential stuffing | Attacker brute-forces login credentials | Rate limiting (at reverse proxy), argon2 password hashing |
| Man-in-the-middle | Attacker intercepts traffic | TLS required in production, Secure cookie flag |

## Defense-in-Depth Layers

### Layer 1: Transport Security

All production deployments must use TLS. Session cookies are marked `Secure` in production, preventing transmission over unencrypted connections. The `Referrer-Policy` header limits information leakage in HTTP referrer headers.

### Layer 2: Browser Security Controls

A comprehensive set of security headers is applied to every response. These headers instruct browsers to enforce restrictions that prevent common web attacks. See [Security Headers](headers.md) for the complete list.

### Layer 3: Protocol-Level Protections

The OAuth 2.0 and OpenID Connect protocols include built-in security mechanisms that Barycenter enforces strictly:

- **PKCE** is mandatory for all authorization code flows. Only the S256 method is accepted. See [PKCE](pkce.md) for details.
- **State parameter** is passed through the authorization flow and validated by the client to prevent CSRF.
- **Nonce** is included in ID tokens when provided, allowing clients to detect replay attacks.

### Layer 4: Session and Token Management

Sessions and tokens have limited lifetimes and are cleaned up by background jobs. Authorization codes are single-use and expire after 5 minutes. Access tokens expire after 1 hour. Refresh tokens support rotation, where issuing a new refresh token invalidates the previous one.

### Layer 5: Infrastructure Hardening

The application is designed to run with minimal privileges. Systemd hardening directives, container security contexts, and strict file permissions limit the blast radius of any compromise. See [Hardening](hardening.md) for configuration details.

## CSRF Mitigation

Barycenter uses two complementary mechanisms to prevent cross-site request forgery:

### SameSite Cookie Attribute

Session cookies are set with `SameSite=Lax`, which prevents the browser from sending cookies on cross-origin POST requests. This blocks the most common CSRF attack vector where a malicious site submits a form to Barycenter.

The `Lax` setting (rather than `Strict`) is chosen deliberately: it allows the session cookie to be sent on top-level navigations (such as clicking a link), which is required for the OAuth authorization redirect flow to work correctly.

### OAuth State Parameter

The `state` parameter provides CSRF protection at the OAuth protocol level. The flow works as follows:

1. The client generates a random, unguessable `state` value and stores it locally (e.g., in a browser session).
2. The client includes `state` in the authorization request to Barycenter.
3. Barycenter returns the same `state` value in the redirect back to the client.
4. The client verifies that the returned `state` matches the stored value.

An attacker cannot forge a valid `state` value, so any authorization response with a missing or mismatched `state` is rejected by the client.

## Replay Protection

### Single-Use Authorization Codes

Authorization codes are marked as consumed immediately upon use at the token endpoint. Any attempt to reuse a code is rejected. Codes also expire after 5 minutes, limiting the window for an attacker to use an intercepted code.

### Nonce Claim

When a client includes a `nonce` parameter in the authorization request, it is embedded in the resulting ID token. The client verifies that the `nonce` in the token matches the value it originally sent. This prevents an attacker from replaying a previously issued ID token in a different authentication session.

### Token Expiration

All tokens carry expiration timestamps:

- **Authorization codes**: 5 minutes
- **Access tokens**: 1 hour
- **Sessions**: Configurable TTL with periodic cleanup

Background jobs run on a schedule to remove expired records from the database, ensuring that stale tokens cannot accumulate.

## Clickjacking Protection

Barycenter prevents clickjacking through two mechanisms:

1. **X-Frame-Options: DENY** -- instructs browsers to refuse to render any Barycenter page inside an `<iframe>`, `<frame>`, or `<object>` element, regardless of the origin of the framing page.

2. **Content-Security-Policy** -- the `default-src 'self'` directive implicitly sets `frame-ancestors 'self'`, providing equivalent protection in browsers that support CSP but may not honor X-Frame-Options.

These protections ensure that an attacker cannot overlay a transparent Barycenter login page on top of a malicious site to trick users into entering credentials or clicking authorization buttons.
