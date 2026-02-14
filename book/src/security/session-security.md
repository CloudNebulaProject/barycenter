# Session Security

Barycenter uses server-side sessions backed by the database to track authenticated users. Session management is a critical security surface because a compromised session grants an attacker the same access as the legitimate user.

## Cookie Attributes

Session cookies are configured with the following attributes:

| Attribute | Value | Purpose |
|-----------|-------|---------|
| `HttpOnly` | `true` | Prevents JavaScript from accessing the cookie, mitigating XSS-based session theft |
| `SameSite` | `Lax` | Prevents the cookie from being sent on cross-origin POST requests, mitigating CSRF |
| `Secure` | `true` (production) | Ensures the cookie is only sent over HTTPS connections |
| `Path` | `/` | Cookie is available for all paths on the domain |

### Why SameSite=Lax?

The `Lax` setting provides CSRF protection while allowing the OAuth redirect flow to work correctly. With `Lax`:

- The cookie **is sent** on top-level navigations (clicking a link, browser redirects) -- this is required for the authorization endpoint redirect flow.
- The cookie **is not sent** on cross-origin POST requests, subresource requests, or iframe navigations -- this blocks CSRF attacks.

The `Strict` setting would break the OAuth flow because the authorization redirect from the client application back to Barycenter is a cross-origin top-level navigation, and `Strict` would not send the session cookie on that redirect.

### Secure Flag in Development

In development mode (when the server is not behind TLS), the `Secure` flag is not set so that cookies work over plain HTTP on `localhost`. In production, the `Secure` flag is always enabled to prevent session cookies from being transmitted over unencrypted connections.

## Random Session IDs

Session identifiers are generated using 24 cryptographically random bytes, encoded as base64url. This produces a 32-character string with 192 bits of entropy.

```
Session ID = base64url(random(24 bytes))
```

With 192 bits of entropy, an attacker attempting to guess a valid session ID by brute force would need to try an average of 2^191 values -- a computationally infeasible task.

The session ID is the sole identifier stored in the cookie. All session data (subject, authentication methods, MFA status, timestamps) is stored server-side in the database, never in the cookie itself.

## Session Lifecycle

### Creation

A session is created when a user successfully authenticates. The session record includes:

- **Session ID**: Random 192-bit identifier
- **Subject**: The authenticated user's identifier
- **AMR**: Authentication Method References (e.g., `["pwd"]`, `["hwk"]`, `["pwd", "hwk"]`)
- **ACR**: Authentication Context Reference (`"aal1"` for single-factor, `"aal2"` for two-factor)
- **MFA Verified**: Boolean indicating whether multi-factor authentication was completed
- **Auth Time**: Timestamp of the authentication event
- **Created At**: Session creation timestamp
- **Expires At**: Session expiration timestamp

### Partial Sessions (MFA)

When a user logs in with a password and two-factor authentication is required, a partial session is created:

1. The session is created with `mfa_verified = false` and `acr = "aal1"`.
2. The user is redirected to `/login/2fa` to complete the second factor.
3. After successful passkey verification, the session is upgraded: `mfa_verified = true`, `acr = "aal2"`, and the AMR array is extended (e.g., from `["pwd"]` to `["pwd", "hwk"]`).

A partial session does not grant access to protected resources. The authorization endpoint checks `mfa_verified` and redirects to 2FA if the session is partial and 2FA is required.

## Session TTL and Expiration

Sessions have a configurable time-to-live (TTL). Every request that uses a session checks whether the session has expired by comparing the current time against the `expires_at` timestamp.

Expired sessions are treated as invalid -- the user must re-authenticate. The session record remains in the database until it is cleaned up by the background job.

## Session Cleanup

A background job runs hourly to remove expired sessions from the database:

- **Job name**: `cleanup_expired_sessions`
- **Schedule**: Every hour at :00
- **Action**: Deletes all session records where `expires_at < now()`

This prevents the accumulation of stale session records that could degrade database performance. The job can also be triggered manually through the admin GraphQL API:

```graphql
mutation {
  triggerJob(jobName: "cleanup_expired_sessions") {
    success
    message
  }
}
```

## CSRF Protection

Barycenter uses two complementary mechanisms for CSRF protection:

### SameSite Cookie

The `SameSite=Lax` attribute on session cookies prevents the browser from sending the session cookie on cross-origin POST requests. This blocks the classic CSRF attack where a malicious page submits a form to Barycenter.

### OAuth State Parameter

For the authorization flow, the `state` parameter provides an additional CSRF check. The client generates a random `state` value, includes it in the authorization request, and verifies that the same value is returned in the redirect. This ensures that the authorization response was initiated by the client and not forged by an attacker.

Together, these mechanisms provide overlapping protection: even if one layer were bypassed (for example, on a browser that does not support SameSite cookies), the other would still prevent the attack.

## Security Considerations

### Session Fixation

Barycenter generates a new session ID on every successful authentication. There is no mechanism for an attacker to set or influence the session ID before the user authenticates, preventing session fixation attacks.

### Concurrent Sessions

Multiple concurrent sessions are allowed for the same user. Each session is independent and tracked separately in the database. Revoking one session does not affect others.

### Session Storage

All session data is stored server-side in the database. The cookie contains only the session ID. This means that session data cannot be tampered with by the client, and sensitive information (such as the user's subject identifier and authentication context) is never exposed to the browser.
