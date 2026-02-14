# Session Lifecycle

This page covers the technical details of how sessions are created, stored, transmitted, upgraded, and cleaned up in Barycenter.

## Session Cookie

When a session is created, Barycenter sends a `Set-Cookie` header to the browser with the following attributes:

| Attribute   | Value          | Purpose                                                    |
|-------------|----------------|------------------------------------------------------------|
| `HttpOnly`  | Yes            | Prevents JavaScript access, mitigating XSS-based session theft. |
| `SameSite`  | `Lax`          | Cookie is sent on top-level navigations and same-site requests, but not on cross-site sub-requests. Balances CSRF protection with OAuth redirect compatibility. |
| `Secure`    | Yes (production) | Cookie is only sent over HTTPS connections. Disabled for `localhost` during development. |
| `Path`      | `/`            | Cookie is available for all paths on the domain.           |

### Example Set-Cookie Header

```
Set-Cookie: session=abc123def456...; HttpOnly; SameSite=Lax; Secure; Path=/
```

The cookie value is the `session_id` -- a 24-byte random value encoded as base64url, providing 192 bits of entropy.

### SameSite=Lax and OAuth Redirects

The `Lax` setting is chosen specifically for compatibility with the OAuth authorization code flow. During the flow, the user is redirected from the relying party to Barycenter and back. `SameSite=Lax` allows the session cookie to be included on these top-level redirects while still blocking cross-site requests initiated by embedded resources (images, iframes, AJAX calls), which provides meaningful CSRF protection.

## Session TTL

Sessions have a finite lifetime defined by the `expires_at` timestamp stored in the database. The TTL is configured in the application settings.

Once a session expires, it is no longer considered valid:

- Requests with an expired session cookie are treated as unauthenticated.
- The user must log in again.
- Expired session records remain in the database until the cleanup job removes them.

## Session States

A session transitions through the following states during its lifecycle:

```
    Created                  Upgraded (optional)        Expired
       |                          |                        |
  [mfa_verified=0]     [mfa_verified=1]         [expires_at < now]
  [amr=["pwd"]]        [amr=["pwd","hwk"]]
  [acr="aal1"]         [acr="aal2"]
```

### State: Created

A session enters the "Created" state after successful single-factor authentication (password or passkey). At this point:

- `mfa_verified = 0`
- `amr` contains a single method (e.g., `["pwd"]`)
- `acr = "aal1"`

If no 2FA is required, the session remains in this state for its entire lifetime and is fully usable for authorization.

### State: Upgraded

If two-factor authentication is completed, the session transitions to the "Upgraded" state:

- `mfa_verified = 1`
- `amr` contains both methods (e.g., `["pwd", "hwk"]`)
- `acr = "aal2"`
- `auth_time` remains unchanged (still reflects the initial authentication)
- `expires_at` remains unchanged (the upgrade does not extend the session)

The upgrade is performed as an in-place update to the existing session row. No new session is created.

### State: Expired

A session is considered expired when `expires_at < current_time`. Expired sessions are:

- Rejected by Barycenter on any request that checks for a valid session.
- Cleaned up by the `cleanup_expired_sessions` background job.

## MFA Upgrade During 2FA

When a user completes the [2FA flow](./2fa-flow.md), the session is upgraded in a single database update:

```sql
UPDATE sessions
SET mfa_verified = 1,
    acr = 'aal2',
    amr = '["pwd", "hwk"]'
WHERE session_id = ?
```

This atomic update ensures that the session is either fully upgraded or not changed at all. There is no intermediate state where `mfa_verified = 1` but `acr` still reads `"aal1"`.

## Session Cleanup

Expired sessions accumulate in the database until they are removed by the `cleanup_expired_sessions` background job.

| Job Name                       | Schedule     | Action                                    |
|--------------------------------|--------------|-------------------------------------------|
| `cleanup_expired_sessions`     | Hourly (:00) | Deletes all sessions where `expires_at < now` |

The cleanup job runs as part of Barycenter's background job scheduler. It can also be triggered manually via the [Admin GraphQL API](../admin/graphql-api.md):

```graphql
mutation {
  triggerJob(jobName: "cleanup_expired_sessions") {
    success
    message
  }
}
```

## Logout

Users can explicitly terminate their session by sending a POST request to the logout endpoint:

```
POST /logout
Cookie: session=<session_id>
```

On logout, Barycenter:

1. Deletes the session record from the database.
2. Clears the session cookie by setting it with an expired `Max-Age`.
3. Redirects the user to the login page (or a configured post-logout URL).

## Session Validation Flow

On each request that requires authentication, Barycenter validates the session:

```
1. Extract session_id from cookie
      |
      +-- No cookie? --> 401 Unauthenticated
      |
2. Look up session in database
      |
      +-- Not found? --> 401 Unauthenticated (cookie is stale)
      |
3. Check expires_at > current_time
      |
      +-- Expired? --> 401 Unauthenticated
      |
4. Session is valid. Read subject, amr, acr, mfa_verified.
```

This validation is performed for every authenticated endpoint, including the authorization endpoint, passkey registration, passkey management, and the 2FA verification endpoints (which require a partial session).

## Security Considerations

- **Session ID entropy**: 192 bits of cryptographic randomness makes brute-force guessing infeasible.
- **Server-side storage**: All session data is stored in the database, not in the cookie. The cookie contains only the opaque identifier.
- **HttpOnly**: JavaScript cannot read the session cookie, protecting against XSS.
- **SameSite=Lax**: Provides CSRF protection while remaining compatible with OAuth redirects.
- **Secure flag**: In production, the cookie is only transmitted over HTTPS.
- **No session fixation**: A new session ID is generated on every successful login. Pre-existing session IDs are never reused.
