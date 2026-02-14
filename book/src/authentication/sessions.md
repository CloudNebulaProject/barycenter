# Sessions

Barycenter uses server-side sessions to track authenticated users across requests. Sessions are created during login and persist until they expire or are explicitly terminated.

## What Is a Session?

A session represents an authenticated user's state on the server. When a user logs in (via password, passkey, or both), Barycenter creates a session record in the database and returns a session identifier to the browser as a cookie. Subsequent requests include this cookie, allowing Barycenter to identify the user without requiring re-authentication on every request.

## Session Data

Each session record in the database contains:

| Column         | Type      | Description                                                           |
|----------------|-----------|-----------------------------------------------------------------------|
| `session_id`   | String    | Random 24-byte base64url-encoded identifier. Used as the cookie value.|
| `subject`      | String    | The authenticated user's subject identifier (stable, unique ID).      |
| `auth_time`    | Timestamp | When the session was created (initial authentication time).           |
| `expires_at`   | Timestamp | When the session will expire and be cleaned up.                       |
| `amr`          | JSON      | Authentication Methods Reference -- array of method identifiers.      |
| `acr`          | String    | Authentication Context Class Reference -- assurance level.            |
| `mfa_verified` | Integer   | Whether multi-factor authentication has been completed (`0` or `1`).  |

## Session Identifiers

Session IDs are generated using `random_id()`, which produces 24 cryptographically random bytes encoded as a base64url string. This provides 192 bits of entropy, making session ID guessing infeasible.

The session ID is the only value sent to the browser. All other session data remains on the server and is looked up by the session ID on each request.

## Authentication Tracking

Sessions track how the user authenticated, which is propagated to ID tokens issued during the session:

### AMR (Authentication Methods Reference)

The `amr` field is a JSON array recording which authentication methods were used:

| Value  | Method                                 |
|--------|----------------------------------------|
| `pwd`  | Password authentication                |
| `hwk`  | Hardware-bound passkey (YubiKey, etc.) |
| `swk`  | Software/cloud passkey (iCloud, etc.)  |

After a password-only login: `["pwd"]`
After a passkey-only login: `["hwk"]` or `["swk"]`
After password + passkey 2FA: `["pwd", "hwk"]` or `["pwd", "swk"]`

### ACR (Authentication Context Class Reference)

The `acr` field records the authentication assurance level:

| Value  | Meaning                                     |
|--------|---------------------------------------------|
| `aal1` | Single-factor authentication                |
| `aal2` | Two-factor authentication (MFA verified)    |

See [AMR and ACR Claims](./amr-acr.md) for a detailed explanation of how these values are determined and used.

## Session Lifecycle

Sessions follow a defined lifecycle from creation through potential upgrade to eventual expiration:

1. **Creation**: A session is created on successful login with initial `amr`, `acr`, and `mfa_verified` values.
2. **Upgrade** (optional): If 2FA is completed, `amr` gains a second method, `acr` becomes `"aal2"`, and `mfa_verified` becomes `1`.
3. **Use**: The session is validated on each request by checking the cookie against the database.
4. **Expiration**: Sessions expire based on `expires_at`. Expired sessions are cleaned up by a background job.
5. **Logout**: Users can explicitly end their session via `POST /logout`.

See [Session Lifecycle](./session-lifecycle.md) for details on cookie settings, TTL, and cleanup.

## Session and the OAuth Flow

During an OAuth authorization request, the session serves several purposes:

- **Authentication check**: If a valid session exists, the user does not need to re-authenticate (unless `prompt=login` or `max_age` requires it).
- **2FA state**: The `mfa_verified` flag determines whether the user needs to complete a second factor.
- **ID token claims**: `auth_time`, `amr`, and `acr` from the session are included in the issued ID token.

## Further Reading

- [AMR and ACR Claims](./amr-acr.md) -- detailed explanation of authentication method tracking
- [Session Lifecycle](./session-lifecycle.md) -- cookie settings, TTL, and cleanup jobs
- [Two-Factor Authentication](./two-factor.md) -- how sessions are upgraded during 2FA
- [Password Authentication](./password.md) -- how sessions are created during login
