# Password Authentication

Barycenter supports traditional username-and-password authentication as its foundational login method. Password authentication can be used standalone or as the first factor in a [two-factor authentication](./two-factor.md) flow.

## Login Page

The login page is served at `GET /login` and presents the user with two options:

1. **Passkey autofill** -- if the browser supports [Conditional UI](./conditional-ui.md), passkey credentials are offered in the username field's autofill dropdown.
2. **Password fallback** -- a standard username and password form that submits via `POST /login`.

When an OAuth authorization request requires authentication, Barycenter redirects the user to `/login` with the original authorization parameters preserved in the session. After successful authentication, the user is redirected back to the `/authorize` endpoint to continue the OAuth flow.

## Password Submission

Credentials are submitted as a standard HTML form POST:

```
POST /login
Content-Type: application/x-www-form-urlencoded

username=alice&password=correct-horse-battery-staple
```

### Request Parameters

| Parameter  | Required | Description                     |
|------------|----------|---------------------------------|
| `username` | Yes      | The user's login name.          |
| `password` | Yes      | The user's plaintext password.  |

### Success Response

On successful authentication, the server:

1. Verifies the password against the stored Argon2 hash.
2. Creates a new [session](./sessions.md) in the database.
3. Sets an `HttpOnly` session cookie on the response.
4. Redirects the user to the original authorization endpoint (or a default landing page if no authorization request is pending).

The newly created session records:

- `amr` (Authentication Methods Reference): `["pwd"]`
- `acr` (Authentication Context Class Reference): `"aal1"`
- `mfa_verified`: `0` (single-factor only at this stage)

### Failure Response

If the username does not exist or the password is incorrect, the server returns the login page with an error message. Barycenter does not distinguish between "unknown user" and "wrong password" in the error response to prevent username enumeration.

## Password Hashing

All passwords are hashed using [Argon2](https://en.wikipedia.org/wiki/Argon2), the winner of the 2015 Password Hashing Competition. Argon2 is a memory-hard function designed to resist brute-force attacks on GPUs and ASICs.

- **Algorithm**: Argon2id (hybrid variant combining Argon2i and Argon2d)
- **Verification**: performed using constant-time comparison to prevent timing attacks
- **Storage**: the full Argon2 encoded string (algorithm, parameters, salt, and hash) is stored in the `users` table

Barycenter never stores or logs plaintext passwords. The password is consumed during verification and immediately dropped from memory.

## Default Admin User

For development and initial setup, Barycenter ships with a default administrator account:

| Field    | Value         |
|----------|---------------|
| Username | `admin`       |
| Password | `password123` |

> **Warning**: Change or remove the default admin credentials before deploying to any non-development environment. See the [Production Checklist](../deployment/production-checklist.md) for hardening guidance.

## Session Creation

After successful password authentication, a new session row is inserted into the `sessions` table:

| Column         | Value                                          |
|----------------|------------------------------------------------|
| `session_id`   | Random 24-byte base64url-encoded identifier    |
| `subject`      | The authenticated user's subject identifier    |
| `auth_time`    | Current UTC timestamp                          |
| `expires_at`   | `auth_time` + session TTL                      |
| `amr`          | `["pwd"]`                                      |
| `acr`          | `"aal1"`                                       |
| `mfa_verified` | `0`                                            |

The session ID is returned to the browser as a cookie. See [Session Lifecycle](./session-lifecycle.md) for details on cookie attributes and expiration behavior.

## Integration with Two-Factor Authentication

If the authenticated user has [two-factor authentication](./two-factor.md) enabled -- either through admin enforcement or because the authorization request triggers context-based 2FA -- the password login creates a **partial session** with `mfa_verified = 0`. The user is then redirected to `/login/2fa` to complete the second factor before the authorization flow can continue.

See [2FA Flow Walkthrough](./2fa-flow.md) for the complete sequence.
