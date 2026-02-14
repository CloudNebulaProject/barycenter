# Consent Flow

After a user authenticates, Barycenter presents a consent screen asking the user to approve or deny the relying party's request for access. The consent flow ensures that users are informed about what data and permissions they are granting to a third-party application.

## How Consent Works

The consent flow is part of the OAuth 2.0 authorization code flow and occurs after authentication but before the authorization code is issued:

1. The user authenticates (password, passkey, or 2FA).
2. Barycenter checks whether the user has already granted consent for this client and scope combination.
3. If **prior consent exists** and covers the requested scopes, the flow proceeds without prompting.
4. If **no prior consent exists** (or the requested scopes exceed what was previously granted), the user is shown the consent page.
5. The user approves or denies the request.
6. If approved, the consent is recorded and the authorization code is issued.

## Consent Page

### GET /consent

The consent page displays the following information to the user:

- **Client name**: The registered name of the application requesting access.
- **Requested scopes**: A human-readable list of the permissions being requested.

The user is presented with two actions:

- **Approve**: Grant the application access to the requested scopes.
- **Deny**: Reject the request. The user is redirected back to the relying party with an `access_denied` error.

### POST /consent

The consent decision is submitted as a form POST:

```
POST /consent
Cookie: session=<session_id>
Content-Type: application/x-www-form-urlencoded

decision=approve
```

| Parameter  | Values              | Description                        |
|------------|---------------------|------------------------------------|
| `decision` | `approve` or `deny` | The user's consent decision.       |

## Consent Storage

Approved consent decisions are stored in the `consent` table:

| Column       | Type      | Description                                                |
|--------------|-----------|------------------------------------------------------------|
| `client_id`  | String    | The client that received consent.                          |
| `subject`    | String    | The user who granted consent.                              |
| `scope`      | String    | Space-separated list of approved scopes.                   |
| `granted_at` | Timestamp | When the consent was granted.                              |

When a user approves consent, Barycenter records the client, user, and scope combination. On subsequent authorization requests from the same client with the same or a subset of the previously approved scopes, the consent page is skipped.

### Scope Matching

Consent is checked per-scope. If a client requests scopes that are a **subset** of previously granted scopes, consent is not re-prompted. If the client requests **additional scopes** beyond what was previously granted, the consent page is shown again with the full set of requested scopes.

Example:

| Previous Consent         | New Request               | Consent Prompted? |
|--------------------------|---------------------------|-------------------|
| `openid profile`         | `openid profile`          | No                |
| `openid profile email`   | `openid profile`          | No (subset)       |
| `openid profile`         | `openid profile email`    | Yes (new scope)   |
| (none)                   | `openid`                  | Yes (first time)  |

## Forcing Re-Consent

### prompt=consent

A relying party can force the consent screen to be displayed by including `prompt=consent` in the authorization request, even if the user has previously granted consent for the requested scopes:

```
GET /authorize?
  client_id=abc123&
  redirect_uri=https://app.example.com/callback&
  response_type=code&
  scope=openid+profile&
  prompt=consent&
  code_challenge=...&
  code_challenge_method=S256&
  state=xyz
```

This is useful when an application wants to ensure the user is aware of and actively agrees to the permissions being granted -- for example, after a policy change or when requesting consent for a different purpose.

When `prompt=consent` is specified:

- The consent page is always shown, regardless of prior consent records.
- If the user approves, the consent record is updated with the new `granted_at` timestamp.
- If the user denies, the existing consent record is not modified.

## Skipping Consent for Development

For development and testing environments, the consent flow can be bypassed entirely using the `BARYCENTER_SKIP_CONSENT` environment variable:

```bash
export BARYCENTER_SKIP_CONSENT=true
```

When this variable is set to `true`:

- The consent page is never shown.
- All authorization requests are treated as if the user approved.
- No consent records are written to the database.

> **Warning**: Never enable `BARYCENTER_SKIP_CONSENT` in production. Skipping consent violates user expectations and may conflict with regulatory requirements (e.g., GDPR, which requires informed consent for data sharing).

This variable is intended solely for automated testing and local development where the consent prompt would be an obstacle.

## Consent and the Authorization Flow

The consent check is integrated into the authorization endpoint flow:

```
GET /authorize
  |
  +-- Valid session? --> No --> Redirect to /login
  |
  +-- 2FA required and not verified? --> Redirect to /login/2fa
  |
  +-- prompt=consent? --> Yes --> Show consent page
  |
  +-- Prior consent covers requested scopes? --> Yes --> Issue authorization code
  |
  +-- No prior consent --> Show consent page
        |
        +-- User approves --> Record consent, issue authorization code
        |
        +-- User denies --> Redirect to RP with error=access_denied
```

## Deny Response

If the user denies consent, Barycenter redirects back to the relying party's registered `redirect_uri` with an error:

```
HTTP/1.1 302 Found
Location: https://app.example.com/callback?error=access_denied&error_description=The+user+denied+the+request&state=xyz
```

The relying party should handle this error gracefully and inform the user that the requested permissions were not granted.
