# Admin-Enforced 2FA

Admin-enforced two-factor authentication allows an administrator to mandate that a specific user must always complete a second authentication factor (passkey verification) after entering their password. This is the strongest 2FA enforcement mode -- the user cannot bypass it regardless of what they are accessing.

## How It Works

1. An administrator sets the `requires_2fa` flag for a user via the [Admin GraphQL API](../admin/graphql-api.md).
2. The flag is stored in the `users` table as `requires_2fa = 1`.
3. On the user's next login, after successful password authentication, Barycenter checks the flag.
4. If `requires_2fa = 1`, a **partial session** is created with `mfa_verified = 0` and the user is redirected to `/login/2fa`.
5. The user completes passkey verification.
6. The session is upgraded to `mfa_verified = 1` with `acr = "aal2"`.

## Enabling 2FA for a User

Use the `setUser2faRequired` GraphQL mutation on the admin API (default port 9091):

```graphql
mutation {
  setUser2faRequired(username: "alice", required: true) {
    success
    message
    requires2fa
  }
}
```

Example using `curl`:

```bash
curl -X POST http://localhost:9091/graphql \
  -H "Content-Type: application/json" \
  -d '{
    "query": "mutation { setUser2faRequired(username: \"alice\", required: true) { success message requires2fa } }"
  }'
```

### Response

```json
{
  "data": {
    "setUser2faRequired": {
      "success": true,
      "message": "2FA requirement updated for user alice",
      "requires2fa": true
    }
  }
}
```

## Disabling 2FA for a User

Pass `required: false` to remove the enforcement:

```graphql
mutation {
  setUser2faRequired(username: "alice", required: false) {
    success
    message
    requires2fa
  }
}
```

This removes the mandatory 2FA requirement. The user will still be prompted for 2FA if a [context-based trigger](./2fa-context-based.md) applies to a specific authorization request.

## Checking a User's 2FA Status

Use the `user2faStatus` query to inspect whether a user has 2FA enabled and whether they have passkeys enrolled:

```graphql
query {
  user2faStatus(username: "alice") {
    username
    requires2fa
    passkeyEnrolled
    passkeyCount
    passkeyEnrolledAt
  }
}
```

### Response

```json
{
  "data": {
    "user2faStatus": {
      "username": "alice",
      "requires2fa": true,
      "passkeyEnrolled": true,
      "passkeyCount": 2,
      "passkeyEnrolledAt": "2026-01-15T10:30:00Z"
    }
  }
}
```

## Database Column

The enforcement flag is stored in the `users` table:

| Column         | Type    | Description                                 |
|----------------|---------|---------------------------------------------|
| `requires_2fa` | Integer | `0` = not required (default), `1` = required|

## The Redirect to /login/2fa

When Barycenter detects that 2FA is required for a user who has just authenticated with a password, it:

1. Creates a partial session with `mfa_verified = 0`, `amr = ["pwd"]`, `acr = "aal1"`.
2. Preserves the pending authorization request parameters in the session.
3. Returns an HTTP redirect to `/login/2fa`.

The `/login/2fa` page presents the user with a passkey verification prompt. Upon successful verification, the session is upgraded and the user is redirected back to `/authorize` to continue the OAuth flow.

See [2FA Flow Walkthrough](./2fa-flow.md) for the complete sequence.

## Considerations

- **Passkey enrollment**: A user must have at least one registered passkey before admin-enforced 2FA can be completed. If the user has no passkeys, they will be unable to satisfy the 2FA requirement and will be stuck at the `/login/2fa` page. Use the `user2faStatus` query to verify enrollment before enabling the flag.
- **Existing sessions**: Enabling `requires_2fa` does not invalidate existing sessions. The flag is checked at the next login. To force re-authentication, expire the user's current sessions.
- **Admin access**: The GraphQL admin API should be protected and not exposed publicly. See [Admin GraphQL API](../admin/graphql-api.md) for access control guidance.
