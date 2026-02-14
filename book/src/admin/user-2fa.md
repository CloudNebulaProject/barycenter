# User 2FA Management

The admin job management schema at `POST /admin/jobs` includes mutations and queries for managing two-factor authentication requirements on a per-user basis. Administrators can enforce 2FA for specific users and check their enrollment status.

## Setting 2FA Requirements

The `setUser2faRequired` mutation enables or disables the 2FA requirement for a specific user. When enabled, the user must complete a second authentication factor (passkey verification) after their initial password login before any authorization flow can proceed.

### Enable 2FA for a User

```graphql
mutation {
  setUser2faRequired(username: "alice", required: true) {
    success
    message
    username
    requires2fa
  }
}
```

### Response

```json
{
  "data": {
    "setUser2faRequired": {
      "success": true,
      "message": "2FA requirement updated for user alice",
      "username": "alice",
      "requires2fa": true
    }
  }
}
```

### Disable 2FA for a User

```graphql
mutation {
  setUser2faRequired(username: "alice", required: false) {
    success
    message
    username
    requires2fa
  }
}
```

### Error Handling

If the user does not exist, the mutation reports a failure:

```json
{
  "data": {
    "setUser2faRequired": {
      "success": false,
      "message": "User not found: nonexistent_user",
      "username": "nonexistent_user",
      "requires2fa": false
    }
  }
}
```

### curl Example

```bash
# Enable 2FA for user "alice"
curl -s -X POST http://localhost:8081/admin/jobs \
  -H "Content-Type: application/json" \
  -d '{
    "query": "mutation { setUser2faRequired(username: \"alice\", required: true) { success message username requires2fa } }"
  }' | jq .

# Disable 2FA for user "alice"
curl -s -X POST http://localhost:8081/admin/jobs \
  -H "Content-Type: application/json" \
  -d '{
    "query": "mutation { setUser2faRequired(username: \"alice\", required: false) { success message username requires2fa } }"
  }' | jq .
```

## Querying 2FA Status

The `user2faStatus` query returns the current 2FA configuration and passkey enrollment details for a user.

### Query

```graphql
{
  user2faStatus(username: "alice") {
    username
    subject
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
      "subject": "550e8400-e29b-41d4-a716-446655440000",
      "requires2fa": true,
      "passkeyEnrolled": true,
      "passkeyCount": 2,
      "passkeyEnrolledAt": "2026-01-15T10:30:00Z"
    }
  }
}
```

### Response Fields

| Field | Type | Description |
|---|---|---|
| `username` | `String` | The queried username. |
| `subject` | `String` | The user's unique subject identifier (UUID). |
| `requires2fa` | `Boolean` | Whether 2FA is currently required for this user. |
| `passkeyEnrolled` | `Boolean` | Whether the user has at least one passkey registered. |
| `passkeyCount` | `Int` | Total number of passkeys registered for the user. |
| `passkeyEnrolledAt` | `String` | ISO 8601 timestamp of the user's first passkey registration. `null` if no passkeys are enrolled. |

### curl Example

```bash
curl -s -X POST http://localhost:8081/admin/jobs \
  -H "Content-Type: application/json" \
  -d '{
    "query": "{ user2faStatus(username: \"alice\") { username subject requires2fa passkeyEnrolled passkeyCount passkeyEnrolledAt } }"
  }' | jq .
```

## Operational Considerations

### Enabling 2FA Before Passkey Enrollment

If you enable 2FA for a user who has no passkeys enrolled, they will be prompted to register a passkey during their next login. The login flow redirects to the 2FA page, which requires a passkey verification step. Users without a passkey will need to register one first.

Check enrollment status before enabling:

```graphql
{
  user2faStatus(username: "alice") {
    requires2fa
    passkeyEnrolled
    passkeyCount
  }
}
```

### Bulk 2FA Enforcement

To enable 2FA for multiple users, issue multiple mutations. GraphQL allows batching in a single request using aliases:

```graphql
mutation {
  alice: setUser2faRequired(username: "alice", required: true) {
    success
    username
  }
  bob: setUser2faRequired(username: "bob", required: true) {
    success
    username
  }
  carol: setUser2faRequired(username: "carol", required: true) {
    success
    username
  }
}
```

### Interaction with Context-Based 2FA

Admin-enforced 2FA and context-based 2FA are independent mechanisms. Even if a user does not have admin-enforced 2FA, they may still be required to complete 2FA when:

- The authorization request includes high-value scopes (`admin`, `payment`, `transfer`, `delete`).
- The `max_age` parameter is below 300 seconds.

See [Context-Based 2FA](../authentication/2fa-context-based.md) for details on these triggers.

## Further Reading

- [Admin-Enforced 2FA](../authentication/2fa-admin-enforced.md) -- how enforced 2FA works during the login flow
- [Context-Based 2FA](../authentication/2fa-context-based.md) -- 2FA triggered by scopes and max_age
- [Passkey Management](./passkey-management.md) -- user-facing passkey operations
- [Job Management](./job-management.md) -- the other operations available at `/admin/jobs`
