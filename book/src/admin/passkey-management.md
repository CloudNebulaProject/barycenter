# Passkey Management

Authenticated users can manage their registered passkeys through the account API. These endpoints allow listing, renaming, and deleting passkeys. All operations require an active user session -- they are user-facing endpoints, not part of the admin GraphQL API.

## Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/account/passkeys` | List all passkeys for the current user |
| `DELETE` | `/account/passkeys/:credential_id` | Delete a specific passkey |
| `PATCH` | `/account/passkeys/:credential_id` | Update a passkey's friendly name |

All endpoints require an active session. Unauthenticated requests receive a `401 Unauthorized` response.

## List Passkeys

```
GET /account/passkeys
```

Returns all passkeys registered for the currently authenticated user.

### Response

```http
HTTP/1.1 200 OK
Content-Type: application/json
```

```json
[
  {
    "credential_id": "dGhpcyBpcyBhIGNyZWRlbnRpYWwgaWQ",
    "name": "YubiKey 5C",
    "backup_eligible": false,
    "backup_state": false,
    "created_at": "2026-01-15T10:30:00Z",
    "last_used_at": "2026-02-14T08:15:00Z"
  },
  {
    "credential_id": "YW5vdGhlciBjcmVkZW50aWFsIGlk",
    "name": "iCloud Keychain",
    "backup_eligible": true,
    "backup_state": true,
    "created_at": "2026-01-20T14:00:00Z",
    "last_used_at": "2026-02-13T19:45:00Z"
  }
]
```

### Response Fields

| Field | Type | Description |
|---|---|---|
| `credential_id` | `string` | Base64url-encoded WebAuthn credential identifier. Used in DELETE and PATCH paths. |
| `name` | `string` | User-assigned friendly name for the passkey. |
| `backup_eligible` | `boolean` | Whether the passkey can be synced across devices. `false` for hardware-bound keys. |
| `backup_state` | `boolean` | Whether the passkey is currently backed up to a cloud provider. |
| `created_at` | `string` | ISO 8601 timestamp of when the passkey was registered. |
| `last_used_at` | `string` | ISO 8601 timestamp of the most recent authentication with this passkey. |

### curl Example

```bash
# List passkeys (requires a session cookie)
curl -s -b cookies.txt http://localhost:8080/account/passkeys | jq .
```

## Delete a Passkey

```
DELETE /account/passkeys/:credential_id
```

Permanently removes a passkey. The credential ID must be URL-encoded if it contains special characters.

### Response

```http
HTTP/1.1 204 No Content
```

### Error Responses

| Status | Condition |
|---|---|
| `401 Unauthorized` | No active session. |
| `404 Not Found` | Credential ID does not exist or does not belong to the current user. |

### curl Example

```bash
# Delete a passkey
curl -s -X DELETE -b cookies.txt \
  http://localhost:8080/account/passkeys/dGhpcyBpcyBhIGNyZWRlbnRpYWwgaWQ
```

> **Warning**: Deleting a user's last passkey removes their ability to use passkey authentication. If the user has admin-enforced 2FA enabled, they will need to re-enroll a passkey on their next login.

## Update a Passkey Name

```
PATCH /account/passkeys/:credential_id
Content-Type: application/json
```

Updates the friendly name associated with a passkey. This helps users distinguish between multiple registered passkeys (e.g., "Work YubiKey" vs "Phone").

### Request Body

```json
{
  "name": "Work YubiKey 5C NFC"
}
```

### Response

```http
HTTP/1.1 200 OK
Content-Type: application/json
```

```json
{
  "credential_id": "dGhpcyBpcyBhIGNyZWRlbnRpYWwgaWQ",
  "name": "Work YubiKey 5C NFC"
}
```

### Error Responses

| Status | Condition |
|---|---|
| `400 Bad Request` | Missing or empty `name` field. |
| `401 Unauthorized` | No active session. |
| `404 Not Found` | Credential ID does not exist or does not belong to the current user. |

### curl Example

```bash
# Rename a passkey
curl -s -X PATCH -b cookies.txt \
  http://localhost:8080/account/passkeys/dGhpcyBpcyBhIGNyZWRlbnRpYWwgaWQ \
  -H "Content-Type: application/json" \
  -d '{"name": "Work YubiKey 5C NFC"}' | jq .
```

## Admin Perspective

While passkey management endpoints are user-facing, administrators can view and manage passkeys through the admin GraphQL API:

- **View passkeys**: Query the Seaography entity schema to list all passkeys across all users.
- **Check enrollment status**: Use the `user2faStatus` query to check whether a specific user has passkeys enrolled. See [User 2FA Management](./user-2fa.md).
- **Enforce 2FA**: Use the `setUser2faRequired` mutation to require passkey-based 2FA for specific users.

### Admin Query Example

```graphql
# At POST /admin/graphql (Entity CRUD)
{
  user {
    findOne(filter: { username: { eq: "alice" } }) {
      username
      passkeyEnrolledAt
    }
  }
}
```

```graphql
# At POST /admin/jobs (Job Management)
{
  user2faStatus(username: "alice") {
    passkeyEnrolled
    passkeyCount
    passkeyEnrolledAt
  }
}
```

## Further Reading

- [Passkey / WebAuthn](../authentication/passkeys.md) -- overview of passkey authentication
- [Registering a Passkey](../authentication/passkey-registration.md) -- the registration ceremony
- [User 2FA Management](./user-2fa.md) -- admin-side 2FA enforcement
