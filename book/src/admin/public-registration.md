# Public Registration

Barycenter supports an optional public registration endpoint that allows users to create their own accounts without administrator intervention. This feature is disabled by default and must be explicitly enabled in the configuration.

## Configuration

Public registration is controlled by the `allow_public_registration` setting:

### Configuration File

```toml
[server]
allow_public_registration = true
```

### Environment Variable

```bash
export BARYCENTER__SERVER__ALLOW_PUBLIC_REGISTRATION=true
```

When set to `false` (the default), the `/register` endpoint returns a `403 Forbidden` response.

## Registration Endpoint

```
POST /register
Content-Type: application/json
```

### Request Body

```json
{
  "username": "newuser",
  "email": "newuser@example.com",
  "password": "secure_password"
}
```

### Fields

| Field | Type | Required | Description |
|---|---|---|---|
| `username` | `string` | Yes | Desired username. Must be unique across all accounts. |
| `email` | `string` | Yes | User's email address. |
| `password` | `string` | Yes | Plaintext password. Hashed with argon2id before storage. |

### Successful Response

```http
HTTP/1.1 201 Created
Content-Type: application/json
```

```json
{
  "username": "newuser",
  "email": "newuser@example.com",
  "subject": "550e8400-e29b-41d4-a716-446655440000"
}
```

### Error Responses

| Status | Condition |
|---|---|
| `400 Bad Request` | Missing required fields or invalid input. |
| `403 Forbidden` | Public registration is disabled. |
| `409 Conflict` | A user with the given username already exists. |

### curl Example

```bash
# Register a new user
curl -s -X POST http://localhost:8080/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "newuser",
    "email": "newuser@example.com",
    "password": "secure_password"
  }' | jq .
```

## When to Enable Public Registration

Public registration is appropriate when:

- **Self-service onboarding**: You want users to create accounts on their own, such as in a SaaS application or community service.
- **Development and testing**: Convenient for local development when you need to create test accounts quickly without using the admin API.

Public registration should remain **disabled** when:

- **Controlled environments**: Only known users should have accounts (use [user sync](./user-sync.md) instead).
- **Enterprise deployments**: User provisioning is handled by an external identity management system or HR workflow.
- **Security-sensitive deployments**: Open registration increases the attack surface by allowing anyone to create an account.

## Security Considerations

When public registration is enabled:

- **Rate limiting**: Consider configuring rate limiting on the `/register` endpoint to prevent abuse. See [Rate Limiting](../security/rate-limiting.md).
- **Password policy**: Barycenter hashes passwords with argon2id regardless of strength. Consider implementing client-side password strength requirements in your application.
- **Email verification**: Barycenter does not currently perform email verification on registration. The provided email is stored as-is.
- **Account enumeration**: The `409 Conflict` response reveals whether a username is taken. If this is a concern for your threat model, consider implementing a unified error response.

## Comparison with Other Methods

| | Public Registration | User Sync | GraphQL API |
|---|---|---|---|
| Self-service | Yes | No | No |
| Bulk provisioning | No | Yes | Possible but manual |
| Password handling | Auto-hashed | Auto-hashed | Pre-hashed required |
| Access required | None (public) | CLI access | Admin API access |
| Idempotent | No (409 on duplicate) | Yes | No (error on duplicate) |

## Further Reading

- [Creating Users](./creating-users.md) -- all user creation methods
- [User Sync from JSON](./user-sync.md) -- declarative user provisioning
- [Rate Limiting](../security/rate-limiting.md) -- protecting public endpoints
