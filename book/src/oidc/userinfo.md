# UserInfo Endpoint

The UserInfo endpoint returns claims about the authenticated user. It is an OAuth 2.0 protected resource that requires a valid access token obtained through the [token endpoint](./token-endpoint.md).

## Endpoint

```
GET /userinfo
Authorization: Bearer <access_token>
```

## Authentication

The access token must be provided as a Bearer token in the `Authorization` header per [RFC 6750](https://datatracker.ietf.org/doc/html/rfc6750):

```
Authorization: Bearer VGhpcyBpcyBhbiBleGFtcGxlIGFjY2VzcyB0b2tlbg
```

The token must be:

- **Valid** -- recognized by Barycenter as a previously issued token.
- **Not expired** -- within its 1-hour TTL.
- **Not revoked** -- not flagged as revoked in the database.

## Example Request

```bash
curl -X GET https://idp.example.com/userinfo \
  -H "Authorization: Bearer VGhpcyBpcyBhbiBleGFtcGxlIGFjY2VzcyB0b2tlbg"
```

## Response

The response is a JSON object containing claims about the user. The claims returned depend on the scopes that were authorized during the original authorization request.

```json
{
  "sub": "550e8400-e29b-41d4-a716-446655440000",
  "name": "Alice Johnson",
  "given_name": "Alice",
  "family_name": "Johnson",
  "email": "alice@example.com",
  "email_verified": true
}
```

## Scope-Based Claims

The set of claims returned is determined by the scopes granted to the access token:

### `openid` (required)

The `openid` scope is mandatory for all OIDC requests. It grants access to the subject identifier.

| Claim | Type | Description |
|---|---|---|
| `sub` | string | Subject identifier. A unique, stable identifier for the user. Always present. |

### `profile`

The `profile` scope grants access to basic profile information.

| Claim | Type | Description |
|---|---|---|
| `name` | string | Full name of the user. |
| `given_name` | string | First name / given name. |
| `family_name` | string | Last name / surname / family name. |

### `email`

The `email` scope grants access to the user's email address and verification status.

| Claim | Type | Description |
|---|---|---|
| `email` | string | The user's email address. |
| `email_verified` | boolean | Whether the email address has been verified. |

### Summary Table

| Scope | Claims Returned |
|---|---|
| `openid` | `sub` |
| `openid profile` | `sub`, `name`, `given_name`, `family_name` |
| `openid email` | `sub`, `email`, `email_verified` |
| `openid profile email` | `sub`, `name`, `given_name`, `family_name`, `email`, `email_verified` |

> **Note**: Claims are only included in the response if values exist for the user. For example, if a user has no `family_name` stored, that claim will be absent from the response even if the `profile` scope was granted.

## Error Responses

### Missing or Invalid Token

If no token is provided or the token is malformed:

```
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer error="invalid_token", error_description="No access token provided"
```

### Expired Token

```
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer error="invalid_token", error_description="The access token has expired"
```

### Revoked Token

```
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer error="invalid_token", error_description="The access token has been revoked"
```

### Insufficient Scope

If the token does not have the `openid` scope:

```
HTTP/1.1 403 Forbidden
WWW-Authenticate: Bearer error="insufficient_scope", scope="openid"
```

## Relationship to the ID Token

Both the ID Token and the UserInfo endpoint provide identity claims, but they serve different purposes:

| Aspect | ID Token | UserInfo Endpoint |
|---|---|---|
| **When obtained** | At token exchange time | On-demand, any time the access token is valid |
| **Format** | Signed JWT (verifiable offline) | Plain JSON (requires server call) |
| **Freshness** | Snapshot at authentication time | Current values from the database |
| **Use case** | Authentication proof for the client | Retrieving up-to-date profile information |

The `sub` claim is guaranteed to be consistent between the ID Token and the UserInfo response for the same user.

## Related

- [Token Endpoint](./token-endpoint.md) -- obtaining the access token.
- [ID Token](./id-token.md) -- claims available in the JWT.
- [Authorization Code Flow](./authorization-code-flow.md) -- requesting specific scopes.
