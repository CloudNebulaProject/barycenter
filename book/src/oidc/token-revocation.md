# Token Revocation

Barycenter provides a token revocation endpoint that allows clients to invalidate access tokens and refresh tokens when they are no longer needed. This is defined in [RFC 7009](https://datatracker.ietf.org/doc/html/rfc7009).

## Endpoint

```
POST /revoke
Content-Type: application/x-www-form-urlencoded
```

## Parameters

| Parameter | Type | Required | Description |
|---|---|---|---|
| `token` | string | Yes | The token to revoke. This can be either an access token or a refresh token. |

Client authentication (via [client_secret_basic or client_secret_post](./client-authentication.md)) is also required.

## Example Request

### Using client_secret_basic

```bash
curl -X POST https://idp.example.com/revoke \
  -u "my_client_id:my_client_secret" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=VGhpcyBpcyBhbiBleGFtcGxlIGFjY2VzcyB0b2tlbg"
```

### Using client_secret_post

```bash
curl -X POST https://idp.example.com/revoke \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=VGhpcyBpcyBhbiBleGFtcGxlIGFjY2VzcyB0b2tlbg" \
  -d "client_id=my_client_id" \
  -d "client_secret=my_client_secret"
```

## Response

### Successful Revocation

A successful revocation returns HTTP 200 with an empty body:

```
HTTP/1.1 200 OK
Content-Length: 0
```

Per RFC 7009, the server responds with HTTP 200 regardless of whether the token was found, was already revoked, or was never valid. This prevents token scanning attacks -- a client cannot determine whether a token exists by observing the response.

### Behavior Matrix

| Token State | Server Action | Response |
|---|---|---|
| Active token | Sets `revoked` flag in database | HTTP 200 |
| Already revoked | No change | HTTP 200 |
| Expired token | No change (already unusable) | HTTP 200 |
| Unknown token | No action | HTTP 200 |

### Error Responses

Errors are only returned for problems with the request itself, not with the token:

| Error Code | HTTP Status | Condition |
|---|---|---|
| `invalid_client` | 401 | Client authentication failed. |
| `invalid_request` | 400 | The `token` parameter is missing. |

```json
{
  "error": "invalid_client",
  "error_description": "Client authentication failed"
}
```

## Effect of Revocation

Once a token is revoked:

- **Access tokens**: Any subsequent request to a protected resource (such as the [UserInfo endpoint](./userinfo.md)) using the revoked token will be rejected with HTTP 401.
- **Refresh tokens**: Any attempt to use the revoked refresh token at the [token endpoint](./token-endpoint.md) will be rejected with `invalid_grant`.

Revocation is immediate. There is no grace period or propagation delay.

> **Note**: Revoking an access token does **not** automatically revoke the associated refresh token, and vice versa. If you need to invalidate both, send two separate revocation requests.

## When to Revoke Tokens

Common scenarios where token revocation is appropriate:

- **User logout**: Revoke the access token and refresh token when the user explicitly signs out.
- **Session termination**: When an administrator terminates a user's session.
- **Security incident**: If a token may have been compromised, revoke it immediately.
- **Application uninstall**: When a user removes or disconnects a client application.

## Related

- [Token Endpoint](./token-endpoint.md) -- obtaining tokens.
- [Refresh Token Grant](./grant-refresh-token.md) -- refresh token rotation also revokes old tokens.
- [Client Authentication](./client-authentication.md) -- authenticating revocation requests.
- [Discovery](./discovery-jwks.md) -- the revocation endpoint is advertised in the discovery document.
