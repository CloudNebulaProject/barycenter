# Token Endpoint

The token endpoint is used to exchange an authorization grant for an access token, ID token, and optionally a refresh token.

## Endpoint

```
POST /token
Content-Type: application/x-www-form-urlencoded
```

All requests to the token endpoint must use `application/x-www-form-urlencoded` encoding for the request body. JSON request bodies are not accepted.

## Client Authentication

Every token request must include client authentication. Barycenter supports two methods:

- **`client_secret_basic`** -- HTTP Basic authentication with the client_id and client_secret.
- **`client_secret_post`** -- client_id and client_secret sent as form parameters in the request body.

See [Client Authentication](./client-authentication.md) for details and examples.

## Supported Grant Types

Barycenter supports three grant types at the token endpoint:

### [Authorization Code Grant](./grant-authorization-code.md)

The primary grant type for web and native applications. Exchanges an authorization code (obtained from the [authorization endpoint](./authorization-code-flow.md)) for tokens. Requires PKCE verification.

```
grant_type=authorization_code
```

### [Refresh Token Grant](./grant-refresh-token.md)

Obtains a new access token using a previously issued refresh token. Implements token rotation for security -- each use of a refresh token invalidates it and issues a new one.

```
grant_type=refresh_token
```

### [Device Authorization Grant](./grant-device-authorization.md)

Enables input-constrained devices (smart TVs, CLI tools, IoT devices) to obtain tokens by having the user authorize on a separate device with a browser.

```
grant_type=urn:ietf:params:oauth:grant-type:device_code
```

## Common Response Format

All successful token responses share the same structure:

```json
{
  "access_token": "eyJhbGciOiJS...",
  "token_type": "bearer",
  "expires_in": 3600,
  "id_token": "eyJhbGciOiJS...",
  "refresh_token": "dGhpcyBpcyBh..."
}
```

| Field | Type | Description |
|---|---|---|
| `access_token` | string | Bearer token for accessing protected resources such as the [UserInfo endpoint](./userinfo.md). |
| `token_type` | string | Always `"bearer"`. |
| `expires_in` | integer | Token lifetime in seconds. Default is `3600` (1 hour). |
| `id_token` | string | A signed [ID Token](./id-token.md) (JWT) containing identity claims. Present when the `openid` scope was requested. |
| `refresh_token` | string | A refresh token for obtaining new access tokens. Present only when the `offline_access` scope was requested. |

## Error Responses

Token endpoint errors are returned as JSON with an HTTP 400 status code (or 401 for authentication failures):

```json
{
  "error": "invalid_grant",
  "error_description": "The authorization code has expired"
}
```

| Error Code | Condition |
|---|---|
| `invalid_request` | Missing required parameter or malformed request. |
| `invalid_client` | Client authentication failed (wrong secret, unknown client_id). Returns HTTP 401. |
| `invalid_grant` | The authorization code, refresh token, or device code is invalid, expired, or already consumed. |
| `unauthorized_client` | The client is not authorized for the requested grant type. |
| `unsupported_grant_type` | The grant type is not supported. |
| `invalid_scope` | The requested scope is invalid or exceeds the originally granted scope. |
| `slow_down` | Device code grant only: the client is polling too frequently. |
| `authorization_pending` | Device code grant only: the user has not yet completed authorization. |
| `expired_token` | Device code grant only: the device code has expired. |

## Related

- [Client Authentication](./client-authentication.md) -- how to authenticate requests to this endpoint.
- [ID Token](./id-token.md) -- structure of the returned ID Token.
- [Token Revocation](./token-revocation.md) -- revoking issued tokens.
