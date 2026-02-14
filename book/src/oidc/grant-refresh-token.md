# Refresh Token Grant

The refresh token grant allows clients to obtain a new access token without requiring the user to re-authenticate. Barycenter implements refresh token rotation as recommended by [OAuth 2.0 Security Best Current Practice](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics): each time a refresh token is used, it is revoked and a new one is issued.

## Prerequisites

Refresh tokens are only issued when the `offline_access` scope is included in the original authorization request:

```
GET /authorize?...&scope=openid%20offline_access&...
```

If `offline_access` is not requested, the token response will not contain a `refresh_token` field, and this grant type cannot be used.

## Request

```
POST /token
Content-Type: application/x-www-form-urlencoded
```

### Parameters

| Parameter | Type | Required | Description |
|---|---|---|---|
| `grant_type` | string | Yes | Must be `refresh_token`. |
| `refresh_token` | string | Yes | The refresh token previously issued to the client. |

Client authentication (via [client_secret_basic or client_secret_post](./client-authentication.md)) is also required.

### Example Request

```bash
curl -X POST https://idp.example.com/token \
  -u "my_client_id:my_client_secret" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token" \
  -d "refresh_token=cmVmcmVzaC10b2tlbi1leGFtcGxl"
```

## Response

A successful refresh returns HTTP 200 with a new token set:

```json
{
  "access_token": "bmV3LWFjY2Vzcy10b2tlbi1leGFtcGxl",
  "token_type": "bearer",
  "expires_in": 3600,
  "id_token": "eyJhbGciOiJSUzI1NiIs...",
  "refresh_token": "bmV3LXJlZnJlc2gtdG9rZW4tZXhhbXBsZQ"
}
```

| Field | Type | Description |
|---|---|---|
| `access_token` | string | A new bearer access token, valid for 1 hour. |
| `token_type` | string | `"bearer"`. |
| `expires_in` | integer | `3600` (seconds). |
| `id_token` | string | A new signed [ID Token](./id-token.md). |
| `refresh_token` | string | A **new** refresh token. The previous refresh token is no longer valid. |

## Token Rotation

Barycenter implements refresh token rotation to limit the impact of token theft:

1. **On each use**, the presented refresh token is marked as revoked in the database.
2. **A new refresh token** is issued and returned in the response.
3. **The new token tracks its parent.** Barycenter records which refresh token was used to obtain the new one (`parent_token` tracking).

```
Original refresh_token (RT1)
  --> Exchange --> RT1 revoked, RT2 issued
                    --> Exchange --> RT2 revoked, RT3 issued
                                      --> Exchange --> RT3 revoked, RT4 issued
```

### Replay Detection

If a revoked refresh token is presented (indicating potential theft), Barycenter rejects the request with `invalid_grant`. The parent_token chain allows Barycenter to identify token reuse.

```
RT1 (revoked) --> Exchange attempt --> Rejected (invalid_grant)
```

This protects against a scenario where an attacker obtains a refresh token after the legitimate client has already rotated it.

## Error Conditions

| Error Code | Condition |
|---|---|
| `invalid_client` | Client authentication failed. HTTP 401. |
| `invalid_grant` | The refresh token is not recognized, has been revoked, or has expired. |
| `invalid_request` | Missing `refresh_token` parameter. |

### Example Error

```json
{
  "error": "invalid_grant",
  "error_description": "The refresh token has been revoked"
}
```

## Token Lifecycle

Refresh tokens follow this lifecycle:

| State | Description |
|---|---|
| **Active** | Valid and can be exchanged for new tokens. |
| **Consumed** | Has been used in a token exchange. Replaced by a new refresh token. |
| **Revoked** | Explicitly revoked via the [revocation endpoint](./token-revocation.md) or detected as replayed. |
| **Expired** | Past its expiration time. Cleaned up by background jobs. |

The `cleanup_expired_refresh_tokens` background job runs every hour (at :30) to remove expired refresh tokens from the database.

## Security Recommendations

- **Store refresh tokens securely.** They are long-lived credentials. Use secure storage mechanisms appropriate to your platform (e.g., encrypted storage on mobile, HTTP-only cookies for web).
- **Always use the latest refresh token.** After each refresh, discard the old token and use the newly issued one.
- **Handle `invalid_grant` gracefully.** If a refresh fails, redirect the user through the full authorization flow to obtain new tokens.
- **Request `offline_access` only when needed.** If your application does not need to refresh tokens (e.g., single-page apps with short sessions), omit the `offline_access` scope.

## Related

- [Token Endpoint](./token-endpoint.md) -- overview of all grant types.
- [Authorization Code Flow](./authorization-code-flow.md) -- obtaining the initial refresh token.
- [Token Revocation](./token-revocation.md) -- explicitly revoking refresh tokens.
