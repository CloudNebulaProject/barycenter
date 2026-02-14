# Authorization Code Grant

The authorization code grant type exchanges an authorization code for an access token and ID token. This is the second half of the [Authorization Code flow](./authorization-code-flow.md), occurring after the user has authenticated and consented.

## Request

```
POST /token
Content-Type: application/x-www-form-urlencoded
```

### Parameters

| Parameter | Type | Required | Description |
|---|---|---|---|
| `grant_type` | string | Yes | Must be `authorization_code`. |
| `code` | string | Yes | The authorization code received from the authorization endpoint redirect. |
| `redirect_uri` | string | Yes | Must exactly match the `redirect_uri` used in the original authorization request. |
| `client_id` | string | Yes | The client identifier. Required in the body for `client_secret_post` authentication; also extracted from the `Authorization` header for `client_secret_basic`. |
| `code_verifier` | string | Yes | The original PKCE code verifier that was used to generate the `code_challenge` sent to the authorization endpoint. |

Client authentication (via [client_secret_basic or client_secret_post](./client-authentication.md)) is also required.

### Example Request (client_secret_basic)

```bash
curl -X POST https://idp.example.com/token \
  -u "my_client_id:my_client_secret" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=Rk1hWUxPdXotbXk2UGFmQndPTEVMWWpIZVhR" \
  -d "redirect_uri=https://app.example.com/callback" \
  -d "code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
```

### Example Request (client_secret_post)

```bash
curl -X POST https://idp.example.com/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=Rk1hWUxPdXotbXk2UGFmQndPTEVMWWpIZVhR" \
  -d "redirect_uri=https://app.example.com/callback" \
  -d "client_id=my_client_id" \
  -d "client_secret=my_client_secret" \
  -d "code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
```

## PKCE Verification

Barycenter verifies the PKCE code verifier against the stored code challenge using the S256 method:

1. Compute `SHA-256(code_verifier)` to produce a 32-byte hash.
2. Encode the hash with base64url (no padding).
3. Compare the result to the `code_challenge` stored with the authorization code.

If the values do not match, the token request is rejected with `invalid_grant`.

```
SHA-256(code_verifier)  -->  base64url  -->  compare with stored code_challenge
```

This ensures that the party exchanging the authorization code is the same party that initiated the authorization request, even if the code was intercepted in transit.

## Response

A successful exchange returns HTTP 200 with a JSON body:

```json
{
  "access_token": "VGhpcyBpcyBhbiBleGFtcGxlIGFjY2VzcyB0b2tlbg",
  "token_type": "bearer",
  "expires_in": 3600,
  "id_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleS0xIn0.eyJpc3MiOiJodHRwczovL2lkcC5leGFtcGxlLmNvbSIsInN1YiI6InVzZXJfMTIzIiwiYXVkIjoibXlfY2xpZW50X2lkIiwiZXhwIjoxNzA5MzE1MjAwLCJpYXQiOjE3MDkzMTE2MDAsImF1dGhfdGltZSI6MTcwOTMxMTU5MCwibm9uY2UiOiJhYmMxMjMiLCJhdF9oYXNoIjoiSGsyYUtCeXpEcERReU4tR2VBN196dyIsImFtciI6WyJwd2QiXSwiYWNyIjoiYWFsMSJ9.signature",
  "refresh_token": "cmVmcmVzaC10b2tlbi1leGFtcGxl"
}
```

| Field | Type | Present | Description |
|---|---|---|---|
| `access_token` | string | Always | Bearer token, valid for 1 hour. |
| `token_type` | string | Always | `"bearer"`. |
| `expires_in` | integer | Always | `3600` (seconds). |
| `id_token` | string | Always | Signed JWT with identity claims. See [ID Token](./id-token.md). |
| `refresh_token` | string | Conditional | Present only if `offline_access` was included in the authorized scope. See [Refresh Token Grant](./grant-refresh-token.md). |

## Validation and Error Conditions

The token endpoint performs several checks before issuing tokens:

| Check | Error Code | Description |
|---|---|---|
| Client authentication | `invalid_client` | The client_id/client_secret pair is invalid. HTTP 401. |
| Code exists | `invalid_grant` | The authorization code is not recognized. |
| Code not expired | `invalid_grant` | The code's 5-minute TTL has elapsed. |
| Code not consumed | `invalid_grant` | The code has already been exchanged. |
| Client ID match | `invalid_grant` | The `client_id` in the token request does not match the client that obtained the code. |
| Redirect URI match | `invalid_grant` | The `redirect_uri` does not match the one used in the authorization request. |
| PKCE verification | `invalid_grant` | `SHA-256(code_verifier)` does not match the stored `code_challenge`. |

All error responses use HTTP 400 (except `invalid_client` which uses HTTP 401):

```json
{
  "error": "invalid_grant",
  "error_description": "The authorization code has been consumed"
}
```

## Security Considerations

- **Authorization codes are single-use.** After a successful exchange, the code is permanently marked as consumed. If an attacker replays a code, the request is rejected.
- **Codes expire after 5 minutes.** This limits the window for interception.
- **PKCE binds the code to the original requester.** Even if an authorization code is intercepted, it cannot be exchanged without the original `code_verifier`.
- **Redirect URI is validated twice** -- once at the authorization endpoint and once at the token endpoint -- ensuring consistency.

## Related

- [Authorization Code Flow](./authorization-code-flow.md) -- the full flow from authorization to token exchange.
- [Client Authentication](./client-authentication.md) -- authenticating the token request.
- [ID Token](./id-token.md) -- understanding the issued ID Token.
- [Token Endpoint](./token-endpoint.md) -- overview of all grant types.
