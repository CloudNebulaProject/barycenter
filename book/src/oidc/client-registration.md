# Client Registration

Barycenter supports Dynamic Client Registration as defined in [RFC 7591](https://datatracker.ietf.org/doc/html/rfc7591). Clients can register themselves programmatically by sending a POST request to the registration endpoint.

## Endpoint

```
POST /connect/register
Content-Type: application/json
```

## Request Body

| Field | Type | Required | Description |
|---|---|---|---|
| `redirect_uris` | array of strings | Yes | One or more redirect URIs for the client. Each URI must be an absolute URI. These are used for exact-match validation during [authorization requests](./authorization-code-flow.md). |
| `client_name` | string | No | Human-readable name for the client application. Displayed to users during consent. |

### Example Request

```bash
curl -X POST https://idp.example.com/connect/register \
  -H "Content-Type: application/json" \
  -d '{
    "redirect_uris": [
      "https://app.example.com/callback",
      "https://app.example.com/auth/redirect"
    ],
    "client_name": "My Application"
  }'
```

## Response

A successful registration returns `201 Created` with the client credentials.

| Field | Type | Description |
|---|---|---|
| `client_id` | string | Unique identifier for the client. Generated as 24 random bytes, base64url-encoded. |
| `client_secret` | string | Client secret for authentication at the [token endpoint](./token-endpoint.md). Generated as 24 random bytes, base64url-encoded. |
| `redirect_uris` | array of strings | The registered redirect URIs, echoed back from the request. |
| `client_name` | string | The client name, echoed back from the request (if provided). |

### Example Response

```json
{
  "client_id": "dG9hc3R5LWNsaWVudC1pZC1leGFtcGxl",
  "client_secret": "c2VjcmV0LXZhbHVlLWhlcmUtZXhhbXBsZQ",
  "redirect_uris": [
    "https://app.example.com/callback",
    "https://app.example.com/auth/redirect"
  ],
  "client_name": "My Application"
}
```

## Validation

The registration endpoint validates the following:

- **`redirect_uris` must be present** and contain at least one URI.
- **Each URI must be a valid absolute URI**. Fragment components (`#fragment`) are not allowed per the OAuth 2.0 specification.

If validation fails, the endpoint returns an error response:

```json
{
  "error": "invalid_client_metadata",
  "error_description": "At least one redirect_uri is required"
}
```

## Client Credentials

After registration, the client must store both the `client_id` and `client_secret` securely. The `client_secret` is needed to authenticate at the token endpoint using either [client_secret_basic or client_secret_post](./client-authentication.md).

> **Important**: The `client_secret` is returned only once at registration time. Barycenter does not provide a mechanism to retrieve it later. If the secret is lost, the client must re-register.

## Usage After Registration

Once registered, the client can initiate the [Authorization Code flow](./authorization-code-flow.md):

```bash
# 1. Register
response=$(curl -s -X POST https://idp.example.com/connect/register \
  -H "Content-Type: application/json" \
  -d '{
    "redirect_uris": ["https://app.example.com/callback"],
    "client_name": "Demo Client"
  }')

# 2. Extract credentials
client_id=$(echo "$response" | jq -r '.client_id')
client_secret=$(echo "$response" | jq -r '.client_secret')

echo "Client ID: $client_id"
echo "Client Secret: $client_secret"

# 3. Use in authorization request
echo "Authorize URL: https://idp.example.com/authorize?client_id=${client_id}&redirect_uri=https://app.example.com/callback&response_type=code&scope=openid&code_challenge=...&code_challenge_method=S256"
```

## Related

- [Authorization Code Flow](./authorization-code-flow.md) -- using the registered client to initiate authorization.
- [Client Authentication](./client-authentication.md) -- authenticating at the token endpoint with the issued credentials.
- [Discovery](./discovery-jwks.md) -- finding the registration endpoint via OpenID Connect Discovery.
