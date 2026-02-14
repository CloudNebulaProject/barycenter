# Client Authentication

When making requests to the [token endpoint](./token-endpoint.md), clients must authenticate themselves to prove they are the legitimate holder of the `client_id`. Barycenter supports two authentication methods defined in [RFC 6749 Section 2.3](https://datatracker.ietf.org/doc/html/rfc6749#section-2.3) and [OpenID Connect Core Section 9](https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication).

## Supported Methods

| Method | Description | Credential Location |
|---|---|---|
| `client_secret_basic` | HTTP Basic authentication | `Authorization` header |
| `client_secret_post` | Form-encoded credentials | Request body |

Both methods are equally supported. Choose the one that best fits your HTTP client library or framework.

## client_secret_basic

The client sends its credentials using HTTP Basic authentication. The `client_id` and `client_secret` are combined with a colon separator, base64-encoded, and sent in the `Authorization` header.

### Format

```
Authorization: Basic base64(client_id:client_secret)
```

### Encoding Steps

1. Concatenate the `client_id`, a colon (`:`), and the `client_secret`.
2. Base64-encode the resulting string.
3. Set the `Authorization` header to `Basic ` followed by the encoded string.

### Example

Given:
- `client_id`: `my_client_id`
- `client_secret`: `my_client_secret`

```bash
# The base64 encoding of "my_client_id:my_client_secret"
echo -n "my_client_id:my_client_secret" | base64
# Output: bXlfY2xpZW50X2lkOm15X2NsaWVudF9zZWNyZXQ=
```

```bash
curl -X POST https://idp.example.com/token \
  -H "Authorization: Basic bXlfY2xpZW50X2lkOm15X2NsaWVudF9zZWNyZXQ=" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=AUTH_CODE" \
  -d "redirect_uri=https://app.example.com/callback" \
  -d "code_verifier=VERIFIER"
```

Most HTTP libraries handle Basic authentication natively. For example, `curl` provides the `-u` flag:

```bash
curl -X POST https://idp.example.com/token \
  -u "my_client_id:my_client_secret" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=AUTH_CODE" \
  -d "redirect_uri=https://app.example.com/callback" \
  -d "code_verifier=VERIFIER"
```

### Special Characters

If the `client_id` or `client_secret` contains special characters (such as `:`, `@`, or non-ASCII characters), they must be percent-encoded per [RFC 6749 Section 2.3.1](https://datatracker.ietf.org/doc/html/rfc6749#section-2.3.1) before base64 encoding. In practice, Barycenter generates credentials using base64url-safe characters, so this is typically not a concern.

## client_secret_post

The client sends its credentials as form parameters in the request body alongside the other token request parameters.

### Parameters

| Parameter | Type | Required | Description |
|---|---|---|---|
| `client_id` | string | Yes | The client identifier. |
| `client_secret` | string | Yes | The client secret. |

### Example

```bash
curl -X POST https://idp.example.com/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=AUTH_CODE" \
  -d "redirect_uri=https://app.example.com/callback" \
  -d "code_verifier=VERIFIER" \
  -d "client_id=my_client_id" \
  -d "client_secret=my_client_secret"
```

## Choosing a Method

| Consideration | client_secret_basic | client_secret_post |
|---|---|---|
| Credential exposure in logs | Credentials in header, less likely to be logged | Credentials in body, may appear in access logs if the server logs POST bodies |
| Framework support | Most HTTP libraries support Basic auth natively | Requires manual parameter inclusion |
| Specification preference | Preferred by OAuth 2.0 spec | Acceptable alternative |
| Simplicity | Requires base64 encoding | Straightforward form parameters |

The OAuth 2.0 specification expresses a preference for `client_secret_basic`, but both methods are fully supported and provide equivalent security.

## Error Handling

If client authentication fails, the token endpoint returns HTTP 401 with a `WWW-Authenticate` header:

```
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Basic
Content-Type: application/json

{
  "error": "invalid_client",
  "error_description": "Client authentication failed"
}
```

Common causes of authentication failure:

- **Unknown `client_id`**: The client has not been [registered](./client-registration.md).
- **Incorrect `client_secret`**: The secret does not match the one issued during registration.
- **Malformed `Authorization` header**: The base64 encoding is incorrect or the header format is wrong.
- **Missing credentials**: Neither the `Authorization` header nor body parameters contain client credentials.

## Related

- [Client Registration](./client-registration.md) -- obtaining client credentials.
- [Token Endpoint](./token-endpoint.md) -- using credentials to request tokens.
