# Discovery and JWKS

Barycenter publishes its configuration and public keys through two standard endpoints, enabling relying parties to automatically configure themselves without manual setup.

## OpenID Connect Discovery

### Endpoint

```
GET /.well-known/openid-configuration
```

This endpoint returns a JSON document describing the OpenID Provider's configuration, as defined in [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html).

### Example Request

```bash
curl https://idp.example.com/.well-known/openid-configuration
```

### Response

```json
{
  "issuer": "https://idp.example.com",
  "authorization_endpoint": "https://idp.example.com/authorize",
  "token_endpoint": "https://idp.example.com/token",
  "userinfo_endpoint": "https://idp.example.com/userinfo",
  "jwks_uri": "https://idp.example.com/.well-known/jwks.json",
  "registration_endpoint": "https://idp.example.com/connect/register",
  "revocation_endpoint": "https://idp.example.com/revoke",
  "device_authorization_endpoint": "https://idp.example.com/device_authorization",
  "scopes_supported": [
    "openid",
    "profile",
    "email",
    "offline_access"
  ],
  "response_types_supported": [
    "code",
    "id_token",
    "id_token token"
  ],
  "grant_types_supported": [
    "authorization_code",
    "refresh_token",
    "urn:ietf:params:oauth:grant-type:device_code"
  ],
  "subject_types_supported": [
    "public"
  ],
  "id_token_signing_alg_values_supported": [
    "RS256"
  ],
  "token_endpoint_auth_methods_supported": [
    "client_secret_basic",
    "client_secret_post"
  ],
  "claims_supported": [
    "iss",
    "sub",
    "aud",
    "exp",
    "iat",
    "auth_time",
    "nonce",
    "at_hash",
    "amr",
    "acr",
    "name",
    "given_name",
    "family_name",
    "email",
    "email_verified"
  ],
  "code_challenge_methods_supported": [
    "S256"
  ],
  "ui_locales_supported": [],
  "claims_locales_supported": []
}
```

### Metadata Fields

#### Endpoints

| Field | Description |
|---|---|
| `issuer` | The identifier for the OpenID Provider. This value is used as the `iss` claim in [ID Tokens](./id-token.md) and must exactly match. |
| `authorization_endpoint` | URL for the [authorization endpoint](./authorization-code-flow.md). |
| `token_endpoint` | URL for the [token endpoint](./token-endpoint.md). |
| `userinfo_endpoint` | URL for the [UserInfo endpoint](./userinfo.md). |
| `jwks_uri` | URL for the [JWKS endpoint](#json-web-key-set-jwks) containing the public signing keys. |
| `registration_endpoint` | URL for [dynamic client registration](./client-registration.md). |
| `revocation_endpoint` | URL for [token revocation](./token-revocation.md). |
| `device_authorization_endpoint` | URL for the [device authorization endpoint](./grant-device-authorization.md). |

#### Supported Features

| Field | Description |
|---|---|
| `scopes_supported` | The scopes that Barycenter recognizes. `openid` is required for all OIDC requests. `profile` and `email` control which claims are returned by the [UserInfo endpoint](./userinfo.md). `offline_access` enables [refresh tokens](./grant-refresh-token.md). |
| `response_types_supported` | Supported `response_type` values for the authorization endpoint. `code` is the recommended Authorization Code flow. |
| `grant_types_supported` | Grant types accepted at the token endpoint. See individual grant type documentation for details. |
| `subject_types_supported` | Subject identifier types. Barycenter uses `public` subject identifiers (the same `sub` value is returned to all clients for a given user). |
| `id_token_signing_alg_values_supported` | Algorithms used for signing ID Tokens. Barycenter uses `RS256` exclusively. |
| `token_endpoint_auth_methods_supported` | [Client authentication methods](./client-authentication.md) accepted at the token endpoint. |
| `claims_supported` | Claims that may appear in [ID Tokens](./id-token.md) or [UserInfo responses](./userinfo.md). |
| `code_challenge_methods_supported` | PKCE challenge methods. Only `S256` is supported; `plain` is rejected. |
| `ui_locales_supported` | Supported UI locales. Currently empty (default locale only). |
| `claims_locales_supported` | Supported claims locales. Currently empty (default locale only). |

## JSON Web Key Set (JWKS)

### Endpoint

```
GET /.well-known/jwks.json
```

This endpoint returns the public keys used by Barycenter to sign ID Tokens, formatted as a JSON Web Key Set per [RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517).

### Example Request

```bash
curl https://idp.example.com/.well-known/jwks.json
```

### Response

```json
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "alg": "RS256",
      "kid": "key-1",
      "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
      "e": "AQAB"
    }
  ]
}
```

### Key Fields

| Field | Type | Description |
|---|---|---|
| `kty` | string | Key type. Always `RSA` for Barycenter's signing keys. |
| `use` | string | Key usage. `sig` indicates the key is used for digital signatures. |
| `alg` | string | Algorithm. `RS256` (RSASSA-PKCS1-v1_5 using SHA-256). |
| `kid` | string | Key ID. Matches the `kid` in the JWT header of [ID Tokens](./id-token.md), allowing relying parties to select the correct key when multiple keys are published. |
| `n` | string | RSA modulus, base64url-encoded. |
| `e` | string | RSA public exponent, base64url-encoded. Typically `AQAB` (65537). |

### Key Lifecycle

- Barycenter generates a **2048-bit RSA key pair** on first startup if no existing key is found.
- The private key is persisted to the path configured in `keys.private_key_path`.
- The public key set is written to `keys.jwks_path` and served by this endpoint.
- The `kid` value is stable across restarts, ensuring that previously issued ID Tokens can still be verified.

## Using Discovery for Client Configuration

Most OIDC client libraries can auto-configure themselves using the discovery endpoint. The typical flow is:

1. Fetch `/.well-known/openid-configuration`.
2. Extract the relevant endpoint URLs (`authorization_endpoint`, `token_endpoint`, `jwks_uri`, etc.).
3. Fetch the JWKS from `jwks_uri` to obtain the public signing keys.
4. Cache the JWKS with appropriate TTL and refresh periodically.

### Example: Discovering and Verifying

```bash
# 1. Fetch the provider configuration
config=$(curl -s https://idp.example.com/.well-known/openid-configuration)

# 2. Extract the JWKS URI
jwks_uri=$(echo "$config" | jq -r '.jwks_uri')

# 3. Fetch the public keys
jwks=$(curl -s "$jwks_uri")

# 4. Display the signing key
echo "$jwks" | jq '.keys[0]'
```

## Caching Recommendations

- **Discovery document**: Cache for at least 24 hours. The configuration changes infrequently (only on server reconfiguration).
- **JWKS**: Cache based on HTTP cache headers. Refresh when encountering an unknown `kid` in a JWT header, as this may indicate key rotation.

## Related

- [ID Token](./id-token.md) -- verifying tokens with the JWKS public key.
- [Client Registration](./client-registration.md) -- the registration endpoint advertised in discovery.
- [Token Endpoint](./token-endpoint.md) -- the token endpoint advertised in discovery.
