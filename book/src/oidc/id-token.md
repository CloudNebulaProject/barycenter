# ID Token

The ID Token is the core artifact of OpenID Connect. It is a JSON Web Token (JWT) that contains claims about the authentication event and the authenticated user. Barycenter signs ID Tokens using the RS256 algorithm (RSA Signature with SHA-256).

## JWT Structure

A JWT consists of three base64url-encoded parts separated by dots:

```
header.payload.signature
```

### Header

```json
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "key-1"
}
```

| Field | Description |
|---|---|
| `alg` | The signing algorithm. Always `RS256`. |
| `typ` | The token type. Always `JWT`. |
| `kid` | The key identifier. Matches the `kid` in the [JWKS](./discovery-jwks.md) endpoint, allowing relying parties to select the correct public key for verification. |

### Payload (Claims)

The payload contains the identity and authentication claims.

### Signature

The signature is computed over the base64url-encoded header and payload using the RSA private key:

```
RSASSA-PKCS1-V1_5-SIGN(SHA-256, base64url(header) + "." + base64url(payload))
```

Relying parties verify the signature using the public key from the [JWKS endpoint](./discovery-jwks.md).

## Claims Reference

| Claim | Type | Required | Description |
|---|---|---|---|
| `iss` | string | Yes | Issuer identifier. The URL of the Barycenter instance (e.g., `https://idp.example.com`). |
| `sub` | string | Yes | Subject identifier. A unique, stable identifier for the authenticated user. |
| `aud` | string | Yes | Audience. The `client_id` of the relying party that requested the token. |
| `exp` | integer | Yes | Expiration time as a Unix timestamp. The token must not be accepted after this time. |
| `iat` | integer | Yes | Issued-at time as a Unix timestamp. When the token was created. |
| `auth_time` | integer | Yes | Time of the authentication event as a Unix timestamp. When the user last actively authenticated. |
| `nonce` | string | Conditional | Present if a `nonce` was provided in the authorization request. Used by the client to associate the ID Token with its request and mitigate replay attacks. |
| `at_hash` | string | Yes | Access Token hash. Binds the ID Token to the access token. See [computation details](#at_hash-computation) below. |
| `amr` | array of strings | Yes | Authentication Methods References. Describes how the user authenticated. See [AMR values](#amr-values). |
| `acr` | string | Yes | Authentication Context Class Reference. Indicates the assurance level of the authentication. See [ACR values](#acr-values). |

## at_hash Computation

The `at_hash` claim binds the ID Token to the co-issued access token, preventing token substitution attacks. Barycenter computes it as follows:

1. Compute the SHA-256 hash of the ASCII representation of the `access_token` value.
2. Take the **left-most 128 bits** (16 bytes) of the hash.
3. Base64url-encode the result (no padding).

```
at_hash = base64url(SHA-256(access_token)[0..16])
```

### Example

Given an access token `VGhpcyBpcyBhbiBleGFtcGxl`:

```
SHA-256("VGhpcyBpcyBhbiBleGFtcGxl")
  = 1e4d6b...  (32 bytes)

Left 128 bits = first 16 bytes

at_hash = base64url(first_16_bytes)
  = "Hk2aKByzDpDQyN-GeA7_zw"
```

Relying parties should verify the `at_hash` by performing the same computation on the received `access_token` and comparing the result.

## AMR Values

The `amr` (Authentication Methods References) claim is an array of strings indicating which authentication methods were used during the session.

| Value | Meaning |
|---|---|
| `pwd` | Password authentication. The user provided a username and password. |
| `hwk` | Hardware-bound key. The user authenticated with a hardware-bound passkey (e.g., YubiKey, platform authenticator without cloud sync). |
| `swk` | Software key. The user authenticated with a cloud-synced passkey (e.g., iCloud Keychain, Google Password Manager). |

Multiple values indicate that more than one authentication method was used (multi-factor authentication):

| AMR | Scenario |
|---|---|
| `["pwd"]` | Password-only authentication. |
| `["hwk"]` | Single-factor passkey login (hardware-bound). |
| `["swk"]` | Single-factor passkey login (cloud-synced). |
| `["pwd", "hwk"]` | Password + hardware passkey (two-factor). |
| `["pwd", "swk"]` | Password + cloud-synced passkey (two-factor). |

## ACR Values

The `acr` (Authentication Context Class Reference) claim indicates the authentication assurance level.

| Value | Meaning | Condition |
|---|---|---|
| `aal1` | Authentication Assurance Level 1. Single-factor authentication. | One authentication method was used (password or passkey). |
| `aal2` | Authentication Assurance Level 2. Multi-factor authentication. | Two or more authentication methods were used (e.g., password + passkey). |

## Example Decoded Token

### Header

```json
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "key-1"
}
```

### Payload

```json
{
  "iss": "https://idp.example.com",
  "sub": "550e8400-e29b-41d4-a716-446655440000",
  "aud": "dG9hc3R5LWNsaWVudC1pZC1leGFtcGxl",
  "exp": 1709315200,
  "iat": 1709311600,
  "auth_time": 1709311590,
  "nonce": "n-0S6_WzA2Mj",
  "at_hash": "Hk2aKByzDpDQyN-GeA7_zw",
  "amr": ["pwd", "hwk"],
  "acr": "aal2"
}
```

This token represents a user who authenticated with a password and then verified with a hardware-bound passkey (two-factor authentication at AAL2).

## Verifying an ID Token

Relying parties must validate the ID Token before trusting its claims. The verification steps are:

1. **Decode the JWT** into its three parts (header, payload, signature).
2. **Retrieve the public key** from the [JWKS endpoint](./discovery-jwks.md) using the `kid` from the header.
3. **Verify the signature** using the RS256 algorithm and the public key.
4. **Validate the `iss` claim** matches the expected issuer URL.
5. **Validate the `aud` claim** contains the client's own `client_id`.
6. **Check the `exp` claim** to ensure the token has not expired. Allow for a small clock skew (e.g., 30 seconds).
7. **Validate the `nonce`** matches the nonce sent in the authorization request (if one was sent).
8. **Verify `at_hash`** by computing it from the received access token and comparing.

## Key Management

- Barycenter generates a **2048-bit RSA key pair** on first startup.
- The private key is persisted to disk (configured via `keys.private_key_path`) and reused across restarts.
- The public key is published via the [JWKS endpoint](./discovery-jwks.md).
- The `kid` in the JWT header corresponds to the `kid` in the JWKS, enabling key rotation.

## Related

- [Discovery and JWKS](./discovery-jwks.md) -- retrieving the public key for verification.
- [Token Endpoint](./token-endpoint.md) -- obtaining ID Tokens.
- [UserInfo Endpoint](./userinfo.md) -- retrieving additional user claims.
