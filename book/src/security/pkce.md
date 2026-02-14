# PKCE (Proof Key for Code Exchange)

Barycenter requires PKCE for all authorization code flows. PKCE prevents authorization code interception attacks, where an attacker captures the authorization code during the redirect and exchanges it for tokens before the legitimate client can.

## S256 Only

Barycenter exclusively supports the `S256` code challenge method. The `plain` method is explicitly rejected because it provides no security benefit -- an attacker who can intercept the authorization code can also intercept a plaintext verifier.

Any authorization request that specifies `code_challenge_method=plain` or omits the `code_challenge_method` parameter will be rejected with an error.

## How PKCE Works

PKCE adds a cryptographic proof to the authorization code flow that binds the token request to the original authorization request. Only the client that initiated the flow can complete it.

### Step 1: Client Generates a Code Verifier

The client generates a cryptographically random string called the **code verifier**. This value must be between 43 and 128 characters long, using only unreserved URI characters (`[A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"`).

```
code_verifier = base64url(random(32 bytes))
```

Example:
```
dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
```

### Step 2: Client Derives the Code Challenge

The client computes the **code challenge** by taking the SHA-256 hash of the code verifier and base64url-encoding the result:

```
code_challenge = base64url(SHA-256(code_verifier))
```

Example:
```
E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
```

### Step 3: Authorization Request

The client includes the code challenge in the authorization request:

```
GET /authorize?
  response_type=code&
  client_id=CLIENT_ID&
  redirect_uri=https://app.example.com/callback&
  scope=openid&
  state=abc123&
  code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&
  code_challenge_method=S256
```

Barycenter validates the request, stores the code challenge alongside the authorization code in the database, and issues the authorization code in the redirect.

### Step 4: Token Request

When exchanging the authorization code for tokens, the client includes the original **code verifier** (not the challenge):

```
POST /token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&
code=AUTHORIZATION_CODE&
redirect_uri=https://app.example.com/callback&
client_id=CLIENT_ID&
client_secret=CLIENT_SECRET&
code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
```

### Step 5: Server Verification

Barycenter verifies the PKCE proof at the token endpoint:

1. Retrieves the stored `code_challenge` for the authorization code.
2. Computes `base64url(SHA-256(code_verifier))` from the provided verifier.
3. Compares the computed value with the stored challenge.
4. If they match, the token request proceeds. If not, it is rejected with `invalid_grant`.

```text
Stored:   E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
Computed: base64url(SHA-256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"))
        = E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
Result:   Match -> issue tokens
```

## Why PKCE Matters

Without PKCE, an attacker who intercepts the authorization code (for example, through a malicious browser extension, a compromised redirect URI, or a man-in-the-middle on the redirect) can exchange it for tokens at the token endpoint.

With PKCE, the attacker also needs the code verifier, which was never transmitted to the authorization server and exists only in the client's memory. Since the code challenge is a one-way hash of the verifier, it cannot be reversed.

## PKCE and Confidential Clients

Barycenter requires PKCE even for confidential clients that authenticate with a client secret. While confidential clients have an additional layer of protection (the attacker would also need the client secret), PKCE provides defense in depth and is recommended by current OAuth 2.0 security best practices (RFC 9126, OAuth 2.0 Security Best Current Practice).

## Error Responses

| Condition | Error Code | Description |
|-----------|-----------|-------------|
| Missing `code_challenge` | `invalid_request` | PKCE is required for all authorization requests |
| `code_challenge_method=plain` | `invalid_request` | Only S256 is supported |
| Missing `code_verifier` at token endpoint | `invalid_request` | Code verifier is required |
| Verifier does not match challenge | `invalid_grant` | PKCE verification failed |

## References

- [RFC 7636 -- Proof Key for Code Exchange](https://datatracker.ietf.org/doc/html/rfc7636)
- [OAuth 2.0 Security Best Current Practice](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)
