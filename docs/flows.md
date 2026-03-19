### End-to-End OIDC Flows

This document provides example curl/browser commands for the complete Authorization Code + PKCE flow.

All examples assume the server is running at `http://localhost:9090`.

---

#### 1. Check Discovery

```bash
curl -s http://localhost:9090/.well-known/openid-configuration | jq .
```

Verify key fields: `issuer`, `authorization_endpoint`, `token_endpoint`, `jwks_uri`, `userinfo_endpoint`, `introspection_endpoint`, `revocation_endpoint`.

---

#### 2. Register a Client

```bash
curl -s -X POST http://localhost:9090/connect/register \
  -H "Content-Type: application/json" \
  -d '{
    "redirect_uris": ["http://localhost:8080/callback"],
    "client_name": "Test Client",
    "token_endpoint_auth_method": "client_secret_basic"
  }' | jq .
```

Save `client_id` and `client_secret` from the response.

---

#### 3. Generate PKCE Challenge

```bash
# Generate code_verifier (43-128 chars, base64url)
CODE_VERIFIER=$(openssl rand -base64 32 | tr -d '=' | tr '+/' '-_')

# Derive code_challenge (S256)
CODE_CHALLENGE=$(printf '%s' "$CODE_VERIFIER" | openssl dgst -binary -sha256 | base64 | tr -d '=' | tr '+/' '-_')

echo "code_verifier:  $CODE_VERIFIER"
echo "code_challenge: $CODE_CHALLENGE"
```

---

#### 4. Start Authorization (Browser)

Open this URL in a browser (replace `CLIENT_ID` with your actual client_id):

```
http://localhost:9090/authorize?client_id=CLIENT_ID&redirect_uri=http://localhost:8080/callback&response_type=code&scope=openid%20profile%20email&code_challenge=CODE_CHALLENGE&code_challenge_method=S256&state=random123&nonce=nonce456
```

If not logged in, you will be redirected to `/login`. Enter credentials (e.g., `admin` / `password123`).

After login and consent, the browser redirects to:
```
http://localhost:8080/callback?code=AUTH_CODE&state=random123
```

Copy the `code` parameter.

---

#### 5. Exchange Code for Tokens

Using **client_secret_basic** (HTTP Basic auth):

```bash
# Base64 encode client_id:client_secret
AUTH=$(printf '%s:%s' "$CLIENT_ID" "$CLIENT_SECRET" | base64 -w0)

curl -s -X POST http://localhost:9090/token \
  -H "Authorization: Basic $AUTH" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&code=AUTH_CODE&redirect_uri=http://localhost:8080/callback&code_verifier=$CODE_VERIFIER" | jq .
```

Using **client_secret_post** (form body):

```bash
curl -s -X POST http://localhost:9090/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&code=AUTH_CODE&redirect_uri=http://localhost:8080/callback&client_id=$CLIENT_ID&client_secret=$CLIENT_SECRET&code_verifier=$CODE_VERIFIER" | jq .
```

The response includes `access_token`, `id_token`, `token_type`, and `expires_in`.

---

#### 6. Decode the ID Token

```bash
# Extract and decode the JWT payload (second segment)
echo "$ID_TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | jq .
```

Expected claims: `iss`, `sub`, `aud`, `exp`, `iat`, `auth_time`, `nonce`, `at_hash`, `amr`, `acr`.

---

#### 7. Call UserInfo

```bash
curl -s http://localhost:9090/userinfo \
  -H "Authorization: Bearer $ACCESS_TOKEN" | jq .
```

Returns claims based on the granted scopes (e.g., `sub`, `name`, `email`).

Error case (missing/invalid token):
```bash
curl -s -w "\nHTTP %{http_code}\n" http://localhost:9090/userinfo
# Returns 401 with WWW-Authenticate header
```

---

#### 8. Introspect a Token

```bash
AUTH=$(printf '%s:%s' "$CLIENT_ID" "$CLIENT_SECRET" | base64 -w0)

curl -s -X POST http://localhost:9090/introspect \
  -H "Authorization: Basic $AUTH" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=$ACCESS_TOKEN" | jq .
```

Active token response:
```json
{
  "active": true,
  "scope": "openid profile email",
  "client_id": "...",
  "sub": "...",
  "exp": 1234567890,
  "iat": 1234564290,
  "token_type": "bearer"
}
```

Expired/revoked/unknown token:
```json
{
  "active": false
}
```

---

#### 9. Revoke a Token

```bash
AUTH=$(printf '%s:%s' "$CLIENT_ID" "$CLIENT_SECRET" | base64 -w0)

curl -s -X POST http://localhost:9090/revoke \
  -H "Authorization: Basic $AUTH" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=$ACCESS_TOKEN"
# Returns 200 OK with empty body
```

After revocation, introspecting the same token returns `{"active": false}`.

---

#### 10. Refresh Token Flow

If the `offline_access` scope was granted, a `refresh_token` is included in the token response.

```bash
AUTH=$(printf '%s:%s' "$CLIENT_ID" "$CLIENT_SECRET" | base64 -w0)

curl -s -X POST http://localhost:9090/token \
  -H "Authorization: Basic $AUTH" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token&refresh_token=$REFRESH_TOKEN" | jq .
```

Token rotation: the old refresh token is revoked and a new one is issued.
