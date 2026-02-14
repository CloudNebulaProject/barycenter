# API Endpoints

Barycenter exposes three independent HTTP servers, each serving a distinct purpose. The public server handles all OIDC and OAuth 2.0 protocol traffic. The admin server provides GraphQL-based management interfaces. The optional authorization policy server evaluates permission checks.

## Public Server

**Default port:** `8080` (configurable via `server.port`)

### Discovery and Registration

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/.well-known/openid-configuration` | None | Returns OpenID Provider metadata as JSON. Includes all supported endpoints, response types, signing algorithms, and grant types. |
| `GET` | `/.well-known/jwks.json` | None | Returns the JSON Web Key Set containing the provider's public signing keys. Clients use these keys to verify ID Token signatures. |
| `POST` | `/connect/register` | None | Dynamic client registration per [RFC 7591](https://www.rfc-editor.org/rfc/rfc7591). Accepts a JSON body with client metadata and returns credentials. |

#### `POST /connect/register`

**Request:**

```http
POST /connect/register HTTP/1.1
Content-Type: application/json

{
  "redirect_uris": ["https://app.example.com/callback"],
  "client_name": "My Application"
}
```

**Response:**

```http
HTTP/1.1 201 Created
Content-Type: application/json

{
  "client_id": "...",
  "client_secret": "...",
  "redirect_uris": ["https://app.example.com/callback"],
  "client_name": "My Application"
}
```

---

### OAuth 2.0 / OIDC Protocol

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/authorize` | None | Authorization endpoint. Initiates the Authorization Code flow with PKCE. Redirects the user to login if no session exists. |
| `POST` | `/token` | Client auth | Token endpoint. Exchanges authorization codes, refresh tokens, or device codes for access tokens and ID tokens. |
| `POST` | `/revoke` | Client auth | Token revocation endpoint. Invalidates an access token or refresh token. |
| `GET` | `/userinfo` | Bearer token | UserInfo endpoint. Returns claims about the authenticated user based on the granted scopes. |

#### `GET /authorize`

Initiates the authorization flow. Only the `code` response type with PKCE S256 is required; implicit flows (`id_token`, `id_token token`) are also supported.

**Query Parameters:**

| Parameter | Required | Description |
|-----------|----------|-------------|
| `client_id` | Yes | The registered client identifier. |
| `redirect_uri` | Yes | Must match a URI registered for the client. |
| `response_type` | Yes | `code`, `id_token`, or `id_token token`. |
| `scope` | Yes | Space-separated scopes. Must include `openid`. |
| `code_challenge` | Yes (for `code`) | Base64url-encoded SHA-256 hash of the code verifier. |
| `code_challenge_method` | Yes (for `code`) | Must be `S256`. Plain is rejected. |
| `state` | Recommended | Opaque value returned in the redirect for CSRF protection. |
| `nonce` | Optional | Opaque value included in the ID Token for replay protection. |
| `max_age` | Optional | Maximum authentication age in seconds. Values below 300 trigger 2FA. |
| `prompt` | Optional | `none`, `login`, or `consent`. Controls the authentication UX. |

**Success Response:** HTTP 302 redirect to `redirect_uri` with `code` and `state` query parameters.

**Error Response:** HTTP 302 redirect to `redirect_uri` with `error`, `error_description`, and `state` query parameters.

#### `POST /token`

**Client Authentication Methods:**

- **`client_secret_basic`**: HTTP Basic authentication with `client_id:client_secret` base64-encoded in the `Authorization` header.
- **`client_secret_post`**: `client_id` and `client_secret` sent as form parameters in the request body.

**Grant Type: `authorization_code`**

```http
POST /token HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Authorization: Basic base64(client_id:client_secret)

grant_type=authorization_code
&code=AUTH_CODE
&redirect_uri=https://app.example.com/callback
&code_verifier=PKCE_VERIFIER
```

**Grant Type: `refresh_token`**

```http
POST /token HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Authorization: Basic base64(client_id:client_secret)

grant_type=refresh_token
&refresh_token=REFRESH_TOKEN
```

**Grant Type: `urn:ietf:params:oauth:grant-type:device_code`**

```http
POST /token HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Authorization: Basic base64(client_id:client_secret)

grant_type=urn:ietf:params:oauth:grant-type:device_code
&device_code=DEVICE_CODE
```

**Success Response:**

```json
{
  "access_token": "...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "...",
  "id_token": "..."
}
```

#### `POST /revoke`

Revokes an access token or refresh token. The request uses the same client authentication methods as the token endpoint.

```http
POST /revoke HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Authorization: Basic base64(client_id:client_secret)

token=TOKEN_VALUE
&token_type_hint=access_token
```

Returns HTTP 200 with an empty body on success, regardless of whether the token was valid.

#### `GET /userinfo`

```http
GET /userinfo HTTP/1.1
Authorization: Bearer ACCESS_TOKEN
```

**Response:**

```json
{
  "sub": "user-subject-uuid",
  "name": "alice",
  "email": "alice@example.com"
}
```

---

### Device Authorization Grant

Implements [RFC 8628](https://www.rfc-editor.org/rfc/rfc8628) for input-constrained devices such as smart TVs and CLI tools.

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/device_authorization` | None | Initiates the device flow. Returns a `device_code`, `user_code`, and `verification_uri`. |
| `GET` | `/device` | None | Renders the device verification page where the user enters the `user_code`. |
| `POST` | `/device/verify` | Session | Verifies the user code and associates it with the authenticated session. |
| `POST` | `/device/consent` | Session | Records the user's consent decision for the device flow. |

#### `POST /device_authorization`

```http
POST /device_authorization HTTP/1.1
Content-Type: application/x-www-form-urlencoded

client_id=CLIENT_ID
&scope=openid profile
```

**Response:**

```json
{
  "device_code": "...",
  "user_code": "ABCD-1234",
  "verification_uri": "https://idp.example.com/device",
  "verification_uri_complete": "https://idp.example.com/device?user_code=ABCD-1234",
  "expires_in": 600,
  "interval": 5
}
```

The client polls `POST /token` with `grant_type=urn:ietf:params:oauth:grant-type:device_code` at the specified `interval` until the user completes verification.

---

### Authentication

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/login` | None | Renders the login page with passkey autofill and password fallback. |
| `POST` | `/login` | None | Processes password authentication. Creates a session on success. |
| `GET` | `/login/2fa` | Session (partial) | Renders the second-factor authentication page. |
| `GET` | `/logout` | Session | Ends the user session and clears the session cookie. |
| `POST` | `/register` | None | Public user self-registration. Only available when `server.allow_public_registration` is `true`. |

#### Consent

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/consent` | Session | Renders the consent page showing requested scopes and client information. |
| `POST` | `/consent` | Session | Records the user's consent decision. On approval, redirects back to the authorization flow. |

---

### WebAuthn / Passkey

All WebAuthn endpoints exchange JSON payloads conforming to the [Web Authentication API](https://www.w3.org/TR/webauthn-3/).

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/webauthn/register/start` | Session | Begins passkey registration. Returns `PublicKeyCredentialCreationOptions`. |
| `POST` | `/webauthn/register/finish` | Session | Completes passkey registration with the authenticator response. |
| `POST` | `/webauthn/authenticate/start` | None | Begins passkey authentication. Returns `PublicKeyCredentialRequestOptions`. |
| `POST` | `/webauthn/authenticate/finish` | None | Completes passkey authentication and creates a session. |
| `POST` | `/webauthn/2fa/start` | Session (partial) | Begins second-factor passkey verification. Requires a partial session from password login. |
| `POST` | `/webauthn/2fa/finish` | Session (partial) | Completes second-factor verification. Upgrades the session to `mfa_verified=1`. |

---

### Passkey Management

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/account/passkeys` | Session | Lists all passkeys registered to the authenticated user. |
| `DELETE` | `/account/passkeys/{credential_id}` | Session | Deletes a specific passkey by its credential ID. |
| `PATCH` | `/account/passkeys/{credential_id}` | Session | Updates the friendly name of a passkey. |

#### `PATCH /account/passkeys/{credential_id}`

```http
PATCH /account/passkeys/abc123 HTTP/1.1
Content-Type: application/json

{
  "friendly_name": "YubiKey 5 NFC"
}
```

---

### Properties

A simple key-value store for arbitrary metadata associated with an owner.

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/properties/{owner}/{key}` | None | Returns the value for the given owner and key. |
| `PUT` | `/properties/{owner}/{key}` | None | Creates or updates the value for the given owner and key. |

---

### Federation

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/federation/trust-anchors` | None | Returns the list of configured OpenID Federation trust anchor URLs. |

---

## Admin Server

**Default port:** `8081` (main port + 1, configurable via `server.admin_port`)

The admin server provides two independent GraphQL APIs served on the same port. Neither requires authentication; restrict access at the network level.

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/admin/graphql` | None | Seaography entity CRUD API. Supports queries and mutations on all database entities. |
| `GET` | `/admin/playground` | None | GraphiQL interactive explorer for the entity CRUD API. |
| `POST` | `/admin/jobs` | None | Job management GraphQL API. Trigger background jobs and query execution history. |
| `GET` | `/admin/jobs/playground` | None | GraphiQL interactive explorer for the job management API. |

### Entity CRUD API (`/admin/graphql`)

The Seaography-generated API provides full CRUD operations on all database entities. Use the GraphiQL playground at `/admin/playground` to explore available queries and mutations.

### Job Management API (`/admin/jobs`)

**Available Jobs:**

| Job Name | Schedule | Description |
|----------|----------|-------------|
| `cleanup_expired_sessions` | Hourly at :00 | Removes sessions past their `expires_at` timestamp. |
| `cleanup_expired_refresh_tokens` | Hourly at :30 | Removes expired and revoked refresh tokens. |
| `cleanup_expired_challenges` | Every 5 minutes | Removes expired WebAuthn challenge records. |

**Example: Trigger a Job**

```graphql
mutation {
  triggerJob(jobName: "cleanup_expired_sessions") {
    success
    message
  }
}
```

**Example: Query Job History**

```graphql
query {
  jobLogs(limit: 10, onlyFailures: false) {
    id
    jobName
    startedAt
    completedAt
    success
    recordsProcessed
  }
}
```

**Example: Query User 2FA Status**

```graphql
query {
  user2faStatus(username: "alice") {
    username
    requires2fa
    passkeyEnrolled
    passkeyCount
    passkeyEnrolledAt
  }
}
```

**Example: Enforce 2FA for a User**

```graphql
mutation {
  setUser2faRequired(username: "alice", required: true) {
    success
    message
    requires2fa
  }
}
```

---

## Authorization Policy Server

**Default port:** `8082` (main port + 2, configurable via `authz.port`)

This server is only started when `authz.enabled = true`. It provides a Relationship-Based Access Control (ReBAC) evaluation API.

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/v1/check` | None | Evaluates whether a subject has a specific permission on a resource. |
| `POST` | `/v1/expand` | None | Expands a permission to enumerate all subjects that hold it on a resource. |
| `GET` | `/healthz` | None | Returns HTTP 200 if the authorization server is healthy. |

#### `POST /v1/check`

```http
POST /v1/check HTTP/1.1
Content-Type: application/json

{
  "namespace": "documents",
  "object": "doc:readme",
  "relation": "viewer",
  "subject": "user:alice"
}
```

**Response:**

```json
{
  "allowed": true
}
```

#### `POST /v1/expand`

```http
POST /v1/expand HTTP/1.1
Content-Type: application/json

{
  "namespace": "documents",
  "object": "doc:readme",
  "relation": "viewer"
}
```

**Response:**

```json
{
  "subjects": ["user:alice", "user:bob", "group:engineering#member"]
}
```
