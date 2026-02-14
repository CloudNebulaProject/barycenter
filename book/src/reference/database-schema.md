# Database Schema

Barycenter uses SeaORM for database access and supports both SQLite and PostgreSQL backends. All tables are created automatically on startup. This reference documents all 12 tables, their columns, types, and constraints.

Column types are shown using their logical Rust/SeaORM types. The actual SQL types differ slightly between SQLite and PostgreSQL but are handled transparently by SeaORM.

---

## users

Stores registered user accounts. Passwords are hashed with argon2.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | `i32` | Primary key, auto-increment | Internal row identifier. |
| `subject` | `String` | Unique, not null | Stable UUID assigned at creation. Used as the `sub` claim in tokens and as the foreign key in related tables. |
| `username` | `String` | Unique, not null | Human-readable login name. Must be unique across all users. |
| `password_hash` | `String` | Not null | Argon2-hashed password. Never stored or transmitted in plaintext. |
| `email` | `Option<String>` | Nullable | User email address. Returned in UserInfo when the `email` scope is granted. |
| `requires_2fa` | `i32` | Not null, default `0` | Admin-enforced two-factor authentication flag. `0` = not required, `1` = required. When set, password login creates only a partial session that must be upgraded via 2FA. |
| `passkey_enrolled_at` | `Option<DateTime>` | Nullable | Timestamp of when the user first registered a passkey. `NULL` if no passkeys are enrolled. |
| `created_at` | `DateTime` | Not null | Timestamp of account creation. |

---

## clients

Stores OAuth 2.0 client registrations created via dynamic registration or the admin API.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | `i32` | Primary key, auto-increment | Internal row identifier. |
| `client_id` | `String` | Unique, not null | Public client identifier. Generated as a base64url-encoded random value (24 bytes). |
| `client_secret` | `String` | Not null | Client secret for confidential clients. Generated as a base64url-encoded random value (24 bytes). |
| `redirect_uris` | `String` | Not null | JSON array of registered redirect URIs. The authorization endpoint validates that the requested `redirect_uri` matches one of these values exactly. |
| `client_name` | `Option<String>` | Nullable | Human-readable client name. Displayed on the consent page. |
| `created_at` | `DateTime` | Not null | Timestamp of client registration. |

---

## auth_codes

Stores authorization codes issued during the Authorization Code flow. Codes are single-use and short-lived (5-minute TTL).

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | `i32` | Primary key, auto-increment | Internal row identifier. |
| `code` | `String` | Unique, not null | The authorization code value. Base64url-encoded random value (24 bytes). |
| `client_id` | `String` | Not null | The client that requested this code. |
| `redirect_uri` | `String` | Not null | The redirect URI bound to this code. Must match during token exchange. |
| `scope` | `String` | Not null | Space-separated list of granted scopes. |
| `subject` | `String` | Not null | The authenticated user's subject identifier. |
| `nonce` | `Option<String>` | Nullable | Client-provided nonce value. Included in the ID Token if present. |
| `code_challenge` | `String` | Not null | PKCE code challenge (base64url-encoded SHA-256 hash). |
| `code_challenge_method` | `String` | Not null | PKCE challenge method. Always `S256`. |
| `expires_at` | `DateTime` | Not null | Expiration timestamp. Codes are valid for 5 minutes from issuance. |
| `consumed` | `bool` | Not null, default `false` | Set to `true` when the code is exchanged at the token endpoint. Prevents replay. |
| `auth_time` | `DateTime` | Not null | Timestamp of the user's authentication event. Carried into the ID Token as the `auth_time` claim. |

---

## access_tokens

Stores bearer access tokens issued by the token endpoint.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | `i32` | Primary key, auto-increment | Internal row identifier. |
| `token` | `String` | Unique, not null | The access token value. Base64url-encoded random value (24 bytes). |
| `client_id` | `String` | Not null | The client this token was issued to. |
| `subject` | `String` | Not null | The user's subject identifier. |
| `scope` | `String` | Not null | Space-separated list of granted scopes. |
| `expires_at` | `DateTime` | Not null | Expiration timestamp. Tokens are valid for 1 hour from issuance. |
| `revoked` | `bool` | Not null, default `false` | Set to `true` when the token is revoked via the revocation endpoint. |
| `created_at` | `DateTime` | Not null | Timestamp of token issuance. |

---

## refresh_tokens

Stores refresh tokens. Supports rotation: when a refresh token is used, the old token is revoked and a new one is issued.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | `i32` | Primary key, auto-increment | Internal row identifier. |
| `token` | `String` | Unique, not null | The refresh token value. Base64url-encoded random value (24 bytes). |
| `client_id` | `String` | Not null | The client this token was issued to. |
| `subject` | `String` | Not null | The user's subject identifier. |
| `scope` | `String` | Not null | Space-separated list of granted scopes. |
| `expires_at` | `DateTime` | Not null | Expiration timestamp. |
| `revoked` | `bool` | Not null, default `false` | Set to `true` when the token is rotated or explicitly revoked. |
| `parent_token` | `Option<String>` | Nullable | The token that was exchanged to produce this one. Forms a chain for rotation tracking. |
| `created_at` | `DateTime` | Not null | Timestamp of token issuance. |

---

## sessions

Stores user sessions. Tracks authentication methods, context level, and MFA status.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | `i32` | Primary key, auto-increment | Internal row identifier. |
| `session_id` | `String` | Unique, not null | Session identifier stored in the user's cookie. Base64url-encoded random value. |
| `subject` | `String` | Not null | The authenticated user's subject identifier. |
| `auth_time` | `DateTime` | Not null | Timestamp of the initial authentication event for this session. |
| `expires_at` | `DateTime` | Not null | Session expiration timestamp. |
| `amr` | `Option<String>` | Nullable | JSON array of Authentication Method Reference values (e.g., `["pwd"]`, `["hwk"]`, `["pwd", "hwk"]`). |
| `acr` | `Option<String>` | Nullable | Authentication Context Class Reference. `"aal1"` for single-factor, `"aal2"` for two-factor. |
| `mfa_verified` | `i32` | Not null, default `0` | Multi-factor authentication status. `0` = single-factor only (partial session), `1` = MFA verified (full session). |

---

## passkeys

Stores registered WebAuthn/FIDO2 passkeys for users.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | `i32` | Primary key, auto-increment | Internal row identifier. |
| `subject` | `String` | Not null | The user's subject identifier. A user can have multiple passkeys. |
| `credential_id` | `String` | Unique, not null | Base64url-encoded credential identifier assigned by the authenticator. Used to look up the passkey during authentication. |
| `passkey_json` | `String` | Not null | The full `Passkey` object serialized as JSON. Contains the public key, credential ID, and authenticator metadata needed for verification. |
| `friendly_name` | `Option<String>` | Nullable | User-assigned name for this passkey (e.g., "YubiKey 5 NFC", "iCloud Keychain"). |
| `created_at` | `DateTime` | Not null | Timestamp of passkey registration. |
| `last_used_at` | `Option<DateTime>` | Nullable | Timestamp of the most recent successful authentication with this passkey. |
| `sign_count` | `i32` | Not null | Signature counter reported by the authenticator. Incremented on each use. A counter that does not increment may indicate a cloned authenticator. |
| `backup_state` | `bool` | Not null | Whether the passkey is backed up to a cloud service (e.g., iCloud Keychain, Google Password Manager). `true` = cloud-synced (software key), `false` = hardware-bound. Determines whether the AMR value is `"swk"` or `"hwk"`. |

---

## webauthn_challenges

Temporary storage for WebAuthn challenge data during registration and authentication ceremonies. Records expire after 5 minutes and are cleaned up by a background job.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | `i32` | Primary key, auto-increment | Internal row identifier. |
| `challenge_id` | `String` | Unique, not null | Identifier linking the challenge to the client session. |
| `challenge_data` | `String` | Not null | JSON-serialized challenge state. Contains the cryptographic challenge and associated metadata needed to verify the authenticator response. |
| `created_at` | `DateTime` | Not null | Timestamp of challenge creation. |
| `expires_at` | `DateTime` | Not null | Expiration timestamp. Challenges are valid for 5 minutes. |

---

## properties

A general-purpose key-value store. Each entry is scoped to an owner.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | `i32` | Primary key, auto-increment | Internal row identifier. |
| `owner` | `String` | Not null | The owner namespace for this property. |
| `key` | `String` | Not null | The property key within the owner's namespace. |
| `value` | `String` | Not null | The property value. |

**Unique constraint:** `(owner, key)` -- each owner can have at most one value per key.

---

## job_executions

Audit log of background job runs. Records when each job started, completed, and whether it succeeded.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | `i32` | Primary key, auto-increment | Internal row identifier. |
| `job_name` | `String` | Not null | Name of the job that was executed (e.g., `cleanup_expired_sessions`). |
| `started_at` | `DateTime` | Not null | Timestamp when the job execution began. |
| `completed_at` | `Option<DateTime>` | Nullable | Timestamp when the job execution finished. `NULL` if the job is still running or crashed. |
| `success` | `i32` | Not null | Result of the execution. `1` = success, `0` = failure. |
| `error_message` | `Option<String>` | Nullable | Error description if the job failed. `NULL` on success. |
| `records_processed` | `Option<i32>` | Nullable | Number of records affected by the job (e.g., number of expired sessions deleted). |

---

## consents

Records user consent decisions. When a user approves a client's request for specific scopes, a consent record is created. Subsequent authorization requests for the same client, user, and scope combination skip the consent prompt.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | `i32` | Primary key, auto-increment | Internal row identifier. |
| `client_id` | `String` | Not null | The client that was granted consent. |
| `subject` | `String` | Not null | The user who granted consent. |
| `scope` | `String` | Not null | The specific scope that was consented to. Each scope is stored as a separate row. |
| `granted_at` | `DateTime` | Not null | Timestamp when consent was granted. |

**Unique constraint:** `(client_id, subject, scope)` -- prevents duplicate consent records for the same combination.

---

## device_codes

Stores device authorization requests for the Device Authorization Grant ([RFC 8628](https://www.rfc-editor.org/rfc/rfc8628)). Each record tracks the lifecycle of a single device flow from initiation through user verification to approval or denial.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | `i32` | Primary key, auto-increment | Internal row identifier. |
| `device_code` | `String` | Unique, not null | The device code used by the client to poll the token endpoint. Base64url-encoded random value. |
| `user_code` | `String` | Unique, not null | The short, human-readable code displayed to the user (e.g., `ABCD-1234`). The user enters this at the verification URI. |
| `client_id` | `String` | Not null | The client that initiated the device flow. |
| `scope` | `String` | Not null | Space-separated list of requested scopes. |
| `expires_at` | `DateTime` | Not null | Expiration timestamp for the device code. Typically 10 minutes from issuance. |
| `interval` | `i32` | Not null | Minimum polling interval in seconds that the client must respect when polling the token endpoint. |
| `status` | `String` | Not null, default `"pending"` | Current state of the device flow. One of: `pending` (awaiting user action), `approved` (user authorized), `denied` (user denied). |
| `subject` | `Option<String>` | Nullable | The authenticated user's subject identifier. Set when the user approves the device flow. `NULL` while pending or if denied. |
| `created_at` | `DateTime` | Not null | Timestamp of when the device authorization request was created. |

---

## Entity Relationships

The following diagram summarizes the key relationships between tables:

```
users (subject)
 |
 |-- 1:N -- sessions (subject)
 |-- 1:N -- passkeys (subject)
 |-- 1:N -- auth_codes (subject)
 |-- 1:N -- access_tokens (subject)
 |-- 1:N -- refresh_tokens (subject)
 |-- 1:N -- consents (subject)
 |-- 1:N -- device_codes (subject)
 |
clients (client_id)
 |
 |-- 1:N -- auth_codes (client_id)
 |-- 1:N -- access_tokens (client_id)
 |-- 1:N -- refresh_tokens (client_id)
 |-- 1:N -- consents (client_id)
 |-- 1:N -- device_codes (client_id)

refresh_tokens.parent_token --> refresh_tokens.token  (self-referential chain)
```

All foreign key relationships use the `subject` (for users) and `client_id` (for clients) string columns rather than integer IDs. This allows token and session records to reference users and clients by their stable external identifiers.
