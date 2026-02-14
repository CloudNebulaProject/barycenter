# Database Schema

Barycenter uses SeaORM for database access and supports both SQLite and PostgreSQL backends. The schema is defined through 12 entity tables managed by SeaORM migrations.

## Database Backend Detection

The database backend is automatically detected from the connection string:

- **SQLite**: `sqlite://barycenter.db?mode=rwc`
- **PostgreSQL**: `postgresql://user:password@localhost/barycenter`

No code changes are needed to switch backends. SeaORM generates compatible queries for both.

## Entity Tables

### `user`

Stores registered user accounts.

| Column | Type | Description |
|--------|------|-------------|
| `id` | TEXT (PK) | Unique user identifier (base64url-encoded random bytes) |
| `username` | TEXT (UNIQUE) | Login username |
| `password_hash` | TEXT | Argon2 password hash |
| `requires_2fa` | INTEGER | Whether admin-enforced 2FA is enabled (0 or 1) |
| `passkey_enrolled_at` | TIMESTAMP | When the user first enrolled a passkey (NULL if none) |
| `created_at` | TIMESTAMP | Account creation timestamp |
| `updated_at` | TIMESTAMP | Last modification timestamp |

### `client`

Stores OAuth 2.0 client registrations created through dynamic client registration.

| Column | Type | Description |
|--------|------|-------------|
| `id` | TEXT (PK) | Client ID (base64url-encoded random bytes) |
| `client_secret` | TEXT | Client secret for confidential clients |
| `redirect_uris` | TEXT | JSON array of registered redirect URIs |
| `client_name` | TEXT | Human-readable client name |
| `token_endpoint_auth_method` | TEXT | Authentication method (`client_secret_basic` or `client_secret_post`) |
| `grant_types` | TEXT | JSON array of allowed grant types |
| `response_types` | TEXT | JSON array of allowed response types |
| `created_at` | TIMESTAMP | Client registration timestamp |

### `auth_code`

Stores authorization codes issued during the authorization flow. Codes are single-use and short-lived.

| Column | Type | Description |
|--------|------|-------------|
| `id` | TEXT (PK) | Authorization code value (base64url-encoded random bytes) |
| `client_id` | TEXT (FK) | Client that requested the code |
| `subject` | TEXT | Authenticated user's subject identifier |
| `redirect_uri` | TEXT | Redirect URI used in the authorization request |
| `scope` | TEXT | Granted scope string |
| `code_challenge` | TEXT | PKCE S256 code challenge |
| `code_challenge_method` | TEXT | Always "S256" |
| `nonce` | TEXT | OpenID Connect nonce (if provided) |
| `consumed` | INTEGER | Whether the code has been used (0 or 1) |
| `created_at` | TIMESTAMP | Code issuance timestamp |
| `expires_at` | TIMESTAMP | Code expiration (5 minutes after creation) |

### `access_token`

Stores issued access tokens for API access.

| Column | Type | Description |
|--------|------|-------------|
| `id` | TEXT (PK) | Access token value (base64url-encoded random bytes) |
| `client_id` | TEXT (FK) | Client the token was issued to |
| `subject` | TEXT | User's subject identifier |
| `scope` | TEXT | Granted scope string |
| `revoked` | INTEGER | Whether the token has been revoked (0 or 1) |
| `created_at` | TIMESTAMP | Token issuance timestamp |
| `expires_at` | TIMESTAMP | Token expiration (1 hour after creation) |

### `refresh_token`

Stores refresh tokens for obtaining new access tokens without re-authentication.

| Column | Type | Description |
|--------|------|-------------|
| `id` | TEXT (PK) | Refresh token value (base64url-encoded random bytes) |
| `client_id` | TEXT (FK) | Client the token was issued to |
| `subject` | TEXT | User's subject identifier |
| `scope` | TEXT | Granted scope string |
| `access_token_id` | TEXT | Associated access token |
| `revoked` | INTEGER | Whether the token has been revoked (0 or 1) |
| `created_at` | TIMESTAMP | Token issuance timestamp |
| `expires_at` | TIMESTAMP | Token expiration timestamp |

### `session`

Stores server-side session data for authenticated users.

| Column | Type | Description |
|--------|------|-------------|
| `id` | TEXT (PK) | Session identifier (base64url-encoded random bytes) |
| `subject` | TEXT | Authenticated user's subject identifier |
| `amr` | TEXT | JSON array of Authentication Method References (e.g., `["pwd"]`, `["pwd", "hwk"]`) |
| `acr` | TEXT | Authentication Context Reference (`"aal1"` or `"aal2"`) |
| `mfa_verified` | INTEGER | Whether multi-factor authentication was completed (0 or 1) |
| `auth_time` | TIMESTAMP | When the user authenticated |
| `created_at` | TIMESTAMP | Session creation timestamp |
| `expires_at` | TIMESTAMP | Session expiration timestamp |

### `passkey`

Stores registered WebAuthn/FIDO2 passkey credentials.

| Column | Type | Description |
|--------|------|-------------|
| `id` | TEXT (PK) | Credential ID (base64url-encoded) |
| `user_id` | TEXT (FK) | User who owns this passkey |
| `name` | TEXT | User-assigned friendly name |
| `passkey_json` | TEXT | Full `Passkey` object serialized as JSON (includes public key, counter, backup state) |
| `created_at` | TIMESTAMP | Passkey registration timestamp |
| `last_used_at` | TIMESTAMP | Last successful authentication timestamp |

### `webauthn_challenge`

Temporary storage for WebAuthn challenge data during registration and authentication ceremonies.

| Column | Type | Description |
|--------|------|-------------|
| `id` | TEXT (PK) | Challenge identifier |
| `challenge_type` | TEXT | Type of ceremony (`registration`, `authentication`, `2fa`) |
| `challenge_data` | TEXT | Serialized challenge state (JSON) |
| `user_id` | TEXT | Associated user (NULL for authentication start) |
| `created_at` | TIMESTAMP | Challenge creation timestamp |
| `expires_at` | TIMESTAMP | Challenge expiration (5 minutes after creation) |

### `property`

Key-value store for arbitrary user properties.

| Column | Type | Description |
|--------|------|-------------|
| `id` | INTEGER (PK) | Auto-incrementing row ID |
| `owner` | TEXT | Property owner identifier |
| `key` | TEXT | Property key |
| `value` | TEXT | Property value |

The combination of `owner` and `key` is unique.

### `job_execution`

Tracks background job execution history for monitoring and debugging.

| Column | Type | Description |
|--------|------|-------------|
| `id` | INTEGER (PK) | Auto-incrementing row ID |
| `job_name` | TEXT | Name of the executed job |
| `started_at` | TIMESTAMP | Job start timestamp |
| `completed_at` | TIMESTAMP | Job completion timestamp |
| `success` | INTEGER | Whether the job succeeded (0 or 1) |
| `records_processed` | INTEGER | Number of records affected |
| `error_message` | TEXT | Error message if the job failed (NULL on success) |

### `consent`

Stores user consent decisions for OAuth client access.

| Column | Type | Description |
|--------|------|-------------|
| `id` | INTEGER (PK) | Auto-incrementing row ID |
| `subject` | TEXT | User's subject identifier |
| `client_id` | TEXT (FK) | Client that consent was granted to |
| `scope` | TEXT | Consented scope string |
| `created_at` | TIMESTAMP | Consent grant timestamp |
| `expires_at` | TIMESTAMP | Consent expiration timestamp (NULL for permanent) |

### `device_code`

Stores device authorization grant codes for the device flow (RFC 8628).

| Column | Type | Description |
|--------|------|-------------|
| `id` | TEXT (PK) | Device code value |
| `user_code` | TEXT (UNIQUE) | User-facing code for device verification |
| `client_id` | TEXT (FK) | Client that requested the device code |
| `scope` | TEXT | Requested scope string |
| `subject` | TEXT | User's subject identifier (NULL until user authorizes) |
| `status` | TEXT | Flow status (`pending`, `authorized`, `denied`, `expired`) |
| `created_at` | TIMESTAMP | Device code issuance timestamp |
| `expires_at` | TIMESTAMP | Device code expiration timestamp |

## SeaORM Patterns

### Entity Definitions

Entities are defined in the `src/entities/` directory. Each entity has a `Model` struct (representing a row), an `Entity` struct (representing the table), and `ActiveModel` (for inserts and updates):

```rust
// Example: Querying a client by ID
let client = client::Entity::find_by_id(client_id)
    .one(&state.db)
    .await?;

// Example: Inserting a new access token
let token = access_token::ActiveModel {
    id: Set(random_id()),
    client_id: Set(client_id.to_string()),
    subject: Set(subject.to_string()),
    scope: Set(scope.to_string()),
    revoked: Set(false),
    created_at: Set(now),
    expires_at: Set(now + Duration::hours(1)),
    ..Default::default()
};
token.insert(&state.db).await?;
```

### Database Connection

The `DatabaseConnection` type from SeaORM abstracts over both SQLite and PostgreSQL. The connection is established once at startup and shared via `AppState`.

## Migrations

Database migrations are located in `migration/src/` and run automatically on application startup via `Migrator::up()`. Each migration file defines an `up` method (apply the migration) and a `down` method (revert the migration).

Migration files follow the naming convention:

```
m20240101_000001_create_users_table.rs
m20240102_000001_create_clients_table.rs
...
```

To create a new migration:

```bash
cd migration
sea-orm-cli migrate generate create_new_table
```

Migrations are applied in lexicographic order by filename. Never modify an existing migration that has been deployed -- always create a new migration to make schema changes.
