# Configuration

Barycenter loads configuration from three sources, applied in order of increasing precedence:

1. **Default values** -- compiled into the binary.
2. **Configuration file** -- TOML format, default path `config.toml`. Override with the `--config` CLI flag.
3. **Environment variables** -- prefixed with `BARYCENTER__`, using double underscores as section separators.

Environment variables always take precedence over the configuration file, which in turn overrides defaults.

## CLI Arguments

| Flag | Short | Description |
|------|-------|-------------|
| `--config <path>` | `-c` | Path to the TOML configuration file. Defaults to `config.toml`. |

## Environment Variable Convention

Every configuration key can be set via an environment variable following this pattern:

```
BARYCENTER__{SECTION}__{KEY}
```

Section and key names are uppercased. Nested sections use double underscores as separators. For example:

| Config Key | Environment Variable |
|------------|---------------------|
| `server.port` | `BARYCENTER__SERVER__PORT` |
| `database.url` | `BARYCENTER__DATABASE__URL` |
| `keys.private_key_path` | `BARYCENTER__KEYS__PRIVATE_KEY_PATH` |
| `authz.policies_dir` | `BARYCENTER__AUTHZ__POLICIES_DIR` |

---

## `[server]`

Controls the public-facing HTTP server and its network binding.

| Key | Type | Default | Env Variable | Description |
|-----|------|---------|--------------|-------------|
| `host` | `String` | `"0.0.0.0"` | `BARYCENTER__SERVER__HOST` | IP address to bind the public server to. Use `127.0.0.1` to restrict to localhost. |
| `port` | `u16` | `8080` | `BARYCENTER__SERVER__PORT` | Port for the public OIDC/OAuth 2.0 server. |
| `public_base_url` | `Option<String>` | `None` | `BARYCENTER__SERVER__PUBLIC_BASE_URL` | The externally reachable base URL used as the OAuth issuer identifier. When set, this value is returned in discovery metadata and included in ID Token `iss` claims. When absent, the issuer is computed as `http://{host}:{port}`. |
| `allow_public_registration` | `bool` | `false` | `BARYCENTER__SERVER__ALLOW_PUBLIC_REGISTRATION` | When `true`, enables the `POST /register` endpoint for public user self-registration. Keep `false` in production unless you intend to allow open sign-up. |
| `admin_port` | `Option<u16>` | `None` | `BARYCENTER__SERVER__ADMIN_PORT` | Port for the admin GraphQL server. Defaults to `port + 1` (e.g., `8081` when the main port is `8080`). |

**Example:**

```toml
[server]
host = "0.0.0.0"
port = 8080
public_base_url = "https://idp.example.com"
allow_public_registration = false
admin_port = 8081
```

---

## `[database]`

Configures the database backend. Barycenter supports both SQLite and PostgreSQL. The backend is automatically detected from the connection string.

| Key | Type | Default | Env Variable | Description |
|-----|------|---------|--------------|-------------|
| `url` | `String` | `"sqlite://barycenter.db?mode=rwc"` | `BARYCENTER__DATABASE__URL` | Database connection string. Use `sqlite://` prefix for SQLite or `postgresql://` prefix for PostgreSQL. |

### SQLite

SQLite is the default and requires no external dependencies. The `?mode=rwc` query parameter creates the database file if it does not exist.

```toml
[database]
url = "sqlite://barycenter.db?mode=rwc"
```

### PostgreSQL

For production deployments, PostgreSQL is recommended.

```toml
[database]
url = "postgresql://barycenter:secret@localhost:5432/barycenter"
```

Or via environment variable:

```bash
export BARYCENTER__DATABASE__URL="postgresql://barycenter:secret@db.internal:5432/barycenter"
```

Tables and schema migrations are applied automatically on startup.

---

## `[keys]`

Controls cryptographic key material used for signing JWTs (ID Tokens).

| Key | Type | Default | Env Variable | Description |
|-----|------|---------|--------------|-------------|
| `jwks_path` | `PathBuf` | `"data/jwks.json"` | `BARYCENTER__KEYS__JWKS_PATH` | File path where the public JSON Web Key Set is written. This file is served at `/.well-known/jwks.json`. |
| `private_key_path` | `PathBuf` | `"data/private_key.pem"` | `BARYCENTER__KEYS__PRIVATE_KEY_PATH` | File path where the private signing key is persisted as JSON. Generated automatically on first run if the file does not exist. |
| `key_id` | `Option<String>` | `None` | `BARYCENTER__KEYS__KEY_ID` | The `kid` (Key ID) value included in JWT headers and the JWKS. When absent, a `kid` is derived automatically. |
| `alg` | `String` | `"RS256"` | `BARYCENTER__KEYS__ALG` | The signing algorithm for ID Tokens. Currently only `RS256` is supported. |

**Key Generation Behavior:**

On first startup, if `private_key_path` does not exist, Barycenter generates a 2048-bit RSA key pair. The private key is saved to `private_key_path` and the public key set is written to `jwks_path`. On subsequent startups, the existing keys are loaded.

**Example:**

```toml
[keys]
jwks_path = "data/jwks.json"
private_key_path = "data/private_key.pem"
alg = "RS256"
```

> **Important:** Protect the private key file. Anyone with access to it can forge ID Tokens that will be accepted by relying parties trusting this provider.

---

## `[federation]`

Configures OpenID Federation trust chain resolution. This feature is not yet fully implemented.

| Key | Type | Default | Env Variable | Description |
|-----|------|---------|--------------|-------------|
| `trust_anchors` | `Vec<String>` | `[]` | `BARYCENTER__FEDERATION__TRUST_ANCHORS` | List of trust anchor entity URLs for OpenID Federation. These are the root authorities in the federation trust chain. |

**Example:**

```toml
[federation]
trust_anchors = [
  "https://federation.example.com",
  "https://trust.academic.edu"
]
```

---

## `[authz]`

Configures the optional authorization policy server that provides Relationship-Based Access Control (ReBAC) evaluation.

| Key | Type | Default | Env Variable | Description |
|-----|------|---------|--------------|-------------|
| `enabled` | `bool` | `false` | `BARYCENTER__AUTHZ__ENABLED` | When `true`, starts the authorization policy server on a separate port. |
| `port` | `Option<u16>` | `None` | `BARYCENTER__AUTHZ__PORT` | Port for the authorization policy server. Defaults to `server.port + 2` (e.g., `8082` when the main port is `8080`). |
| `policies_dir` | `PathBuf` | `"policies"` | `BARYCENTER__AUTHZ__POLICIES_DIR` | Directory containing authorization policy definition files. |

**Example:**

```toml
[authz]
enabled = true
port = 8082
policies_dir = "policies"
```

---

## Complete Configuration Example

Below is a full `config.toml` showing all settings with their default values:

```toml
[server]
host = "0.0.0.0"
port = 8080
# public_base_url = "https://idp.example.com"
allow_public_registration = false
# admin_port = 8081

[database]
url = "sqlite://barycenter.db?mode=rwc"

[keys]
jwks_path = "data/jwks.json"
private_key_path = "data/private_key.pem"
# key_id = "my-key-id"
alg = "RS256"

[federation]
trust_anchors = []

[authz]
enabled = false
# port = 8082
policies_dir = "policies"
```

## Production Recommendations

- Set `public_base_url` to your externally reachable HTTPS URL. This value becomes the `iss` claim in all ID Tokens and must remain stable.
- Use PostgreSQL for production workloads by setting `database.url` to a `postgresql://` connection string.
- Keep `allow_public_registration = false` unless open sign-up is an intentional feature of your deployment.
- Bind the admin server to a private network or restrict access via firewall rules. The admin API has no built-in authentication.
- Store key files (`private_key_path`, `jwks_path`) in a directory with restricted filesystem permissions.
- Use environment variables for secrets (database passwords, key paths) to avoid committing them to version control.
