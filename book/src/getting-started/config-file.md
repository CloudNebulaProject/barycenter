# Configuration File

Barycenter reads its configuration from a TOML file. By default it looks for `config.toml` in the working directory, or you can specify a path with `--config`.

## Full Annotated Example

```toml
# =============================================================================
# Server Configuration
# =============================================================================
[server]
# Address to bind to. Use "0.0.0.0" to listen on all interfaces.
# Default: "127.0.0.1"
host = "0.0.0.0"

# Port for the public OIDC server.
# The admin GraphQL server runs on port+1 (e.g., 8081).
# The authorization policy server runs on port+2 (e.g., 8082).
# Default: 8080
port = 8080

# The public URL where this server is reachable by clients and browsers.
# Used as the OIDC issuer identifier. Must not include a trailing slash.
# If not set, the issuer is constructed as http://{host}:{port}.
# Default: not set
public_base_url = "https://id.example.com"

# Whether to allow unauthenticated dynamic client registration at
# POST /connect/register. Set to false in production if you want to
# control client registration through other means.
# Default: true
allow_public_registration = true

# Port for the admin GraphQL API server. If not set, defaults to port+1.
# Default: not set (auto-derived from port)
# admin_port = 8081

# =============================================================================
# Database Configuration
# =============================================================================
[database]
# Database connection string. Barycenter auto-detects the backend from the URL.
#
# SQLite:     sqlite://path/to/database.db?mode=rwc
# PostgreSQL: postgresql://user:password@host:port/dbname
#
# The ?mode=rwc flag for SQLite means read-write-create: the file is created
# if it does not already exist.
#
# Default: "sqlite://data/barycenter.db?mode=rwc"
url = "sqlite://data/barycenter.db?mode=rwc"

# =============================================================================
# Key Configuration
# =============================================================================
[keys]
# Path to the JWKS (JSON Web Key Set) file containing the public key(s).
# This file is published at /.well-known/jwks.json.
# Default: "data/jwks.json"
jwks_path = "data/jwks.json"

# Path to the RSA private key in PEM format. Generated automatically on
# first run if it does not exist. Used for signing ID tokens.
# Default: "data/private_key.pem"
private_key_path = "data/private_key.pem"

# Key ID included in the JWT header. Must match the kid in the JWKS.
# Default: "barycenter-key-1"
key_id = "barycenter-key-1"

# Signing algorithm. Currently only RS256 is supported.
# Default: "RS256"
alg = "RS256"

# =============================================================================
# Federation Configuration
# =============================================================================
[federation]
# List of OpenID Federation trust anchor URLs.
# Used for future trust chain validation. Currently informational.
# Default: []
trust_anchors = []

# =============================================================================
# Authorization Policy Configuration
# =============================================================================
[authz]
# Enable or disable the authorization policy server.
# When disabled, the authz port is not opened.
# Default: false
enabled = false

# Port for the authorization policy server. If not set, defaults to port+2.
# Default: not set (auto-derived from server port)
# port = 8082

# Directory containing KDL policy definition files.
# Policies are loaded from all .kdl files in this directory.
# Default: "policies/"
policies_dir = "policies/"
```

## Section Reference

### `[server]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `host` | String | `"127.0.0.1"` | Bind address |
| `port` | Integer | `8080` | Public server port |
| `public_base_url` | String | *none* | Public URL / OIDC issuer |
| `allow_public_registration` | Boolean | `true` | Allow unauthenticated client registration |
| `admin_port` | Integer | `port + 1` | Admin GraphQL server port |

### `[database]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `url` | String | `"sqlite://data/barycenter.db?mode=rwc"` | Database connection string |

### `[keys]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `jwks_path` | String | `"data/jwks.json"` | Path to public JWKS file |
| `private_key_path` | String | `"data/private_key.pem"` | Path to RSA private key |
| `key_id` | String | `"barycenter-key-1"` | Key ID for JWT header |
| `alg` | String | `"RS256"` | Signing algorithm |

### `[federation]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `trust_anchors` | Array of Strings | `[]` | Trust anchor URLs |

### `[authz]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | Boolean | `false` | Enable the authz policy server |
| `port` | Integer | `port + 2` | Authz server port |
| `policies_dir` | String | `"policies/"` | KDL policy files directory |

## Issuer URL Logic

The OIDC issuer identifier is determined as follows:

1. If `server.public_base_url` is set, use that value (with any trailing slash removed).
2. Otherwise, construct the issuer as `http://{host}:{port}`.

The issuer appears in:
- The `iss` claim of all ID tokens
- The `issuer` field in `/.well-known/openid-configuration`
- Various OIDC metadata endpoints

For production deployments, always set `public_base_url` to the externally-reachable HTTPS URL of your Barycenter instance.

## Minimal Production Configuration

```toml
[server]
host = "0.0.0.0"
port = 8080
public_base_url = "https://id.example.com"
allow_public_registration = false

[database]
url = "postgresql://barycenter:secret@db.internal:5432/barycenter"

[keys]
jwks_path = "/var/lib/barycenter/jwks.json"
private_key_path = "/var/lib/barycenter/private_key.pem"
```
