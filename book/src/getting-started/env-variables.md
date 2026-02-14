# Environment Variables

All Barycenter configuration values can be overridden using environment variables. This is particularly useful for containerized deployments and CI/CD pipelines where you want to avoid mounting configuration files.

## Naming Convention

Environment variables use the prefix `BARYCENTER__` (with double underscores) and map to the TOML configuration hierarchy using `__` as a separator for nested keys.

The pattern is:

```
BARYCENTER__{SECTION}__{KEY}
```

For example, the TOML key `server.port` becomes `BARYCENTER__SERVER__PORT`.

## Precedence

Configuration values are resolved in this order (later sources override earlier ones):

```
Built-in defaults  <  config.toml  <  Environment variables
```

An environment variable **always wins** over the same key in the configuration file. This lets you set base configuration in a file and override specific values per environment.

## Common Examples

### Server Settings

```bash
# Change the listen port
export BARYCENTER__SERVER__PORT=9090

# Set the public-facing URL (used as OIDC issuer)
export BARYCENTER__SERVER__PUBLIC_BASE_URL=https://id.example.com

# Bind to all interfaces
export BARYCENTER__SERVER__HOST=0.0.0.0

# Disable public client registration
export BARYCENTER__SERVER__ALLOW_PUBLIC_REGISTRATION=false
```

### Database

```bash
# Use PostgreSQL
export BARYCENTER__DATABASE__URL="postgresql://barycenter:secret@localhost:5432/barycenter"

# Use SQLite with an explicit path
export BARYCENTER__DATABASE__URL="sqlite:///var/lib/barycenter/data.db?mode=rwc"
```

### Key Paths

```bash
export BARYCENTER__KEYS__JWKS_PATH="/var/lib/barycenter/jwks.json"
export BARYCENTER__KEYS__PRIVATE_KEY_PATH="/var/lib/barycenter/private_key.pem"
export BARYCENTER__KEYS__KEY_ID="my-custom-key-id"
```

### Authorization Policy Engine

```bash
export BARYCENTER__AUTHZ__ENABLED=true
export BARYCENTER__AUTHZ__POLICIES_DIR="/etc/barycenter/policies"
```

## Logging

Logging is controlled by the standard `RUST_LOG` environment variable, **not** through the `BARYCENTER__` prefix. Barycenter uses the Rust `tracing` ecosystem.

```bash
# Show info-level logs from Barycenter, warn from dependencies
export RUST_LOG=barycenter=info

# Verbose debug output for everything
export RUST_LOG=debug

# Trace-level logging for the Barycenter crate only
export RUST_LOG=barycenter=trace

# Multiple filters
export RUST_LOG=barycenter=debug,sea_orm=info,axum=warn
```

## Complete Mapping Reference

| Environment Variable | TOML Key | Default |
|---------------------|----------|---------|
| `BARYCENTER__SERVER__HOST` | `server.host` | `127.0.0.1` |
| `BARYCENTER__SERVER__PORT` | `server.port` | `8080` |
| `BARYCENTER__SERVER__PUBLIC_BASE_URL` | `server.public_base_url` | *none* |
| `BARYCENTER__SERVER__ALLOW_PUBLIC_REGISTRATION` | `server.allow_public_registration` | `true` |
| `BARYCENTER__SERVER__ADMIN_PORT` | `server.admin_port` | `port + 1` |
| `BARYCENTER__DATABASE__URL` | `database.url` | `sqlite://data/barycenter.db?mode=rwc` |
| `BARYCENTER__KEYS__JWKS_PATH` | `keys.jwks_path` | `data/jwks.json` |
| `BARYCENTER__KEYS__PRIVATE_KEY_PATH` | `keys.private_key_path` | `data/private_key.pem` |
| `BARYCENTER__KEYS__KEY_ID` | `keys.key_id` | `barycenter-key-1` |
| `BARYCENTER__KEYS__ALG` | `keys.alg` | `RS256` |
| `BARYCENTER__AUTHZ__ENABLED` | `authz.enabled` | `false` |
| `BARYCENTER__AUTHZ__PORT` | `authz.port` | `port + 2` |
| `BARYCENTER__AUTHZ__POLICIES_DIR` | `authz.policies_dir` | `policies/` |

## Tips

- **Boolean values**: Use `true` or `false` (case-insensitive).
- **Integer values**: Provide plain numbers without quotes (e.g., `8080`).
- **String values with special characters**: Quote the value in the shell if it contains characters like `?`, `&`, or spaces.
- **Docker**: Use the `-e` flag or an `env_file` to pass variables to containers.
- **Systemd**: Use `Environment=` directives in the service unit file, or `EnvironmentFile=` to load from a file.
