# Configuration

Barycenter uses a layered configuration system. Values are resolved in the following order, where later sources override earlier ones:

1. **Built-in defaults** -- Sensible defaults defined in the application code
2. **Configuration file** -- A TOML file (default: `config.toml`)
3. **Environment variables** -- Variables prefixed with `BARYCENTER__`

This means an environment variable will always take precedence over a value in the configuration file, and a value in the configuration file will override the built-in default.

## Configuration Sources

- **[Configuration File](./config-file.md)** -- Full annotated reference for `config.toml` with all available sections and keys.
- **[Environment Variables](./env-variables.md)** -- How to override configuration values using environment variables, with examples and precedence rules.
- **[Database Setup](./database-setup.md)** -- Choosing between SQLite and PostgreSQL, connection string formats, and migration behavior.

## Quick Example

A minimal `config.toml`:

```toml
[server]
host = "0.0.0.0"
port = 8080

[database]
url = "sqlite://data/barycenter.db?mode=rwc"
```

The same values via environment variables:

```bash
export BARYCENTER__SERVER__HOST=0.0.0.0
export BARYCENTER__SERVER__PORT=8080
export BARYCENTER__DATABASE__URL="sqlite://data/barycenter.db?mode=rwc"
```

## Specifying a Config File

By default, Barycenter looks for `config.toml` in the current working directory. Use the `--config` flag to specify a different path:

```bash
barycenter --config /etc/barycenter/config.toml
```

If the specified file does not exist, Barycenter will exit with an error. If no `--config` flag is given and `config.toml` does not exist in the current directory, Barycenter will start with built-in defaults and any environment variable overrides.

## Logging

Logging is controlled by the `RUST_LOG` environment variable, not the configuration file. Barycenter uses the standard Rust `tracing` ecosystem.

```bash
# Info-level logging for Barycenter, warn for dependencies
RUST_LOG=barycenter=info cargo run

# Verbose debug output
RUST_LOG=debug cargo run

# Trace-level for the Barycenter crate only
RUST_LOG=barycenter=trace cargo run
```
