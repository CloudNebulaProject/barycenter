# Linux systemd

This guide covers deploying Barycenter as a systemd service on Linux distributions such as Debian, Ubuntu, Fedora, RHEL, and Arch Linux. A systemd unit file is provided in the repository at `deploy/systemd/barycenter.service`.

## Prerequisites

- A Linux system with systemd
- The Rust toolchain (to build from source) or a pre-built binary
- SQLite development libraries (if using SQLite) or a reachable PostgreSQL instance

## Step 1: Build the Binary

```bash
cargo build --release
```

The release binary is located at `target/release/barycenter`.

## Step 2: Create a Service User

Create a dedicated system user with no login shell and a home directory for data:

```bash
sudo useradd -r -s /bin/false -d /var/lib/barycenter barycenter
```

## Step 3: Install the Binary

```bash
sudo cp target/release/barycenter /usr/local/bin/barycenter
sudo chmod 755 /usr/local/bin/barycenter
```

## Step 4: Create Directories

```bash
sudo mkdir -p /etc/barycenter
sudo mkdir -p /var/lib/barycenter/data
sudo chown -R barycenter:barycenter /var/lib/barycenter
```

| Directory | Purpose |
|-----------|---------|
| `/etc/barycenter/` | Configuration file |
| `/var/lib/barycenter/data/` | Database (SQLite), RSA private key, JWKS |

## Step 5: Install the Configuration File

Copy and edit the configuration file:

```bash
sudo cp config.toml /etc/barycenter/config.toml
sudo chmod 640 /etc/barycenter/config.toml
sudo chown root:barycenter /etc/barycenter/config.toml
```

Edit `/etc/barycenter/config.toml` to set the correct values for your deployment. At a minimum, configure the `public_base_url` and database path:

```toml
[server]
public_base_url = "https://idp.example.com"

[database]
url = "sqlite:///var/lib/barycenter/data/barycenter.db?mode=rwc"

[keys]
jwks_path = "/var/lib/barycenter/data/jwks.json"
private_key_path = "/var/lib/barycenter/data/private_key.pem"
```

## Step 6: Install the systemd Unit

```bash
sudo cp deploy/systemd/barycenter.service /etc/systemd/system/barycenter.service
sudo systemctl daemon-reload
```

The unit file runs Barycenter as the `barycenter` user, reads the configuration from `/etc/barycenter/config.toml`, and restarts the service on failure.

## Step 7: Enable and Start

```bash
sudo systemctl enable --now barycenter
```

This enables Barycenter to start automatically on boot and starts it immediately.

## Managing the Service

```bash
# Check status
sudo systemctl status barycenter

# View logs
sudo journalctl -u barycenter

# Follow logs in real time
sudo journalctl -u barycenter -f

# Restart after a configuration change
sudo systemctl restart barycenter

# Stop the service
sudo systemctl stop barycenter

# Disable automatic start on boot
sudo systemctl disable barycenter
```

## Log Level

Set the log level through the `RUST_LOG` environment variable. You can override it in the unit file by creating a drop-in:

```bash
sudo systemctl edit barycenter
```

Add the following content:

```ini
[Service]
Environment=RUST_LOG=info
```

Save and restart:

```bash
sudo systemctl restart barycenter
```

Common log level values:

| Value | Description |
|-------|-------------|
| `error` | Only errors |
| `warn` | Warnings and errors |
| `info` | Informational messages (recommended for production) |
| `debug` | Detailed debugging output |
| `barycenter=debug` | Debug output for Barycenter only, info for dependencies |

## File Permissions Summary

| Path | Owner | Mode | Purpose |
|------|-------|------|---------|
| `/usr/local/bin/barycenter` | `root:root` | `755` | Application binary |
| `/etc/barycenter/config.toml` | `root:barycenter` | `640` | Configuration file |
| `/var/lib/barycenter/data/` | `barycenter:barycenter` | `750` | Data directory |
| `/var/lib/barycenter/data/private_key.pem` | `barycenter:barycenter` | `600` | RSA private key (created at first run) |

## Upgrading

To upgrade Barycenter to a new version:

```bash
# Build the new version
cargo build --release

# Stop the service
sudo systemctl stop barycenter

# Replace the binary
sudo cp target/release/barycenter /usr/local/bin/barycenter

# Start the service
sudo systemctl start barycenter

# Verify
sudo systemctl status barycenter
sudo journalctl -u barycenter --since "1 minute ago"
```

Database migrations run automatically on startup.

## Further Reading

- [Production Checklist](./production-checklist.md) -- steps to verify before going live
- [Reverse Proxy and TLS](./reverse-proxy-tls.md) -- placing Barycenter behind nginx
- [Backup and Recovery](./backup-recovery.md) -- backing up the data directory
