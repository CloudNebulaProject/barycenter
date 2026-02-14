# FreeBSD rc.d

This guide covers deploying Barycenter as an rc.d service on FreeBSD. An rc.d script is provided in the repository at `deploy/freebsd/barycenter`.

## Prerequisites

- FreeBSD 13 or later
- The Rust toolchain (to build from source) or a pre-built binary
- SQLite libraries (if using SQLite) or a reachable PostgreSQL instance

## Step 1: Build the Binary

```bash
cargo build --release
```

The release binary is located at `target/release/barycenter`.

## Step 2: Create a Service User

Create a dedicated user with no login shell:

```bash
pw useradd barycenter -d /var/db/barycenter -s /usr/sbin/nologin -c "Barycenter IdP"
mkdir -p /var/db/barycenter/data
chown -R barycenter:barycenter /var/db/barycenter
```

## Step 3: Install the Binary

```bash
cp target/release/barycenter /usr/local/bin/barycenter
chmod 755 /usr/local/bin/barycenter
```

## Step 4: Create Configuration Directory

```bash
mkdir -p /usr/local/etc/barycenter
```

## Step 5: Install the Configuration File

```bash
cp config.toml /usr/local/etc/barycenter/config.toml
chmod 640 /usr/local/etc/barycenter/config.toml
chown root:barycenter /usr/local/etc/barycenter/config.toml
```

Edit `/usr/local/etc/barycenter/config.toml` for your deployment:

```toml
[server]
public_base_url = "https://idp.example.com"

[database]
url = "sqlite:///var/db/barycenter/data/barycenter.db?mode=rwc"

[keys]
jwks_path = "/var/db/barycenter/data/jwks.json"
private_key_path = "/var/db/barycenter/data/private_key.pem"
```

## Step 6: Install the rc.d Script

```bash
install -m 755 deploy/freebsd/barycenter /usr/local/etc/rc.d/barycenter
```

## Step 7: Enable the Service

Add the following line to `/etc/rc.conf`:

```bash
barycenter_enable="YES"
```

Or use `sysrc`:

```bash
sysrc barycenter_enable="YES"
```

## Step 8: Start the Service

```bash
service barycenter start
```

## Managing the Service

```bash
# Check status
service barycenter status

# Start the service
service barycenter start

# Stop the service
service barycenter stop

# Restart after a configuration change
service barycenter restart
```

## Viewing Logs

If the rc.d script logs to syslog, view logs with:

```bash
grep barycenter /var/log/messages
```

To follow logs in real time:

```bash
tail -f /var/log/messages | grep barycenter
```

For more detailed logging, set the `RUST_LOG` environment variable in the rc.d configuration. Add to `/etc/rc.conf`:

```bash
barycenter_env="RUST_LOG=info"
```

Or with `sysrc`:

```bash
sysrc barycenter_env="RUST_LOG=info"
```

## Directory Layout

| Path | Owner | Mode | Purpose |
|------|-------|------|---------|
| `/usr/local/bin/barycenter` | `root:wheel` | `755` | Application binary |
| `/usr/local/etc/barycenter/config.toml` | `root:barycenter` | `640` | Configuration file |
| `/usr/local/etc/rc.d/barycenter` | `root:wheel` | `755` | rc.d service script |
| `/var/db/barycenter/data/` | `barycenter:barycenter` | `750` | Data directory |
| `/var/db/barycenter/data/private_key.pem` | `barycenter:barycenter` | `600` | RSA private key (created at first run) |

## Upgrading

```bash
# Build the new version
cargo build --release

# Stop the service
service barycenter stop

# Replace the binary
cp target/release/barycenter /usr/local/bin/barycenter

# Start the service
service barycenter start

# Verify
service barycenter status
```

Database migrations run automatically on startup.

## Jail Deployment

Barycenter works well inside a FreeBSD jail for additional isolation. The setup is identical to the steps above, performed inside the jail. Ensure the jail has network access to any external PostgreSQL instance if not using SQLite.

## Further Reading

- [Production Checklist](./production-checklist.md) -- steps to verify before going live
- [Reverse Proxy and TLS](./reverse-proxy-tls.md) -- placing Barycenter behind a reverse proxy
- [Backup and Recovery](./backup-recovery.md) -- backing up the data directory
