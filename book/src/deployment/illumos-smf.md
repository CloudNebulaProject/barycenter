# illumos / Solaris SMF

This guide covers deploying Barycenter as a Service Management Facility (SMF) service on illumos distributions such as SmartOS, OmniOS, and OpenIndiana. An SMF manifest is provided in the repository at `deploy/illumos/barycenter.xml`.

## Prerequisites

- An illumos-based system (SmartOS, OmniOS, OpenIndiana, or similar)
- The Rust toolchain (to build from source) or a pre-built binary
- SQLite libraries (if using SQLite) or a reachable PostgreSQL instance

## Step 1: Build the Binary

```bash
cargo build --release
```

The release binary is located at `target/release/barycenter`.

## Step 2: Create a Service User

```bash
useradd -d /var/barycenter -s /usr/bin/false -c "Barycenter IdP" barycenter
mkdir -p /var/barycenter/data
chown -R barycenter:barycenter /var/barycenter
```

## Step 3: Install the Binary

```bash
mkdir -p /opt/barycenter/bin
cp target/release/barycenter /opt/barycenter/bin/barycenter
chmod 755 /opt/barycenter/bin/barycenter
```

## Step 4: Install the Configuration File

```bash
mkdir -p /etc/barycenter
cp config.toml /etc/barycenter/config.toml
chmod 640 /etc/barycenter/config.toml
chown root:barycenter /etc/barycenter/config.toml
```

Edit `/etc/barycenter/config.toml` for your deployment:

```toml
[server]
public_base_url = "https://idp.example.com"

[database]
url = "sqlite:///var/barycenter/data/barycenter.db?mode=rwc"

[keys]
jwks_path = "/var/barycenter/data/jwks.json"
private_key_path = "/var/barycenter/data/private_key.pem"
```

## Step 5: Import the SMF Manifest

```bash
svccfg import deploy/illumos/barycenter.xml
```

This registers the service with SMF. You can verify the import:

```bash
svcs -a | grep barycenter
```

## Step 6: Enable the Service

```bash
svcadm enable barycenter
```

## Managing the Service

```bash
# Check service status
svcs barycenter

# Check detailed status (includes process ID)
svcs -p barycenter

# View service properties
svccfg -s barycenter listprop

# Restart the service
svcadm restart barycenter

# Disable the service
svcadm disable barycenter

# Re-enable the service
svcadm enable barycenter
```

## Viewing Logs

SMF services log to files managed by the framework. Find the log file path:

```bash
svcs -L barycenter
```

View the log:

```bash
less $(svcs -L barycenter)
```

Follow the log in real time:

```bash
tail -f $(svcs -L barycenter)
```

## Troubleshooting Service Failures

If the service enters a `maintenance` state, it means SMF detected a persistent failure:

```bash
# Check the service state
svcs -xv barycenter

# Read the service log for error details
less $(svcs -L barycenter)

# After fixing the issue, clear the maintenance state
svcadm clear barycenter
```

Common causes:

- **Configuration error** -- Invalid `config.toml` syntax or unreachable database.
- **Permission denied** -- The `barycenter` user cannot read the config file or write to the data directory.
- **Port in use** -- Another process is already listening on port 8080, 8081, or 8082.

## Setting Environment Variables

To set the log level or other environment variables, modify the SMF service properties:

```bash
svccfg -s barycenter setenv RUST_LOG info
svcadm restart barycenter
```

## Directory Layout

| Path | Owner | Mode | Purpose |
|------|-------|------|---------|
| `/opt/barycenter/bin/barycenter` | `root:root` | `755` | Application binary |
| `/etc/barycenter/config.toml` | `root:barycenter` | `640` | Configuration file |
| `/var/barycenter/data/` | `barycenter:barycenter` | `750` | Data directory |
| `/var/barycenter/data/private_key.pem` | `barycenter:barycenter` | `600` | RSA private key (created at first run) |

## Upgrading

```bash
# Build the new version
cargo build --release

# Disable the service
svcadm disable barycenter

# Replace the binary
cp target/release/barycenter /opt/barycenter/bin/barycenter

# Enable the service
svcadm enable barycenter

# Verify
svcs barycenter
```

Database migrations run automatically on startup.

## Zone Deployment

On SmartOS and other illumos distributions that support zones, Barycenter can be deployed inside a zone for additional isolation. The setup is identical to the steps above, performed inside the zone. Ensure the zone has network access to any external PostgreSQL instance if not using SQLite.

## Further Reading

- [Production Checklist](./production-checklist.md) -- steps to verify before going live
- [Reverse Proxy and TLS](./reverse-proxy-tls.md) -- placing Barycenter behind a reverse proxy
- [Backup and Recovery](./backup-recovery.md) -- backing up the data directory
