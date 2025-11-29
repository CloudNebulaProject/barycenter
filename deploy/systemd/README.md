# systemd Deployment

This directory contains systemd service files for running Barycenter on Linux systems.

## Installation

1. **Create the barycenter user:**
   ```bash
   sudo useradd -r -s /bin/false -d /var/lib/barycenter barycenter
   ```

2. **Create required directories:**
   ```bash
   sudo mkdir -p /etc/barycenter /var/lib/barycenter/data
   sudo chown -R barycenter:barycenter /var/lib/barycenter
   ```

3. **Install the binary:**
   ```bash
   sudo cargo build --release
   sudo cp target/release/barycenter /usr/local/bin/
   sudo chmod +x /usr/local/bin/barycenter
   ```

4. **Install the configuration:**
   ```bash
   sudo cp config.toml /etc/barycenter/config.toml
   sudo chown root:barycenter /etc/barycenter/config.toml
   sudo chmod 640 /etc/barycenter/config.toml
   ```

   Edit `/etc/barycenter/config.toml` and update paths:
   ```toml
   [database]
   url = "sqlite:///var/lib/barycenter/barycenter.db?mode=rwc"

   [keys]
   jwks_path = "/var/lib/barycenter/data/jwks.json"
   private_key_path = "/var/lib/barycenter/data/private_key.pem"
   ```

5. **Install the systemd service:**
   ```bash
   sudo cp deploy/systemd/barycenter.service /etc/systemd/system/
   sudo systemctl daemon-reload
   ```

6. **Enable and start the service:**
   ```bash
   sudo systemctl enable barycenter
   sudo systemctl start barycenter
   ```

## Management

**Check status:**
```bash
sudo systemctl status barycenter
```

**View logs:**
```bash
sudo journalctl -u barycenter -f
```

**Restart service:**
```bash
sudo systemctl restart barycenter
```

**Stop service:**
```bash
sudo systemctl stop barycenter
```

## Security

The service runs with extensive security hardening:
- Runs as non-root user
- Private /tmp directory
- Read-only filesystem (except data directory)
- System call filtering
- Memory protections
- No new privileges

## Environment Variables

You can override configuration using environment variables in the service file:

```ini
[Service]
Environment="BARYCENTER__SERVER__PUBLIC_BASE_URL=https://idp.example.com"
Environment="RUST_LOG=debug"
```
