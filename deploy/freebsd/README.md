# FreeBSD Deployment

This directory contains rc.d script for running Barycenter on FreeBSD systems.

## Installation

1. **Install Rust and build the binary:**
   ```bash
   pkg install rust
   cargo build --release
   ```

2. **Create the barycenter user:**
   ```bash
   pw useradd barycenter -d /var/db/barycenter -s /usr/sbin/nologin -c "Barycenter IdP"
   ```

3. **Create required directories:**
   ```bash
   mkdir -p /usr/local/etc/barycenter
   mkdir -p /var/db/barycenter/data
   chown -R barycenter:barycenter /var/db/barycenter
   ```

4. **Install the binary:**
   ```bash
   install -m 755 target/release/barycenter /usr/local/bin/
   ```

5. **Install the configuration:**
   ```bash
   cp config.toml /usr/local/etc/barycenter/config.toml
   chown root:barycenter /usr/local/etc/barycenter/config.toml
   chmod 640 /usr/local/etc/barycenter/config.toml
   ```

   Edit `/usr/local/etc/barycenter/config.toml` and update paths:
   ```toml
   [database]
   url = "sqlite:///var/db/barycenter/barycenter.db?mode=rwc"

   [keys]
   jwks_path = "/var/db/barycenter/data/jwks.json"
   private_key_path = "/var/db/barycenter/data/private_key.pem"
   ```

6. **Install the rc.d script:**
   ```bash
   install -m 755 deploy/freebsd/barycenter /usr/local/etc/rc.d/
   ```

7. **Enable the service in /etc/rc.conf:**
   ```bash
   echo 'barycenter_enable="YES"' >> /etc/rc.conf
   ```

   Optional configuration:
   ```bash
   echo 'barycenter_config="/usr/local/etc/barycenter/config.toml"' >> /etc/rc.conf
   echo 'barycenter_env="RUST_LOG=info"' >> /etc/rc.conf
   ```

8. **Start the service:**
   ```bash
   service barycenter start
   ```

## Management

**Check status:**
```bash
service barycenter status
```

**View logs:**
```bash
tail -f /var/log/messages | grep barycenter
```

**Restart service:**
```bash
service barycenter restart
```

**Stop service:**
```bash
service barycenter stop
```

## Configuration Options

All configuration options are set in `/etc/rc.conf`:

- `barycenter_enable` - Enable/disable the service (YES/NO)
- `barycenter_user` - User to run as (default: barycenter)
- `barycenter_group` - Group to run as (default: barycenter)
- `barycenter_config` - Path to config file
- `barycenter_env` - Environment variables (e.g., "RUST_LOG=debug")

## Logging

By default, output goes to syslog. To configure separate log file, update newsyslog:

```bash
echo "/var/log/barycenter.log barycenter:barycenter 644 7 * @T00 JC" >> /etc/newsyslog.conf
touch /var/log/barycenter.log
chown barycenter:barycenter /var/log/barycenter.log
```
