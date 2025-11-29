# illumos/Solaris Deployment

This directory contains SMF (Service Management Facility) manifest for running Barycenter on illumos and Solaris systems.

## Installation

1. **Install Rust and build the binary:**
   ```bash
   # On OmniOS/OpenIndiana, install rust from pkgsrc
   pkg install rust
   cargo build --release
   ```

2. **Create the barycenter user:**
   ```bash
   useradd -d /var/barycenter -s /usr/bin/false -c "Barycenter IdP" barycenter
   ```

3. **Create required directories:**
   ```bash
   mkdir -p /opt/barycenter/bin
   mkdir -p /etc/barycenter
   mkdir -p /var/barycenter/data
   chown -R barycenter:barycenter /var/barycenter
   ```

4. **Install the binary:**
   ```bash
   cp target/release/barycenter /opt/barycenter/bin/
   chmod 755 /opt/barycenter/bin/barycenter
   ```

5. **Install the configuration:**
   ```bash
   cp config.toml /etc/barycenter/config.toml
   chown root:barycenter /etc/barycenter/config.toml
   chmod 640 /etc/barycenter/config.toml
   ```

   Edit `/etc/barycenter/config.toml` and update paths:
   ```toml
   [database]
   url = "sqlite:///var/barycenter/barycenter.db?mode=rwc"

   [keys]
   jwks_path = "/var/barycenter/data/jwks.json"
   private_key_path = "/var/barycenter/data/private_key.pem"
   ```

6. **Import the SMF manifest:**
   ```bash
   svccfg import deploy/illumos/barycenter.xml
   ```

7. **Enable the service:**
   ```bash
   svcadm enable barycenter
   ```

## Management

**Check status:**
```bash
svcs -l barycenter
```

**View logs:**
```bash
svcs -L barycenter  # Show log file location
tail -f /var/svc/log/application-barycenter:default.log
```

**Restart service:**
```bash
svcadm restart barycenter
```

**Stop service:**
```bash
svcadm disable barycenter
```

**Clear maintenance state:**
```bash
svcadm clear barycenter
```

## Configuration

### Modifying Service Properties

To change the config file location:
```bash
svccfg -s barycenter setprop application/config_file = /custom/path/config.toml
svcadm refresh barycenter
svcadm restart barycenter
```

To change the data directory:
```bash
svccfg -s barycenter setprop application/data_dir = /custom/data/dir
svcadm refresh barycenter
svcadm restart barycenter
```

### Environment Variables

To set environment variables, edit the manifest and modify the `method_environment` section:

```xml
<method_environment>
    <envvar name='RUST_LOG' value='debug' />
    <envvar name='BARYCENTER__SERVER__PUBLIC_BASE_URL' value='https://idp.example.com' />
</method_environment>
```

Then reimport:
```bash
svccfg import deploy/illumos/barycenter.xml
svcadm refresh barycenter
svcadm restart barycenter
```

## Troubleshooting

**Service won't start:**
```bash
# Check the service log
svcs -L barycenter
tail -50 /var/svc/log/application-barycenter:default.log

# Check service state
svcs -x barycenter
```

**Permission issues:**
Ensure the barycenter user has write access to the data directory:
```bash
chown -R barycenter:barycenter /var/barycenter
chmod 755 /var/barycenter
```

## SMF Features

SMF provides:
- Automatic restart on failure
- Dependency management
- Log file rotation
- Process contract management
- Property-based configuration
