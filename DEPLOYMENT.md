# Deployment Guide

This guide covers deploying Barycenter OpenID Connect Identity Provider on various platforms.

## Table of Contents

- [Docker](#docker)
- [Docker Compose](#docker-compose)
- [Kubernetes (Helm)](#kubernetes-helm)
- [Linux (systemd)](#linux-systemd)
- [FreeBSD](#freebsd)
- [illumos/Solaris](#illumossolaris)
- [Configuration](#configuration)
- [Security Considerations](#security-considerations)

---

## Docker

### Building the Image

```bash
docker build -t barycenter:latest .
```

### Running the Container

```bash
docker run -d \
  --name barycenter \
  -p 8080:8080 \
  -v barycenter-data:/app/data \
  -e RUST_LOG=info \
  barycenter:latest
```

### Custom Configuration

Mount a custom config file:

```bash
docker run -d \
  --name barycenter \
  -p 8080:8080 \
  -v ./config.toml:/app/config/config.toml:ro \
  -v barycenter-data:/app/data \
  barycenter:latest
```

---

## Docker Compose

### Quick Start

```bash
# Start the service
docker-compose up -d

# View logs
docker-compose logs -f

# Stop the service
docker-compose down
```

### Production Configuration

Edit `docker-compose.yml` to customize:

```yaml
environment:
  - RUST_LOG=info
  - BARYCENTER__SERVER__PUBLIC_BASE_URL=https://idp.example.com
```

---

## Kubernetes (Helm)

### Prerequisites

- Kubernetes cluster (1.19+)
- Helm 3.x
- kubectl configured

### Installation

1. **Install the Helm chart:**

```bash
helm install barycenter ./deploy/helm/barycenter \
  --create-namespace \
  --namespace barycenter
```

2. **With custom values:**

```bash
helm install barycenter ./deploy/helm/barycenter \
  --namespace barycenter \
  --set ingress.enabled=true \
  --set ingress.hosts[0].host=idp.example.com \
  --set config.server.publicBaseUrl=https://idp.example.com
```

3. **Using a values file:**

Create `my-values.yaml`:

```yaml
ingress:
  enabled: true
  className: nginx
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
  hosts:
    - host: idp.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: barycenter-tls
      hosts:
        - idp.example.com

config:
  server:
    publicBaseUrl: "https://idp.example.com"

persistence:
  enabled: true
  size: 20Gi
  storageClass: fast-ssd

resources:
  limits:
    cpu: 2000m
    memory: 1Gi
  requests:
    cpu: 200m
    memory: 256Mi
```

Install with:

```bash
helm install barycenter ./deploy/helm/barycenter \
  --namespace barycenter \
  --values my-values.yaml
```

4. **Using Gateway API instead of Ingress:**

The Helm chart supports Kubernetes Gateway API as a modern alternative to Ingress. Gateway API requires the Gateway API CRDs to be installed in your cluster.

Create `gateway-values.yaml`:

```yaml
# Disable traditional Ingress
ingress:
  enabled: false

# Enable Gateway API
gatewayAPI:
  enabled: true
  parentRefs:
    - name: my-gateway
      namespace: gateway-system
      sectionName: https  # Optional: target specific listener
  hostnames:
    - idp.example.com
  annotations:
    # Optional annotations for the HTTPRoute
    example.com/custom: value

config:
  server:
    publicBaseUrl: "https://idp.example.com"

persistence:
  enabled: true
  size: 20Gi
```

Install with Gateway API:

```bash
helm install barycenter ./deploy/helm/barycenter \
  --namespace barycenter \
  --values gateway-values.yaml
```

**Benefits of Gateway API:**
- More expressive and extensible than Ingress
- Role-oriented design with clear separation of concerns
- Better support for advanced traffic management
- Vendor-neutral and portable across implementations

### Management

**Upgrade:**
```bash
helm upgrade barycenter ./deploy/helm/barycenter \
  --namespace barycenter \
  --values my-values.yaml
```

**Uninstall:**
```bash
helm uninstall barycenter --namespace barycenter
```

**Check status:**
```bash
helm status barycenter --namespace barycenter
kubectl get pods -n barycenter
```

---

## Linux (systemd)

### Installation

See detailed instructions in [`deploy/systemd/README.md`](deploy/systemd/README.md).

**Quick steps:**

1. Build and install binary:
```bash
cargo build --release
sudo cp target/release/barycenter /usr/local/bin/
```

2. Create user and directories:
```bash
sudo useradd -r -s /bin/false -d /var/lib/barycenter barycenter
sudo mkdir -p /etc/barycenter /var/lib/barycenter/data
sudo chown -R barycenter:barycenter /var/lib/barycenter
```

3. Install configuration:
```bash
sudo cp config.toml /etc/barycenter/
# Edit /etc/barycenter/config.toml to update paths
```

4. Install and start service:
```bash
sudo cp deploy/systemd/barycenter.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now barycenter
```

### Management

```bash
# Status
sudo systemctl status barycenter

# Logs
sudo journalctl -u barycenter -f

# Restart
sudo systemctl restart barycenter
```

---

## FreeBSD

### Installation

See detailed instructions in [`deploy/freebsd/README.md`](deploy/freebsd/README.md).

**Quick steps:**

1. Build and install:
```bash
cargo build --release
sudo install -m 755 target/release/barycenter /usr/local/bin/
```

2. Create user and directories:
```bash
sudo pw useradd barycenter -d /var/db/barycenter -s /usr/sbin/nologin
sudo mkdir -p /usr/local/etc/barycenter /var/db/barycenter/data
sudo chown -R barycenter:barycenter /var/db/barycenter
```

3. Install configuration:
```bash
sudo cp config.toml /usr/local/etc/barycenter/
# Edit /usr/local/etc/barycenter/config.toml
```

4. Install and enable service:
```bash
sudo install -m 755 deploy/freebsd/barycenter /usr/local/etc/rc.d/
echo 'barycenter_enable="YES"' | sudo tee -a /etc/rc.conf
sudo service barycenter start
```

---

## illumos/Solaris

### Installation

See detailed instructions in [`deploy/illumos/README.md`](deploy/illumos/README.md).

**Quick steps:**

1. Build and install:
```bash
cargo build --release
sudo mkdir -p /opt/barycenter/bin
sudo cp target/release/barycenter /opt/barycenter/bin/
```

2. Create user and directories:
```bash
sudo useradd -d /var/barycenter -s /usr/bin/false barycenter
sudo mkdir -p /etc/barycenter /var/barycenter/data
sudo chown -R barycenter:barycenter /var/barycenter
```

3. Install configuration:
```bash
sudo cp config.toml /etc/barycenter/
# Edit /etc/barycenter/config.toml
```

4. Import and enable SMF service:
```bash
sudo svccfg import deploy/illumos/barycenter.xml
sudo svcadm enable barycenter
```

---

## Configuration

### Environment Variables

All configuration can be overridden using environment variables with the `BARYCENTER__` prefix:

```bash
# Override server settings
export BARYCENTER__SERVER__PORT=9090
export BARYCENTER__SERVER__PUBLIC_BASE_URL=https://idp.example.com

# Override database
export BARYCENTER__DATABASE__URL=sqlite:///custom/path/db.sqlite

# Set logging
export RUST_LOG=debug
```

### Configuration File

The `config.toml` file structure:

```toml
[server]
host = "0.0.0.0"
port = 8080
public_base_url = "https://idp.example.com"  # Required in production

[database]
url = "sqlite://barycenter.db?mode=rwc"

[keys]
jwks_path = "data/jwks.json"
private_key_path = "data/private_key.pem"
alg = "RS256"

[federation]
trust_anchors = []
```

### Production Checklist

- [ ] Set `public_base_url` to your actual domain
- [ ] Use HTTPS/TLS (via reverse proxy or ingress)
- [ ] Configure proper logging (`RUST_LOG=info`)
- [ ] Set up persistent storage for database and keys
- [ ] Configure backups for database and private keys
- [ ] Set appropriate file permissions (600 for keys, 640 for config)
- [ ] Run as non-root user
- [ ] Configure firewall rules
- [ ] Set up monitoring and health checks
- [ ] Review and apply security hardening settings

---

## Security Considerations

### TLS/HTTPS

Barycenter should always run behind a TLS-terminating reverse proxy or load balancer in production. Never expose it directly on HTTP.

**Options:**
- **Kubernetes:** Use Ingress with cert-manager for automatic TLS
- **Linux:** Use nginx, Caddy, or Traefik as reverse proxy
- **Cloud:** Use cloud load balancers (ALB, GCE LB, etc.)

### Reverse Proxy Example (nginx)

```nginx
server {
    listen 443 ssl http2;
    server_name idp.example.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://localhost:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### File Permissions

```bash
# Configuration (readable by service, writable by root)
chmod 640 /etc/barycenter/config.toml
chown root:barycenter /etc/barycenter/config.toml

# Private key (readable only by service)
chmod 600 /var/lib/barycenter/data/private_key.pem
chown barycenter:barycenter /var/lib/barycenter/data/private_key.pem

# Data directory
chmod 750 /var/lib/barycenter
chown barycenter:barycenter /var/lib/barycenter
```

### Backup Strategy

**Critical files to backup:**
1. Private RSA key (`private_key.pem`)
2. Database (`barycenter.db`)
3. Configuration (`config.toml`)

**Backup script example:**

```bash
#!/bin/bash
BACKUP_DIR=/backup/barycenter/$(date +%Y%m%d)
mkdir -p $BACKUP_DIR

# Backup database
sqlite3 /var/lib/barycenter/barycenter.db ".backup '$BACKUP_DIR/barycenter.db'"

# Backup keys and config
cp /var/lib/barycenter/data/private_key.pem $BACKUP_DIR/
cp /etc/barycenter/config.toml $BACKUP_DIR/

# Encrypt and upload to remote storage
tar czf - $BACKUP_DIR | gpg -e -r admin@example.com | \
  aws s3 cp - s3://backups/barycenter-$(date +%Y%m%d).tar.gz.gpg
```

### Monitoring

**Health check endpoint:**
```bash
curl http://localhost:8080/.well-known/openid-configuration
```

**Metrics to monitor:**
- HTTP response times
- Error rates (4xx, 5xx)
- Database connection status
- Disk usage (for SQLite file)
- Memory/CPU usage

---

## Support

For issues and questions:
- GitHub Issues: https://github.com/yourusername/barycenter/issues
- Documentation: See `README.md` and `CLAUDE.md`
