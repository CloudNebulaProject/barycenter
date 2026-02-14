# Hardening

This section covers operating system, container, and infrastructure hardening measures for production Barycenter deployments. These measures limit the blast radius of any compromise by restricting what the application process can access.

## File Permissions

Barycenter uses a dedicated service user and group. File permissions follow the principle of least privilege:

| Path | Permission | Owner | Purpose |
|------|-----------|-------|---------|
| `/usr/local/bin/barycenter` | `755` | `root:root` | Application binary (read-only for service user) |
| `/etc/barycenter/config.toml` | `640` | `root:barycenter` | Configuration file (readable by service group, not world-readable) |
| `/var/lib/barycenter/` | `750` | `barycenter:barycenter` | Data directory (database, runtime files) |
| `/var/lib/barycenter/private_key.json` | `600` | `barycenter:barycenter` | RSA private key (owner-only access) |
| `/var/lib/barycenter/jwks.json` | `644` | `barycenter:barycenter` | Public JWKS (world-readable, contains only public keys) |
| `/var/lib/barycenter/barycenter.db` | `600` | `barycenter:barycenter` | SQLite database (owner-only access) |
| `/var/log/barycenter/` | `750` | `barycenter:barycenter` | Log directory |

### Setting Up the Service User

```bash
# Create a system user with no login shell and no home directory
groupadd --system barycenter
useradd --system --gid barycenter --shell /usr/sbin/nologin \
  --no-create-home --home /var/lib/barycenter barycenter

# Create directories
mkdir -p /var/lib/barycenter /var/log/barycenter /etc/barycenter

# Set ownership and permissions
chown barycenter:barycenter /var/lib/barycenter /var/log/barycenter
chmod 750 /var/lib/barycenter /var/log/barycenter

chown root:barycenter /etc/barycenter/config.toml
chmod 640 /etc/barycenter/config.toml
```

## Systemd Hardening

When running Barycenter as a systemd service, apply the following security directives to restrict the process:

```ini
[Unit]
Description=Barycenter OpenID Connect Identity Provider
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=barycenter
Group=barycenter

ExecStart=/usr/local/bin/barycenter --config /etc/barycenter/config.toml

# Filesystem restrictions
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/var/lib/barycenter /var/log/barycenter

# Privilege restrictions
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=

# System call filtering
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
SystemCallArchitectures=native

# Network restrictions
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
PrivateUsers=no

# Other restrictions
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=no
RemoveIPC=yes

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=barycenter

# Restart policy
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

### Directive Explanations

| Directive | Value | Effect |
|-----------|-------|--------|
| `ProtectSystem=strict` | `strict` | Mounts the entire file system hierarchy read-only, except paths listed in `ReadWritePaths` |
| `ProtectHome=yes` | `yes` | Makes `/home`, `/root`, and `/run/user` inaccessible |
| `PrivateTmp=yes` | `yes` | Creates a private `/tmp` directory not shared with other services |
| `NoNewPrivileges=yes` | `yes` | Prevents the process from gaining new privileges via setuid, setgid, or capabilities |
| `CapabilityBoundingSet=` | (empty) | Drops all Linux capabilities from the process |
| `ReadWritePaths` | Data and log dirs | Only these paths are writable; everything else is read-only |
| `SystemCallFilter=@system-service` | Allowlist | Restricts available system calls to those needed by typical network services |
| `MemoryDenyWriteExecute=no` | `no` | Set to `no` because WebAssembly compilation may require W^X memory (if WASM processing occurs server-side) |

### Verifying Hardening

After starting the service, verify that the security directives are applied:

```bash
# Check the security score (lower is more secure, 0-10 scale)
systemd-analyze security barycenter

# Verify the service is running with restrictions
systemctl status barycenter
```

## Docker Security

When running Barycenter in Docker, apply the following security measures.

### Dockerfile Best Practices

```dockerfile
FROM rust:1.84-bookworm AS builder
WORKDIR /build
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates && \
    rm -rf /var/lib/apt/lists/* && \
    groupadd --system barycenter && \
    useradd --system --gid barycenter --no-create-home barycenter

COPY --from=builder /build/target/release/barycenter /usr/local/bin/barycenter

USER barycenter
EXPOSE 9090
ENTRYPOINT ["/usr/local/bin/barycenter"]
```

### Docker Run Security Options

```bash
docker run -d \
  --name barycenter \
  --read-only \
  --tmpfs /tmp:noexec,nosuid,size=64m \
  --security-opt no-new-privileges:true \
  --cap-drop ALL \
  --user 65534:65534 \
  -v /var/lib/barycenter:/data:rw \
  -p 9090:9090 \
  barycenter:latest
```

### Docker Compose Security Context

```yaml
services:
  barycenter:
    image: barycenter:latest
    read_only: true
    tmpfs:
      - /tmp:noexec,nosuid,size=64m
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    user: "65534:65534"
    volumes:
      - barycenter-data:/data
    ports:
      - "9090:9090"

volumes:
  barycenter-data:
```

## Kubernetes Security Context

Apply the following security settings in your Kubernetes Pod or Deployment specification:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: barycenter
spec:
  replicas: 1
  selector:
    matchLabels:
      app: barycenter
  template:
    metadata:
      labels:
        app: barycenter
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 65534
        runAsGroup: 65534
        fsGroup: 65534
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: barycenter
          image: barycenter:latest
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop:
                - ALL
          ports:
            - containerPort: 9090
              name: http
            - containerPort: 9091
              name: admin
          volumeMounts:
            - name: data
              mountPath: /data
            - name: tmp
              mountPath: /tmp
          resources:
            requests:
              memory: "64Mi"
              cpu: "100m"
            limits:
              memory: "256Mi"
              cpu: "500m"
      volumes:
        - name: data
          persistentVolumeClaim:
            claimName: barycenter-data
        - name: tmp
          emptyDir:
            medium: Memory
            sizeLimit: 64Mi
```

### Security Context Breakdown

| Setting | Value | Effect |
|---------|-------|--------|
| `runAsNonRoot` | `true` | Kubelet refuses to start the container if it would run as root |
| `runAsUser` | `65534` | Runs the process as the `nobody` user |
| `readOnlyRootFilesystem` | `true` | Container filesystem is mounted read-only; only mounted volumes are writable |
| `allowPrivilegeEscalation` | `false` | Prevents the process from gaining elevated privileges |
| `capabilities.drop: ALL` | All dropped | Removes all Linux capabilities from the container |
| `seccompProfile: RuntimeDefault` | Default profile | Applies the container runtime's default seccomp profile to restrict system calls |

## Network Segmentation

### Admin API Isolation

The admin GraphQL API runs on a separate port (default: 9091) and must not be exposed to the public internet. Use network policies to restrict access:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: barycenter-admin-policy
spec:
  podSelector:
    matchLabels:
      app: barycenter
  policyTypes:
    - Ingress
  ingress:
    # Allow public traffic to the main port
    - ports:
        - port: 9090
    # Restrict admin port to internal management network
    - from:
        - namespaceSelector:
            matchLabels:
              network: management
      ports:
        - port: 9091
```

### Database Access

If using PostgreSQL, ensure the database is only accessible from the Barycenter application:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: postgres-access-policy
spec:
  podSelector:
    matchLabels:
      app: postgres
  policyTypes:
    - Ingress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: barycenter
      ports:
        - port: 5432
```

### Firewall Rules (Non-Kubernetes)

For traditional deployments, configure firewall rules to restrict access:

```bash
# Allow public access to the main port
iptables -A INPUT -p tcp --dport 9090 -j ACCEPT

# Allow admin port only from management network
iptables -A INPUT -p tcp --dport 9091 -s 10.0.0.0/24 -j ACCEPT
iptables -A INPUT -p tcp --dport 9091 -j DROP
```
