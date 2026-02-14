# Docker

Barycenter publishes multi-architecture container images to the GitHub Container Registry. This page covers pulling, running, and building the Docker image for standalone deployments. For multi-container setups see [Docker Compose](./docker-compose.md).

## Image Registry

```bash
docker pull ghcr.io/cloudnebulaproject/barycenter:latest
```

Tagged releases are also available:

```bash
docker pull ghcr.io/cloudnebulaproject/barycenter:0.2.0
```

Images are built for `linux/amd64` and `linux/arm64`.

## Ports

Barycenter exposes three ports corresponding to its [three-server architecture](../getting-started/architecture.md):

| Port | Purpose | Expose publicly? |
|------|---------|------------------|
| 8080 | Public OIDC server | Yes |
| 8081 | Admin GraphQL API | No -- internal only |
| 8082 | Authorization policy server | No -- internal only |

Only the public OIDC port should be reachable from the internet. The admin and authorization ports should be restricted to trusted networks or kept behind a firewall.

## Volumes

| Mount point | Purpose | Required |
|-------------|---------|----------|
| `/app/data` | SQLite database, RSA private key, JWKS public key set | Recommended for persistence |
| `/app/config/config.toml` | Configuration file (mount read-only) | Optional if using environment variables exclusively |

If no volume is mounted at `/app/data`, the database and key material live inside the container and are lost when the container is removed.

## Running the Container

### Minimal

```bash
docker run -d \
  --name barycenter \
  -p 8080:8080 \
  ghcr.io/cloudnebulaproject/barycenter:latest
```

This starts Barycenter with defaults: an in-container SQLite database and an auto-generated RSA key pair. Suitable for quick evaluation only.

### With Persistent Storage and Configuration

```bash
docker run -d \
  --name barycenter \
  -p 8080:8080 \
  -p 8081:8081 \
  -p 8082:8082 \
  -v $(pwd)/config.toml:/app/config/config.toml:ro \
  -v barycenter-data:/app/data \
  ghcr.io/cloudnebulaproject/barycenter:latest
```

### With Environment Variable Overrides

Any configuration value can be overridden through environment variables using the `BARYCENTER__` prefix with double-underscore separators for nested keys:

```bash
docker run -d \
  --name barycenter \
  -p 8080:8080 \
  -e RUST_LOG=info \
  -e BARYCENTER__SERVER__PUBLIC_BASE_URL=https://idp.example.com \
  -e BARYCENTER__DATABASE__URL=postgresql://user:pass@db-host/barycenter \
  -v barycenter-data:/app/data \
  ghcr.io/cloudnebulaproject/barycenter:latest
```

### With PostgreSQL

When using an external PostgreSQL database, the `/app/data` volume is still needed for key material but no longer stores the database:

```bash
docker run -d \
  --name barycenter \
  -p 8080:8080 \
  -v barycenter-data:/app/data \
  -e BARYCENTER__DATABASE__URL=postgresql://barycenter:secret@postgres:5432/barycenter \
  --network my-network \
  ghcr.io/cloudnebulaproject/barycenter:latest
```

## Security Hardening

For production containers, apply these options:

```bash
docker run -d \
  --name barycenter \
  -p 8080:8080 \
  -v $(pwd)/config.toml:/app/config/config.toml:ro \
  -v barycenter-data:/app/data \
  --security-opt no-new-privileges:true \
  --read-only \
  --tmpfs /tmp \
  -e RUST_LOG=info \
  ghcr.io/cloudnebulaproject/barycenter:latest
```

- `--security-opt no-new-privileges:true` prevents privilege escalation inside the container.
- `--read-only` makes the root filesystem immutable. Only `/app/data` and `/tmp` are writable.
- `--tmpfs /tmp` provides a writable temporary filesystem backed by memory.

## Building the Image Locally

From the repository root:

```bash
docker build -t barycenter:latest .
```

For a specific platform:

```bash
docker build --platform linux/amd64 -t barycenter:latest .
```

For multi-architecture builds using buildx:

```bash
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t barycenter:latest \
  .
```

## Environment Variable Reference

| Variable | Purpose | Example |
|----------|---------|---------|
| `RUST_LOG` | Log level filter | `info`, `barycenter=debug` |
| `BARYCENTER__SERVER__PORT` | Public server listen port | `8080` |
| `BARYCENTER__SERVER__PUBLIC_BASE_URL` | OAuth issuer URL | `https://idp.example.com` |
| `BARYCENTER__DATABASE__URL` | Database connection string | `sqlite://barycenter.db?mode=rwc` |

See [Configuration](../getting-started/configuration.md) for the full list of available environment variables.

## Next Steps

- [Docker Compose](./docker-compose.md) -- multi-container setups with PostgreSQL
- [Reverse Proxy and TLS](./reverse-proxy-tls.md) -- placing Barycenter behind nginx or another proxy
- [Production Checklist](./production-checklist.md) -- steps to verify before going live
