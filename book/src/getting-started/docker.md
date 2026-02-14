# Docker

Barycenter publishes container images to the GitHub Container Registry. You can also build the image locally from the repository.

## Pull the Pre-Built Image

```bash
docker pull ghcr.io/cloudnebulaproject/barycenter:latest
```

Tagged versions are also available:

```bash
docker pull ghcr.io/cloudnebulaproject/barycenter:0.1.0
```

The images are built for both `linux/amd64` and `linux/arm64` architectures.

## Run the Container

Barycenter exposes three ports corresponding to its [three-server architecture](./architecture.md):

| Port | Purpose |
|------|---------|
| 8080 | Public OIDC server |
| 8081 | Admin GraphQL API |
| 8082 | Authorization policy server |

### Basic Usage

```bash
docker run -d \
  --name barycenter \
  -p 8080:8080 \
  -p 8081:8081 \
  -p 8082:8082 \
  ghcr.io/cloudnebulaproject/barycenter:latest
```

This starts Barycenter with the default SQLite database and an auto-generated RSA key pair. Data is stored inside the container and will be lost when the container is removed.

### With Persistent Storage

To persist the database and key material across container restarts, mount the `data/` directory and provide a configuration file:

```bash
docker run -d \
  --name barycenter \
  -p 8080:8080 \
  -p 8081:8081 \
  -p 8082:8082 \
  -v $(pwd)/data:/app/data \
  -v $(pwd)/config.toml:/app/config.toml:ro \
  ghcr.io/cloudnebulaproject/barycenter:latest
```

The `data/` directory will contain:
- The SQLite database file (if using SQLite)
- The RSA private key (PEM format)
- The JWKS public key set

### With Environment Variables

Configuration values can be overridden via environment variables:

```bash
docker run -d \
  --name barycenter \
  -p 8080:8080 \
  -p 8081:8081 \
  -p 8082:8082 \
  -e BARYCENTER__SERVER__PORT=8080 \
  -e BARYCENTER__SERVER__PUBLIC_BASE_URL=https://id.example.com \
  -e BARYCENTER__DATABASE__URL=postgresql://user:pass@db-host/barycenter \
  ghcr.io/cloudnebulaproject/barycenter:latest
```

### With PostgreSQL

For production deployments using PostgreSQL:

```bash
docker run -d \
  --name barycenter \
  -p 8080:8080 \
  -p 8081:8081 \
  -p 8082:8082 \
  -v $(pwd)/data:/app/data \
  -e BARYCENTER__DATABASE__URL=postgresql://barycenter:secret@postgres:5432/barycenter \
  --network my-network \
  ghcr.io/cloudnebulaproject/barycenter:latest
```

## Build the Image Locally

From the repository root:

```bash
docker build -t barycenter:local .
```

For a specific platform:

```bash
docker build --platform linux/amd64 -t barycenter:local .
```

For multi-architecture builds:

```bash
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t barycenter:local \
  .
```

## Docker Compose Example

A minimal `docker-compose.yml` for development:

```yaml
services:
  barycenter:
    image: ghcr.io/cloudnebulaproject/barycenter:latest
    ports:
      - "8080:8080"
      - "8081:8081"
      - "8082:8082"
    volumes:
      - ./data:/app/data
      - ./config.toml:/app/config.toml:ro
    environment:
      RUST_LOG: barycenter=info
```

With PostgreSQL:

```yaml
services:
  barycenter:
    image: ghcr.io/cloudnebulaproject/barycenter:latest
    ports:
      - "8080:8080"
      - "8081:8081"
      - "8082:8082"
    volumes:
      - barycenter-data:/app/data
    environment:
      BARYCENTER__DATABASE__URL: postgresql://barycenter:secret@postgres:5432/barycenter
      BARYCENTER__SERVER__PUBLIC_BASE_URL: http://localhost:8080
      RUST_LOG: barycenter=info
    depends_on:
      postgres:
        condition: service_healthy

  postgres:
    image: postgres:17
    environment:
      POSTGRES_USER: barycenter
      POSTGRES_PASSWORD: secret
      POSTGRES_DB: barycenter
    volumes:
      - postgres-data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U barycenter"]
      interval: 5s
      timeout: 5s
      retries: 5

volumes:
  barycenter-data:
  postgres-data:
```

## Volume Reference

| Mount point | Purpose | Required |
|-------------|---------|----------|
| `/app/data` | Database file (SQLite), RSA keys, JWKS | Recommended for persistence |
| `/app/config.toml` | Configuration file (read-only mount) | Optional (can use env vars instead) |
| `/app/policies` | KDL authorization policy files | Only if using the authz engine |
