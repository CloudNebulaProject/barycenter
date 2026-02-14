# Docker Compose

Docker Compose simplifies running Barycenter alongside supporting services such as PostgreSQL. This page provides ready-to-use Compose files for several common configurations.

## Standalone with SQLite

The simplest Compose setup uses the built-in SQLite database:

```yaml
services:
  barycenter:
    image: ghcr.io/cloudnebulaproject/barycenter:latest
    ports:
      - "8080:8080"
      - "8081:8081"
      - "8082:8082"
    volumes:
      - ./config.toml:/app/config/config.toml:ro
      - barycenter-data:/app/data
    environment:
      - RUST_LOG=info

volumes:
  barycenter-data:
```

Start it with:

```bash
docker compose up -d
```

## With PostgreSQL

For production use, PostgreSQL is recommended:

```yaml
services:
  barycenter:
    image: ghcr.io/cloudnebulaproject/barycenter:latest
    ports:
      - "8080:8080"
      - "8081:8081"
      - "8082:8082"
    volumes:
      - ./config.toml:/app/config/config.toml:ro
      - barycenter-data:/app/data
    environment:
      - RUST_LOG=info
      - BARYCENTER__DATABASE__URL=postgresql://barycenter:secret@postgres:5432/barycenter
      - BARYCENTER__SERVER__PUBLIC_BASE_URL=https://idp.example.com
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

The `depends_on` condition ensures Barycenter waits for PostgreSQL to become healthy before starting.

## Production-Hardened

This configuration adds security options suitable for production:

```yaml
services:
  barycenter:
    image: ghcr.io/cloudnebulaproject/barycenter:latest
    ports:
      - "8080:8080"
    volumes:
      - ./config.toml:/app/config/config.toml:ro
      - barycenter-data:/app/data
    environment:
      - RUST_LOG=info
      - BARYCENTER__SERVER__PUBLIC_BASE_URL=https://idp.example.com
      - BARYCENTER__DATABASE__URL=postgresql://barycenter:secret@postgres:5432/barycenter
    security_opt:
      - no-new-privileges:true
    read_only: true
    tmpfs:
      - /tmp
    depends_on:
      postgres:
        condition: service_healthy
    restart: unless-stopped

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
    restart: unless-stopped

volumes:
  barycenter-data:
  postgres-data:
```

Key differences from the basic setup:

- **`security_opt: no-new-privileges:true`** -- prevents privilege escalation inside the container.
- **`read_only: true`** -- makes the root filesystem immutable. Only the `/app/data` volume and `/tmp` tmpfs are writable.
- **`tmpfs: /tmp`** -- provides a writable temporary directory backed by memory.
- **Only port 8080 is published** -- the admin (8081) and authorization (8082) ports are not exposed to the host network. Other containers on the same Compose network can still reach them by service name.
- **`restart: unless-stopped`** -- automatically restarts after crashes or host reboots.

## Accessing Internal Ports

If you need the admin or authorization APIs from the host (for example, during initial setup), you can temporarily add them to the `ports` list:

```yaml
    ports:
      - "8080:8080"
      - "127.0.0.1:8081:8081"   # Admin API, localhost only
      - "127.0.0.1:8082:8082"   # Authz API, localhost only
```

Binding to `127.0.0.1` ensures these ports are only reachable from the host machine and not from the external network.

## Using an `.env` File

Sensitive values such as database credentials should not be committed to version control. Use a `.env` file alongside your Compose file:

```bash
# .env
POSTGRES_PASSWORD=a-strong-random-password
BARYCENTER_DB_URL=postgresql://barycenter:a-strong-random-password@postgres:5432/barycenter
```

Then reference these variables in the Compose file:

```yaml
services:
  barycenter:
    environment:
      - BARYCENTER__DATABASE__URL=${BARYCENTER_DB_URL}
    # ...

  postgres:
    environment:
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
    # ...
```

## Managing the Stack

```bash
# Start all services in the background
docker compose up -d

# View logs
docker compose logs -f barycenter

# Restart Barycenter after a configuration change
docker compose restart barycenter

# Stop and remove all services
docker compose down

# Stop and remove all services, including volumes (destroys data)
docker compose down -v
```

## Next Steps

- [Reverse Proxy and TLS](./reverse-proxy-tls.md) -- terminate TLS in front of the Compose stack
- [Backup and Recovery](./backup-recovery.md) -- back up the Docker volumes
- [Production Checklist](./production-checklist.md) -- verify your setup before going live
