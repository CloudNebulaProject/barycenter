# Database Setup

Barycenter supports two database backends: **SQLite** for development and small deployments, and **PostgreSQL** for production workloads. The backend is automatically detected from the connection string -- no additional configuration flags are needed.

## SQLite

SQLite is the default backend and requires no external database server. It is well-suited for development, testing, and single-instance deployments.

### Connection String Format

```
sqlite://path/to/database.db?mode=rwc
```

The `?mode=rwc` flag means **read-write-create**: the database file is created automatically if it does not exist. This is the recommended mode for most use cases.

### Examples

```toml
# Relative path (relative to working directory)
[database]
url = "sqlite://data/barycenter.db?mode=rwc"

# Absolute path
[database]
url = "sqlite:///var/lib/barycenter/barycenter.db?mode=rwc"
```

Via environment variable:

```bash
export BARYCENTER__DATABASE__URL="sqlite://data/barycenter.db?mode=rwc"
```

### SQLite Considerations

- **Single-writer**: SQLite uses a file-level lock for writes. Only one Barycenter instance can write to a given database file at a time.
- **No network access**: The database file must be on local or network-attached storage accessible from the Barycenter process.
- **Backup**: Copy the database file while Barycenter is stopped, or use SQLite's `.backup` command for online backups.
- **Performance**: SQLite handles moderate request loads well. For high-throughput production deployments, consider PostgreSQL.

## PostgreSQL

PostgreSQL is the recommended backend for production deployments. It supports concurrent connections, replication, and standard database administration tools.

### Connection String Format

```
postgresql://user:password@host:port/database
```

### Examples

```toml
[database]
url = "postgresql://barycenter:secret@localhost:5432/barycenter"
```

With SSL:

```toml
[database]
url = "postgresql://barycenter:secret@db.example.com:5432/barycenter?sslmode=require"
```

Via environment variable:

```bash
export BARYCENTER__DATABASE__URL="postgresql://barycenter:secret@db.internal:5432/barycenter"
```

### PostgreSQL Setup

Create a database and user for Barycenter:

```sql
CREATE USER barycenter WITH PASSWORD 'your-secure-password';
CREATE DATABASE barycenter OWNER barycenter;
```

Or using `createdb`:

```bash
createuser barycenter --pwprompt
createdb barycenter --owner=barycenter
```

Barycenter only needs standard privileges on its own database. It does not require superuser access.

### PostgreSQL Considerations

- **Connection pooling**: Barycenter maintains a connection pool internally via SeaORM. For very large deployments, consider placing PgBouncer or a similar connection pooler in front of PostgreSQL.
- **Replication**: You can use PostgreSQL streaming replication for high availability. Barycenter should always connect to the primary (writable) instance.
- **SSL/TLS**: Use `?sslmode=require` or `?sslmode=verify-full` in the connection string for encrypted database connections in production.

## Automatic Migrations

Barycenter runs database migrations automatically on startup. There is no separate migration command or manual step required.

When the application starts:

1. It connects to the configured database.
2. It checks for pending migrations.
3. It applies any new migrations in order.
4. It logs which migrations were applied (if any).

This applies to both SQLite and PostgreSQL. The migration system is idempotent -- running migrations on an already-up-to-date database is a no-op.

### Managed Tables

Migrations create and manage the following tables:

| Table | Purpose |
|-------|---------|
| `clients` | OAuth client registrations |
| `auth_codes` | Authorization codes with PKCE challenges |
| `access_tokens` | Bearer tokens with scope and expiration |
| `refresh_tokens` | Refresh tokens with rotation tracking |
| `sessions` | User sessions with AMR, ACR, and MFA state |
| `users` | User accounts with password hashes and 2FA settings |
| `passkeys` | WebAuthn credential storage |
| `webauthn_challenges` | Temporary WebAuthn challenge data |
| `device_codes` | Device authorization grant codes |
| `consents` | Per-client, per-scope consent records |
| `job_executions` | Background job execution history |
| `properties` | Key-value property store |

### Migration Safety

- **Non-destructive**: Migrations only add tables and columns; they do not drop or alter existing data.
- **Backup first**: Before upgrading Barycenter to a new version, back up your database. While migrations are designed to be safe, having a backup provides a rollback path.
- **Version tracking**: Applied migrations are tracked in a `seaql_migrations` table managed by SeaORM.

## Switching Databases

To migrate from SQLite to PostgreSQL (or vice versa):

1. Set up the target database (create the PostgreSQL database and user, or prepare the SQLite path).
2. Update the `database.url` in your configuration or environment.
3. Start Barycenter -- migrations will create the schema in the new database.
4. Export data from the old database and import it into the new one using standard tools.

There is no built-in data migration tool between backends. Use `sqlite3` and `psql` (or equivalent tools) for data transfer.

## High Availability

For high-availability deployments:

- **PostgreSQL** is required. SQLite does not support concurrent writers from multiple processes.
- Run multiple Barycenter instances pointing to the same PostgreSQL database.
- Use a load balancer in front of the public server ports.
- Ensure all instances share the same RSA key material (via shared storage or identical `private_key_path` contents).
- PostgreSQL handles concurrent access and locking automatically.
