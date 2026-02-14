# Backup and Recovery

Barycenter stores critical data that must be backed up to recover from hardware failure, accidental deletion, or corruption. This page describes what to back up, how to perform backups for each storage backend, and how to restore from a backup.

## What to Back Up

Three categories of data are critical:

| Data | Location | Impact if Lost |
|------|----------|----------------|
| RSA private key | `private_key.pem` in the data directory | All issued ID tokens become unverifiable. Clients cannot validate existing tokens. A new key is generated on restart, but previously issued tokens are invalidated. |
| Database | SQLite file or PostgreSQL database | All client registrations, authorization codes, access tokens, refresh tokens, user accounts, passkey registrations, and session data are lost. |
| Configuration | `config.toml` | Must be recreated manually. Store in version control. |

The JWKS public key file (`jwks.json`) is derived from the private key and is regenerated automatically. It does not need to be backed up independently.

## Backup Procedures

### SQLite

The SQLite database is a single file, but copying it while Barycenter is running can produce a corrupt copy. Use SQLite's built-in backup command instead:

```bash
sqlite3 /var/lib/barycenter/data/barycenter.db ".backup '/var/backups/barycenter/barycenter-$(date +%Y%m%d-%H%M%S).db'"
```

This command creates a consistent snapshot even while the database is in use.

Alternatively, stop the service before copying:

```bash
systemctl stop barycenter
cp /var/lib/barycenter/data/barycenter.db /var/backups/barycenter/barycenter-$(date +%Y%m%d-%H%M%S).db
systemctl start barycenter
```

### PostgreSQL

Use `pg_dump` to create a logical backup:

```bash
pg_dump -U barycenter -h db-host -d barycenter -F custom -f /var/backups/barycenter/barycenter-$(date +%Y%m%d-%H%M%S).pgdump
```

For automated backups, consider using `pg_basebackup` for physical backups or a tool like pgBackRest for incremental backups with point-in-time recovery.

### Private Key

Copy the private key file:

```bash
cp /var/lib/barycenter/data/private_key.pem /var/backups/barycenter/private_key-$(date +%Y%m%d-%H%M%S).pem
```

The private key does not change after initial generation, so it only needs to be backed up once and again if the key is rotated.

### Configuration

```bash
cp /etc/barycenter/config.toml /var/backups/barycenter/config-$(date +%Y%m%d-%H%M%S).toml
```

The recommended approach is to store the configuration file in version control (Git) so that changes are tracked and the file can be recovered from any commit.

### Docker Volumes

For Docker deployments, back up the named volume:

```bash
docker run --rm \
  -v barycenter-data:/data:ro \
  -v $(pwd)/backups:/backup \
  alpine tar czf /backup/barycenter-data-$(date +%Y%m%d-%H%M%S).tar.gz -C /data .
```

## Encrypting Backups

Backups contain the RSA private key and potentially database credentials. Encrypt them before storing off-site:

```bash
gpg --symmetric --cipher-algo AES256 \
  -o /var/backups/barycenter/backup-$(date +%Y%m%d).gpg \
  /var/backups/barycenter/barycenter-$(date +%Y%m%d-%H%M%S).db
```

To decrypt:

```bash
gpg --decrypt /var/backups/barycenter/backup-20260214.gpg > restored.db
```

For automated encryption, use GPG with a public key so that no passphrase is needed during backup creation:

```bash
gpg --encrypt --recipient backup@example.com \
  -o /var/backups/barycenter/backup-$(date +%Y%m%d).gpg \
  /var/backups/barycenter/barycenter-$(date +%Y%m%d-%H%M%S).db
```

## Automated Backup Script

A complete backup script that handles SQLite, the private key, and the configuration:

```bash
#!/bin/sh
set -e

BACKUP_DIR="/var/backups/barycenter"
DATA_DIR="/var/lib/barycenter/data"
CONFIG="/etc/barycenter/config.toml"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)

mkdir -p "$BACKUP_DIR"

# Database
sqlite3 "$DATA_DIR/barycenter.db" ".backup '$BACKUP_DIR/db-$TIMESTAMP.db'"

# Private key
cp "$DATA_DIR/private_key.pem" "$BACKUP_DIR/key-$TIMESTAMP.pem"

# Configuration
cp "$CONFIG" "$BACKUP_DIR/config-$TIMESTAMP.toml"

# Create a single encrypted archive
tar czf - -C "$BACKUP_DIR" \
  "db-$TIMESTAMP.db" \
  "key-$TIMESTAMP.pem" \
  "config-$TIMESTAMP.toml" \
  | gpg --symmetric --cipher-algo AES256 --batch --passphrase-file /root/.backup-passphrase \
  > "$BACKUP_DIR/barycenter-$TIMESTAMP.tar.gz.gpg"

# Clean up unencrypted files
rm "$BACKUP_DIR/db-$TIMESTAMP.db"
rm "$BACKUP_DIR/key-$TIMESTAMP.pem"
rm "$BACKUP_DIR/config-$TIMESTAMP.toml"

# Prune backups older than 30 days
find "$BACKUP_DIR" -name "barycenter-*.tar.gz.gpg" -mtime +30 -delete

echo "Backup completed: $BACKUP_DIR/barycenter-$TIMESTAMP.tar.gz.gpg"
```

Schedule with cron (daily at 2 AM):

```cron
0 2 * * * /usr/local/bin/barycenter-backup.sh
```

## Recovery Procedures

### Restoring SQLite

1. Stop Barycenter.
2. Replace the database file with the backup.
3. Start Barycenter. Migrations run automatically if the backup is from an older version.

```bash
systemctl stop barycenter
cp /var/backups/barycenter/db-20260214-020000.db /var/lib/barycenter/data/barycenter.db
chown barycenter:barycenter /var/lib/barycenter/data/barycenter.db
chmod 600 /var/lib/barycenter/data/barycenter.db
systemctl start barycenter
```

### Restoring PostgreSQL

1. Stop Barycenter.
2. Drop and recreate the database, then restore from the dump.
3. Start Barycenter.

```bash
systemctl stop barycenter
dropdb -U postgres barycenter
createdb -U postgres -O barycenter barycenter
pg_restore -U barycenter -d barycenter /var/backups/barycenter/barycenter-20260214-020000.pgdump
systemctl start barycenter
```

### Restoring the Private Key

1. Stop Barycenter.
2. Copy the backed-up key to the data directory.
3. Set correct ownership and permissions.
4. Start Barycenter.

```bash
systemctl stop barycenter
cp /var/backups/barycenter/key-20260214-020000.pem /var/lib/barycenter/data/private_key.pem
chown barycenter:barycenter /var/lib/barycenter/data/private_key.pem
chmod 600 /var/lib/barycenter/data/private_key.pem
systemctl start barycenter
```

### Restoring from an Encrypted Archive

```bash
gpg --decrypt /var/backups/barycenter/barycenter-20260214-020000.tar.gz.gpg | tar xzf - -C /tmp/barycenter-restore/
```

Then follow the individual restoration steps above using the extracted files.

## Off-Site Storage

Backups should be stored in at least one location separate from the primary server. Options include:

- **Object storage** (S3, GCS, MinIO) -- upload the encrypted archive after each backup.
- **Remote server** -- transfer via rsync or scp.
- **Tape or cold storage** -- for long-term retention requirements.

## Backup Verification

Periodically verify that backups can be restored:

1. Decrypt the archive.
2. Restore the database to a test instance.
3. Start Barycenter against the test database.
4. Confirm the OIDC discovery endpoint responds.
5. Confirm that a known client registration exists.

An unverified backup is not a backup.

## Further Reading

- [Production Checklist](./production-checklist.md) -- includes backup verification steps
- [Linux systemd](./systemd.md) -- service management for backup scheduling
