# Production Checklist

Use this checklist to verify your Barycenter deployment before serving production traffic. Each item includes the rationale and how to verify or fix it.

## Configuration

- [ ] **Set `public_base_url` to the externally-reachable HTTPS URL.**
  This value becomes the OAuth `iss` claim in ID tokens and the `issuer` in the OpenID discovery document. OIDC clients validate tokens against this URL.

  ```toml
  [server]
  public_base_url = "https://idp.example.com"
  ```

  Verify:
  ```bash
  curl https://idp.example.com/.well-known/openid-configuration | jq .issuer
  ```

- [ ] **Use HTTPS.** TLS must be terminated either by a [reverse proxy](./reverse-proxy-tls.md) or a Kubernetes Ingress/Gateway. Barycenter does not terminate TLS natively. Never expose the HTTP port directly to the internet.

- [ ] **Configure the database connection string.** For production, PostgreSQL is recommended for multi-replica deployments. SQLite is suitable for single-instance setups.

  ```toml
  [database]
  url = "postgresql://barycenter:secret@db-host:5432/barycenter"
  ```

## Logging

- [ ] **Set the log level to `info` or `warn`.** Avoid running `debug` or `trace` in production as these levels produce high log volume and may expose sensitive data in logs.

  ```bash
  RUST_LOG=info
  ```

- [ ] **Forward logs to a centralized logging system.** Use journald, Docker log drivers, or Kubernetes log aggregation to collect and retain logs.

## Persistent Storage

- [ ] **Persist the data directory.** The data directory contains the RSA private key and (for SQLite) the database. Losing the private key invalidates all issued tokens.

  | Deployment | Mount point |
  |------------|-------------|
  | Docker | `/app/data` volume |
  | systemd | `/var/lib/barycenter/data/` |
  | FreeBSD | `/var/db/barycenter/data/` |
  | illumos | `/var/barycenter/data/` |
  | Kubernetes | PVC at `/app/data` |

- [ ] **Verify the data directory is writable by the Barycenter process.**

## Backups

- [ ] **Back up the RSA private key.** This key signs all ID tokens. If lost, every client must re-validate or re-authenticate. See [Backup and Recovery](./backup-recovery.md).

- [ ] **Back up the database.** Both SQLite and PostgreSQL databases should be backed up regularly.

- [ ] **Back up the configuration file.** Store it in version control or a configuration management system.

- [ ] **Test backup restoration.** Periodically verify that backups can be restored to a working state.

## File Permissions

- [ ] **Private key file: mode `600`.** Only the Barycenter service user should be able to read the RSA private key.

  ```bash
  chmod 600 /var/lib/barycenter/data/private_key.pem
  ```

- [ ] **Configuration file: mode `640`.** The config file may contain database credentials. Restrict access to root and the Barycenter group.

  ```bash
  chmod 640 /etc/barycenter/config.toml
  chown root:barycenter /etc/barycenter/config.toml
  ```

- [ ] **Data directory: mode `750`.** Only the Barycenter user and group should access the directory.

## Run as Non-Root

- [ ] **The Barycenter process does not run as root.** All deployment methods (systemd, rc.d, SMF, Docker, Kubernetes) should run the process as a dedicated unprivileged user.

  | Deployment | User |
  |------------|------|
  | Docker | Container default (non-root) |
  | systemd | `barycenter` |
  | FreeBSD | `barycenter` |
  | illumos | `barycenter` |
  | Kubernetes | `runAsNonRoot: true` in security context |

## Container Security (Docker / Kubernetes)

- [ ] **Enable `no-new-privileges`.** Prevents the process from gaining additional privileges.

- [ ] **Use a read-only root filesystem.** Mount the root filesystem as read-only and provide writable volumes only where needed.

- [ ] **Drop all capabilities.** The Barycenter process does not require any Linux capabilities.

- [ ] **In Kubernetes, apply the `restricted` Pod Security Standard.**

## Network

- [ ] **Only expose port 8080 publicly.** The admin API (8081) and authorization API (8082) should not be reachable from the internet.

- [ ] **Firewall rules.** Restrict inbound traffic to only the ports and source networks required.

  | Port | Access |
  |------|--------|
  | 8080 | Public (through reverse proxy) |
  | 8081 | Management network only |
  | 8082 | Application network only |

- [ ] **In Kubernetes, enable the authz NetworkPolicy** if using the authorization engine:

  ```yaml
  authz:
    networkPolicy:
      enabled: true
  ```

## Monitoring and Health Checks

- [ ] **Set up health checks.** Monitor the OIDC discovery endpoint to confirm the service is responsive:

  ```bash
  curl -f https://idp.example.com/.well-known/openid-configuration
  ```

- [ ] **Monitor disk usage.** For SQLite deployments, the database grows over time. Set alerts for low disk space on the data volume.

- [ ] **Monitor certificate expiration.** Set alerts for TLS certificates nearing expiry. Automated renewal (certbot, cert-manager) should be verified periodically.

- [ ] **Monitor background jobs.** Query the admin API to check that cleanup jobs are running successfully:

  ```graphql
  query {
    jobLogs(limit: 5, onlyFailures: true) {
      jobName
      startedAt
      success
    }
  }
  ```

## Client Registration

- [ ] **Review registered clients.** Ensure only expected clients are registered. Remove test clients that should not exist in production.

- [ ] **Verify redirect URIs.** Each registered client's redirect URIs should use HTTPS and match the actual callback URLs of the client application.

## Summary

Completing every item on this checklist ensures that Barycenter is deployed with appropriate security, reliability, and operational visibility for production use. Revisit this checklist after infrastructure changes, upgrades, or scaling events.
