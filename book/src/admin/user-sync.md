# User Sync from JSON

The `sync-users` CLI subcommand provisions user accounts from a JSON file. It is designed for declarative, repeatable user management in production environments where the set of administrative or service accounts is known at deployment time.

## Usage

```bash
barycenter sync-users --file users.json
```

The command reads the specified JSON file, and for each user definition:

- **Creates** the user if the username does not already exist.
- **Updates** the user if the username already exists (updates email, password, and other fields).
- **Does not delete** users that are present in the database but absent from the JSON file.

This idempotent behavior means you can run the command repeatedly -- during every deployment, as a startup script, or as a Kubernetes init container -- without causing errors or duplicating accounts.

## JSON File Format

The users file is a JSON array of user objects:

```json
[
  {
    "username": "admin",
    "email": "admin@example.com",
    "password": "strong_admin_password"
  },
  {
    "username": "alice",
    "email": "alice@example.com",
    "password": "alice_secure_password"
  },
  {
    "username": "service-account",
    "email": "svc@example.com",
    "password": "service_account_password"
  }
]
```

### Fields

| Field | Type | Required | Description |
|---|---|---|---|
| `username` | `string` | Yes | Unique username for login. Used as the key for idempotent matching. |
| `email` | `string` | Yes | User's email address. Updated on subsequent syncs if changed. |
| `password` | `string` | Yes | Plaintext password. Automatically hashed with argon2id before storage. |

Passwords in the JSON file are stored in plaintext and hashed automatically by the sync command. Protect the JSON file with appropriate file system permissions and do not commit it to version control with real passwords.

## Idempotent Behavior

The sync operation uses the `username` field as the unique key:

| Scenario | Action |
|---|---|
| Username does not exist in database | Create new user with hashed password |
| Username already exists in database | Update email and password hash if changed |
| Username exists in database but not in JSON file | No action (user is preserved) |

This means:

- Running `sync-users` twice with the same file produces the same result as running it once.
- Adding a new user to the JSON file and re-running creates only that new user.
- Changing a password in the JSON file and re-running updates the password hash.
- Removing a user from the JSON file does **not** delete them from the database.

## Kubernetes Init Container Pattern

A common deployment pattern is to run `sync-users` as an init container before the main Barycenter pod starts. This ensures administrative accounts exist before the server begins accepting requests.

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: barycenter
spec:
  template:
    spec:
      initContainers:
        - name: sync-users
          image: your-registry/barycenter:latest
          command: ["barycenter", "sync-users", "--file", "/config/users.json"]
          volumeMounts:
            - name: users-config
              mountPath: /config
            - name: data
              mountPath: /data
      containers:
        - name: barycenter
          image: your-registry/barycenter:latest
          command: ["barycenter", "--config", "/config/config.toml"]
          volumeMounts:
            - name: users-config
              mountPath: /config
            - name: data
              mountPath: /data
      volumes:
        - name: users-config
          secret:
            secretName: barycenter-users
        - name: data
          persistentVolumeClaim:
            claimName: barycenter-data
```

The users JSON file is mounted from a Kubernetes Secret to keep passwords out of ConfigMaps:

```bash
kubectl create secret generic barycenter-users \
  --from-file=users.json=./users.json \
  --from-file=config.toml=./config.toml
```

## Security Considerations

- **File permissions**: The JSON file contains plaintext passwords. Set restrictive permissions (`chmod 600 users.json`) and limit access to the deployment system.
- **Secrets management**: In Kubernetes, store the file as a Secret rather than a ConfigMap. Consider using external secret managers (e.g., Vault, AWS Secrets Manager) that inject secrets at runtime.
- **Version control**: Never commit the users JSON file with real passwords to a repository. Use a template or placeholder file instead, and populate real values during deployment.
- **Audit trail**: The sync command logs which users were created or updated, providing a record of provisioning actions.

## Example Workflow

```bash
# 1. Create the users file
cat > users.json << 'EOF'
[
  {
    "username": "admin",
    "email": "admin@myorg.com",
    "password": "change-me-in-production"
  },
  {
    "username": "readonly-service",
    "email": "readonly@myorg.com",
    "password": "service-account-password"
  }
]
EOF

# 2. Restrict file permissions
chmod 600 users.json

# 3. Run the sync
barycenter sync-users --file users.json

# 4. Verify users were created
curl -s -X POST http://localhost:8081/admin/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ user { findMany { nodes { username email } } } }"}' | jq .
```

## Further Reading

- [Creating Users](./creating-users.md) -- all user creation methods
- [User Sync in Kubernetes](../deployment/k8s-user-sync.md) -- detailed Kubernetes deployment guide
- [Public Registration](./public-registration.md) -- self-service registration as an alternative
