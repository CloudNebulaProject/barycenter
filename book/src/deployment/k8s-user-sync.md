# User Sync in Kubernetes

Barycenter supports provisioning users at startup through an init container that runs before the main application. This is useful for seeding an initial set of users in automated deployments where interactive user creation is not practical.

## How It Works

When `userSync.enabled` is `true`, the Helm chart adds an init container to the Barycenter pod. This init container:

1. Reads a JSON array of user objects from a file.
2. Inserts or updates each user in the database.
3. Exits. The main Barycenter container then starts with the users already present.

The init container runs every time the pod starts, so it is safe to add new users to the list and redeploy. Existing users are updated to match the provided data.

## Inline User Definitions

For small deployments or development environments, define users directly in `values.yaml`:

```yaml
userSync:
  enabled: true
  users: |
    [
      {
        "username": "alice",
        "password": "correct-horse-battery-staple",
        "email": "alice@example.com"
      },
      {
        "username": "bob",
        "password": "another-strong-passphrase",
        "email": "bob@example.com"
      }
    ]
```

> **Warning:** Passwords in `values.yaml` are stored as plaintext in the Kubernetes ConfigMap. For production deployments, use the `existingSecret` method described below.

## Using an Existing Secret

For production, store user data in a Kubernetes Secret:

```bash
kubectl create secret generic barycenter-users \
  --from-file=users.json=./users.json \
  -n barycenter
```

Where `users.json` contains:

```json
[
  {
    "username": "alice",
    "password": "correct-horse-battery-staple",
    "email": "alice@example.com"
  },
  {
    "username": "bob",
    "password": "another-strong-passphrase",
    "email": "bob@example.com"
  }
]
```

Reference the Secret in your values:

```yaml
userSync:
  enabled: true
  existingSecret: barycenter-users
```

The chart mounts the Secret into the init container and reads the `users.json` key.

## User Object Schema

Each user object in the JSON array supports the following fields:

| Field | Required | Description |
|-------|----------|-------------|
| `username` | Yes | Unique username for login |
| `password` | Yes | Plaintext password (hashed with Argon2 on import) |
| `email` | No | User email address |

Passwords are always hashed before being stored in the database. The plaintext password in the JSON is never persisted.

## Updating Users

To add or modify users:

1. Update the JSON array (in `values.yaml` or in the Secret).
2. Redeploy with `helm upgrade`.

The init container runs again and applies the changes. Existing users whose data has not changed are left untouched.

## Combining with Other User Sources

User sync is additive. Users created through other means -- such as the [Admin GraphQL API](../admin/graphql-api.md), [public registration](../admin/public-registration.md), or direct database access -- are not affected by the sync process. The init container only manages the users present in the JSON array.

## Disabling User Sync

To stop running the init container, set `userSync.enabled` to `false` and redeploy. Previously synced users remain in the database; they are not deleted.

```yaml
userSync:
  enabled: false
```

## Troubleshooting

If the pod is stuck in `Init:0/1` status, check the init container logs:

```bash
kubectl logs <pod-name> -c user-sync -n barycenter
```

Common issues:

- **Database not reachable** -- If using PostgreSQL, verify that the database is accessible from the pod and that the connection string in `config.database.url` is correct.
- **Invalid JSON** -- Validate the JSON syntax before deploying. A missing comma or bracket will prevent the init container from completing.
- **Secret not found** -- Ensure the Secret referenced by `existingSecret` exists in the same namespace as the Barycenter release.

## Further Reading

- [Helm Chart Values](./helm-values.md) -- full reference of `userSync.*` values
- [User Sync from JSON](../admin/user-sync.md) -- the underlying user-sync mechanism
- [Creating Users](../admin/creating-users.md) -- other methods for provisioning users
