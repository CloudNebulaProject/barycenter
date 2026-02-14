# Creating Users

Barycenter provides several mechanisms for creating user accounts, ranging from the automatic default admin user to programmatic creation via the GraphQL API.

## Default Admin User

On first startup, Barycenter creates a default administrator account if no users exist in the database:

| Field | Value |
|---|---|
| Username | `admin` |
| Password | `password123` |

This account is intended for initial setup and testing. In production deployments, you should either:

- Change the admin password immediately after first login.
- Use [user sync](./user-sync.md) to provision accounts with strong passwords as part of your deployment process, replacing the default admin.

The default admin user is only created when the users table is empty. If you have provisioned users through any other method before first startup, the default admin is not created.

## Creating Users via the GraphQL API

The Seaography entity CRUD schema at `POST /admin/graphql` supports creating user records directly. This is useful for ad-hoc user creation by administrators.

### Example Mutation

```graphql
mutation {
  user {
    createOne(
      data: {
        username: "alice"
        email: "alice@example.com"
        passwordHash: "$argon2id$v=19$m=19456,t=2,p=1$..."
      }
    ) {
      id
      username
      email
    }
  }
}
```

### curl Example

```bash
curl -s -X POST http://localhost:8081/admin/graphql \
  -H "Content-Type: application/json" \
  -d '{
    "query": "mutation { user { createOne(data: { username: \"alice\", email: \"alice@example.com\", passwordHash: \"$argon2id$v=19$m=19456,t=2,p=1$...\" }) { id username email } } }"
  }' | jq .
```

### Password Hashing

The GraphQL API expects a pre-computed password hash in argon2id format. You must hash the password before sending it to the API. The hash can be generated using any argon2 library or command-line tool:

```bash
# Using the argon2 command-line utility
echo -n "user_password" | argon2 $(openssl rand -base64 16) -id -e
```

> **Note**: For most provisioning scenarios, the [user sync CLI](./user-sync.md) handles password hashing automatically from plaintext passwords in the JSON file, making it a more practical choice than direct GraphQL mutations.

## Creating Users via User Sync

The `sync-users` CLI subcommand reads a JSON file containing user definitions and creates or updates accounts idempotently. This is the recommended method for production deployments where the set of users is known ahead of time.

```bash
barycenter sync-users --file users.json
```

See [User Sync from JSON](./user-sync.md) for the full file format and usage details.

## Creating Users via Public Registration

When enabled, the public registration endpoint allows users to create their own accounts:

```bash
curl -X POST http://localhost:8080/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "newuser",
    "email": "newuser@example.com",
    "password": "secure_password"
  }'
```

See [Public Registration](./public-registration.md) for configuration details.

## Choosing the Right Method

| Method | Password Handling | Best For |
|---|---|---|
| Default admin | Pre-set (`password123`) | Initial setup and development |
| GraphQL API | Pre-hashed (argon2id) required | Ad-hoc creation by administrators |
| User sync CLI | Plaintext in JSON, hashed automatically | Declarative production provisioning |
| Public registration | Plaintext in request, hashed automatically | Self-service account creation |

## Further Reading

- [User Sync from JSON](./user-sync.md) -- bulk provisioning with automatic password hashing
- [Public Registration](./public-registration.md) -- self-service account creation
- [Entity CRUD (Seaography)](./entity-crud.md) -- full CRUD operations for all entities
- [User 2FA Management](./user-2fa.md) -- enabling 2FA after user creation
