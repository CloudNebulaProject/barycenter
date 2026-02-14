# User Management

Barycenter provides multiple methods for managing user accounts, each suited to different operational contexts. This section covers how users are created, provisioned, and managed across the system.

## User Provisioning Methods

| Method | Use Case | Details |
|---|---|---|
| Default admin user | First-run bootstrap | Created automatically on startup. See [Creating Users](./creating-users.md). |
| Seaography GraphQL API | Ad-hoc user creation by administrators | Full CRUD via `POST /admin/graphql`. See [Creating Users](./creating-users.md). |
| User sync from JSON | Declarative provisioning from configuration | Idempotent CLI subcommand for bulk provisioning. See [User Sync from JSON](./user-sync.md). |
| Public registration | Self-service account creation | Optional endpoint for open registration. See [Public Registration](./public-registration.md). |

## User Lifecycle

### Account Creation

Users can be created through any of the methods listed above. Every user account includes:

- **Username**: unique identifier used for login.
- **Email**: contact address (used in OIDC claims).
- **Password hash**: argon2id hash of the user's password.
- **Subject**: a UUID assigned at creation, used as the `sub` claim in tokens.
- **2FA settings**: whether 2FA is required, and passkey enrollment status.

### Authentication

Once created, users authenticate via:

- **Password login** at `POST /login`.
- **Passkey login** via WebAuthn at `POST /webauthn/authenticate/start` and `POST /webauthn/authenticate/finish`.
- **Two-factor authentication** when required, via `POST /webauthn/2fa/start` and `POST /webauthn/2fa/finish`.

### Passkey Management

Authenticated users can manage their own passkeys through the account API. See [Passkey Management](./passkey-management.md).

### 2FA Enforcement

Administrators can require specific users to complete two-factor authentication on every login. See [User 2FA Management](./user-2fa.md).

## Choosing a Provisioning Method

- **Development and testing**: Rely on the default admin user. Create additional test users via the Seaography API.
- **Production with known users**: Use the [user sync CLI](./user-sync.md) to declare users in a JSON file and provision them as part of deployment (e.g., as a Kubernetes init container).
- **Production with self-service**: Enable [public registration](./public-registration.md) to let users create their own accounts.
- **Mixed environments**: Combine user sync for administrative accounts with public registration for end users.

## Further Reading

- [Creating Users](./creating-users.md) -- default admin user and GraphQL-based creation
- [User Sync from JSON](./user-sync.md) -- declarative bulk provisioning
- [Public Registration](./public-registration.md) -- self-service account creation
- [Passkey Management](./passkey-management.md) -- user-facing passkey operations
- [User 2FA Management](./user-2fa.md) -- admin-enforced two-factor authentication
