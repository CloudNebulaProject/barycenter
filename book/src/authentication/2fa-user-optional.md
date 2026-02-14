# User-Optional 2FA

> **Status**: This feature is planned but **not yet implemented**.

User-optional two-factor authentication will allow users to enable 2FA for their own accounts through a self-service interface, without requiring an administrator to set the flag.

## Planned Functionality

When implemented, this mode will provide:

- **Self-service enrollment**: Users will be able to enable 2FA from an account settings page, requiring them to register at least one passkey as part of the enrollment process.
- **Self-service disablement**: Users will be able to disable self-imposed 2FA from the same settings page, typically requiring a passkey verification to confirm the change.
- **Independent of admin enforcement**: User-optional 2FA will coexist with [admin-enforced 2FA](./2fa-admin-enforced.md). If an administrator has already mandated 2FA for a user, the user cannot disable it. If the user enables 2FA voluntarily, the administrator can still override the setting.

## How It Will Differ from Admin-Enforced 2FA

| Aspect               | Admin-Enforced                        | User-Optional (Planned)         |
|----------------------|---------------------------------------|---------------------------------|
| Who enables it       | Administrator via GraphQL API         | User via account settings UI    |
| Who can disable it   | Administrator only                    | User (unless admin also enforces) |
| Requires passkey     | Passkey must be enrolled beforehand   | Enrollment is part of the setup flow |
| Stored as            | `requires_2fa = 1` in `users` table  | Separate user-preference flag   |

## Current Alternatives

Until user-optional 2FA is available, the same outcome can be achieved through:

1. **Admin-enforced 2FA**: An administrator can enable 2FA for individual users using the `setUser2faRequired` mutation. See [Admin-Enforced 2FA](./2fa-admin-enforced.md).
2. **Context-based 2FA**: Applications can require 2FA for specific operations by requesting [high-value scopes](./2fa-context-based.md) or setting a low `max_age`.

## Tracking

This feature is tracked in the project's pending work. Contributions are welcome -- see [Contributing](../development/contributing.md) for guidelines.
