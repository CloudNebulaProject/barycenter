# Two-Factor Authentication

Barycenter supports two-factor authentication (2FA) to provide a higher level of assurance for sensitive operations. When 2FA is required, users must authenticate with both a password and a passkey before the authorization flow can proceed.

## Overview

Two-factor authentication in Barycenter means combining two distinct authentication methods:

1. **First factor**: Password authentication (`amr: "pwd"`)
2. **Second factor**: Passkey verification (`amr: "hwk"` or `"swk"`)

After both factors are verified, the session is upgraded to:

- `amr`: `["pwd", "hwk"]` or `["pwd", "swk"]`
- `acr`: `"aal2"` (Authentication Assurance Level 2)
- `mfa_verified`: `1`

These values are propagated to the [ID Token](../oidc/id-token.md) so that relying parties can make authorization decisions based on the strength of the authentication.

## Three Modes of 2FA

Barycenter provides three mechanisms for triggering two-factor authentication, each suited to different operational needs:

### 1. Admin-Enforced 2FA

An administrator sets a per-user flag requiring 2FA for every login. This is the strongest enforcement mode -- the user cannot bypass the second factor regardless of what they are accessing.

- Configured via the [Admin GraphQL API](../admin/graphql-api.md) using the `setUser2faRequired` mutation.
- Stored as `requires_2fa = 1` in the `users` table.
- Takes effect on the next login attempt.

See [Admin-Enforced 2FA](./2fa-admin-enforced.md) for details.

### 2. Context-Based 2FA

The authorization request itself triggers 2FA based on the sensitivity of the operation. This allows applications to require stronger authentication for high-risk actions without mandating 2FA for routine access.

Two conditions can trigger context-based 2FA:

- **High-value scopes**: Authorization requests that include scopes such as `admin`, `payment`, `transfer`, or `delete`.
- **Fresh authentication**: Authorization requests with `max_age` less than 300 seconds, indicating the relying party requires a recent, strong authentication.

See [Context-Based 2FA](./2fa-context-based.md) for details.

### 3. User-Optional 2FA

Users will be able to enable 2FA for their own accounts through a self-service settings page, independent of administrator policy.

> **Note**: This mode is not yet implemented. See [User-Optional 2FA](./2fa-user-optional.md) for the planned functionality.

## When Is 2FA Triggered?

During the authorization flow, Barycenter evaluates whether 2FA is required by checking the following conditions in order:

| Check                                      | Trigger Condition                              |
|--------------------------------------------|------------------------------------------------|
| User has `requires_2fa = 1`                | Admin-enforced 2FA is active for this user.    |
| Requested scope includes a high-value scope| `admin`, `payment`, `transfer`, or `delete`.   |
| `max_age` parameter is less than 300       | Relying party requires fresh strong auth.      |

If any condition is met and the current session does not already have `mfa_verified = 1`, the user is redirected to `/login/2fa` to complete the second factor.

## 2FA Flow Summary

The high-level 2FA flow is:

1. User authenticates with password at `/login`.
2. A **partial session** is created with `mfa_verified = 0`.
3. Barycenter determines that 2FA is required.
4. User is redirected to `/login/2fa`.
5. User completes passkey verification via `/webauthn/2fa/start` and `/webauthn/2fa/finish`.
6. The session is **upgraded**: `mfa_verified = 1`, `acr = "aal2"`, `amr` includes both methods.
7. User is redirected back to `/authorize` to complete the OAuth flow.

See [2FA Flow Walkthrough](./2fa-flow.md) for a detailed sequence diagram.

## Passkey Enrollment Requirement

Two-factor authentication requires that the user has at least one registered passkey. If a user has `requires_2fa = 1` but no enrolled passkeys, the 2FA step cannot be completed.

Administrators should ensure that users enroll a passkey before enabling mandatory 2FA. The [user2faStatus](../admin/user-2fa.md) GraphQL query can check whether a user has passkeys enrolled.

## Further Reading

- [Admin-Enforced 2FA](./2fa-admin-enforced.md) -- per-user enforcement via GraphQL
- [Context-Based 2FA](./2fa-context-based.md) -- scope and max_age triggers
- [User-Optional 2FA](./2fa-user-optional.md) -- planned self-service enrollment
- [2FA Flow Walkthrough](./2fa-flow.md) -- complete sequence diagram
- [AMR and ACR Claims](./amr-acr.md) -- how authentication strength is represented in tokens
