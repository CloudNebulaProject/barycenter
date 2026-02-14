# Context-Based 2FA

Context-based two-factor authentication triggers the second factor based on properties of the authorization request rather than a per-user flag. This allows applications to require stronger authentication for sensitive operations while keeping routine access frictionless.

## Trigger Conditions

Two conditions can independently trigger context-based 2FA:

### 1. High-Value Scopes

If the authorization request includes any scope that Barycenter considers high-value, 2FA is required regardless of the user's `requires_2fa` setting.

The following scopes are classified as high-value:

| Scope      | Rationale                                           |
|------------|-----------------------------------------------------|
| `admin`    | Administrative operations with broad system impact. |
| `payment`  | Financial transactions.                             |
| `transfer` | Asset or data transfer operations.                  |
| `delete`   | Destructive operations that remove data.            |

#### Scope Matching Logic

Barycenter evaluates the requested scopes during the authorization flow using an `is_high_value_scope()` check. The match is performed against the exact scope string:

```
Requested scopes: ["openid", "profile", "payment"]
                                          ^^^^^^^
                                    High-value scope detected --> 2FA required
```

If the authorization request contains `openid profile email`, no high-value scope is present and 2FA is not triggered by this condition.

#### Example Authorization Request

```
GET /authorize?
  client_id=abc123&
  redirect_uri=https://app.example.com/callback&
  response_type=code&
  scope=openid+payment&
  code_challenge=...&
  code_challenge_method=S256&
  state=xyz
```

Because the `payment` scope is included, Barycenter will require 2FA even if the user does not have `requires_2fa = 1`.

### 2. Fresh Authentication Requirement (max_age)

If the authorization request includes a `max_age` parameter with a value less than 300 seconds (5 minutes), Barycenter interprets this as a request for fresh, strong authentication and triggers 2FA.

This is useful when a relying party needs to ensure the user has recently proven their identity with a high level of assurance -- for example, before displaying sensitive account settings or confirming a critical action.

#### Evaluation Logic

```
max_age parameter present?
  |
  +-- No --> max_age does not trigger 2FA
  |
  +-- Yes --> max_age < 300?
               |
               +-- No --> max_age does not trigger 2FA
               |
               +-- Yes --> 2FA required
```

#### Example Authorization Request

```
GET /authorize?
  client_id=abc123&
  redirect_uri=https://app.example.com/callback&
  response_type=code&
  scope=openid+profile&
  max_age=60&
  code_challenge=...&
  code_challenge_method=S256&
  state=xyz
```

Even though no high-value scope is requested, the `max_age=60` parameter triggers 2FA because 60 < 300.

## Interaction with Admin-Enforced 2FA

Context-based 2FA is evaluated independently of [admin-enforced 2FA](./2fa-admin-enforced.md). The checks are additive:

| User `requires_2fa` | High-Value Scope | `max_age < 300` | 2FA Required? |
|----------------------|------------------|------------------|---------------|
| `0`                  | No               | No               | No            |
| `0`                  | Yes              | No               | Yes           |
| `0`                  | No               | Yes              | Yes           |
| `1`                  | No               | No               | Yes           |
| `1`                  | Yes              | Yes              | Yes           |

If any condition evaluates to "2FA required" and the session does not already have `mfa_verified = 1`, the user is redirected to `/login/2fa`.

## Session Handling

When context-based 2FA is triggered:

1. The user has already authenticated with a password, creating a session with `mfa_verified = 0`.
2. Barycenter evaluates the authorization request and determines 2FA is needed.
3. The authorization parameters are preserved in the session.
4. The user is redirected to `/login/2fa`.
5. After successful passkey verification, the session is upgraded to `mfa_verified = 1`, `acr = "aal2"`.
6. The user is redirected back to `/authorize` where the flow continues.

If the user already has a valid session with `mfa_verified = 1` (from a previous 2FA authentication in the same session), the second factor is not requested again.

## Use Cases

### Step-Up Authentication

A common pattern is to request basic scopes for normal operations and high-value scopes only when needed:

```
# Normal access -- no 2FA
scope=openid profile email

# Administrative action -- triggers 2FA
scope=openid admin

# Payment confirmation -- triggers 2FA
scope=openid payment
```

### Confirm Sensitive Action

A relying party can use `max_age` to require fresh authentication before displaying sensitive information:

```
# User is already logged in, but RP wants fresh strong auth
# before showing account deletion page
GET /authorize?...&scope=openid+delete&max_age=60
```

This ensures the user has authenticated within the last 60 seconds and has completed 2FA, providing high confidence that the current user is the account owner.
