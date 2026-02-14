# AMR and ACR Claims

Barycenter tracks how a user authenticated and includes this information in the [ID Token](../oidc/id-token.md) as standard OpenID Connect claims. Relying parties can use these claims to make authorization decisions based on the strength of the authentication.

## AMR -- Authentication Methods Reference

The `amr` claim is a JSON array of strings identifying the authentication methods used during the session. It is defined in [RFC 8176](https://www.rfc-editor.org/rfc/rfc8176).

### Supported Values

| AMR Value | Method                      | Description                                                        |
|-----------|-----------------------------|--------------------------------------------------------------------|
| `pwd`     | Password                    | The user entered a username and password.                          |
| `hwk`     | Hardware-bound key          | The user authenticated with a hardware-bound passkey (e.g., YubiKey, Titan Security Key, platform TPM) that cannot be synced or cloned. |
| `swk`     | Software key                | The user authenticated with a software or cloud-synced passkey (e.g., iCloud Keychain, Google Password Manager, 1Password). |

### How AMR Is Determined

The AMR array is built incrementally as the user authenticates:

| Authentication Event           | AMR After Event     |
|--------------------------------|---------------------|
| Password login                 | `["pwd"]`           |
| Passkey login (hardware-bound) | `["hwk"]`           |
| Passkey login (cloud-synced)   | `["swk"]`           |
| Password + 2FA (hardware key)  | `["pwd", "hwk"]`    |
| Password + 2FA (cloud key)     | `["pwd", "swk"]`    |

The passkey type (`hwk` vs `swk`) is determined by the authenticator's `backup_eligible` flag:

- **`backup_eligible = false`**: The credential is hardware-bound and cannot be transferred. AMR value: `hwk`.
- **`backup_eligible = true`**: The credential may be synced across devices via a cloud service. AMR value: `swk`.

This check is performed on every authentication, not just at registration, because the backup state can change over time.

### AMR in the ID Token

The `amr` claim appears as a top-level array in the ID token:

```json
{
  "iss": "https://auth.example.com",
  "sub": "user-uuid-123",
  "aud": "client-abc",
  "amr": ["pwd", "hwk"],
  "acr": "aal2",
  "auth_time": 1739557200,
  "..."
}
```

## ACR -- Authentication Context Class Reference

The `acr` claim is a string that indicates the overall assurance level of the authentication. Barycenter uses the NIST Authentication Assurance Levels (AAL) defined in [SP 800-63B](https://pages.nist.gov/800-63-3/sp800-63b.html).

### Supported Values

| ACR Value | Assurance Level               | Meaning                                             |
|-----------|-------------------------------|-----------------------------------------------------|
| `aal1`    | Authentication Assurance Level 1 | Single-factor authentication. The user proved their identity with one method (password alone or passkey alone). |
| `aal2`    | Authentication Assurance Level 2 | Two-factor authentication. The user proved their identity with two distinct methods (password + passkey). |

### How ACR Is Determined

The ACR value is set based on the `mfa_verified` flag in the session:

| `mfa_verified` | ACR     | Condition                                           |
|----------------|---------|-----------------------------------------------------|
| `0`            | `aal1`  | Only one authentication method has been used.       |
| `1`            | `aal2`  | Two authentication methods have been verified.      |

The transition from `aal1` to `aal2` happens during the [2FA flow](./2fa-flow.md) when the passkey verification succeeds and the session is upgraded.

### ACR in the ID Token

```json
{
  "acr": "aal2"
}
```

Relying parties can check this value to enforce minimum assurance levels:

```python
# Example: reject tokens that don't meet aal2
id_token = decode_id_token(token_string)
if id_token["acr"] != "aal2":
    raise InsufficientAuthenticationError("This action requires two-factor authentication")
```

## auth_time Claim

The `auth_time` claim records when the user's session was first created (the time of initial authentication). It is a Unix timestamp (seconds since epoch).

```json
{
  "auth_time": 1739557200
}
```

Key behaviors:

- `auth_time` is set when the session is created (during password login or passkey login).
- `auth_time` is **not updated** when the session is upgraded during 2FA. It always reflects the time of the first factor.
- Relying parties can use `auth_time` together with the `max_age` parameter to determine whether the authentication is fresh enough for their needs.

### Relationship with max_age

When a relying party includes `max_age` in the authorization request, Barycenter checks whether the session's `auth_time` is within the specified window:

```
current_time - auth_time <= max_age
```

If the session is too old, the user is required to re-authenticate. If `max_age` is less than 300 seconds, [context-based 2FA](./2fa-context-based.md) is also triggered.

## Combining AMR, ACR, and auth_time

Together, these three claims give relying parties a complete picture of the authentication:

| Claim       | Answers the Question                                |
|-------------|-----------------------------------------------------|
| `amr`       | **How** did the user authenticate? (methods used)   |
| `acr`       | **How strong** is the authentication? (assurance)   |
| `auth_time` | **When** did the user authenticate? (freshness)     |

### Example: Enforcing Strong, Fresh Authentication

A relying party protecting a payment flow might check all three:

```python
id_token = decode_id_token(token_string)

# Require two-factor authentication
assert id_token["acr"] == "aal2", "Payment requires 2FA"

# Require a hardware-bound key was used
assert "hwk" in id_token["amr"], "Payment requires hardware key"

# Require authentication within the last 5 minutes
assert time.time() - id_token["auth_time"] < 300, "Authentication too old"
```
