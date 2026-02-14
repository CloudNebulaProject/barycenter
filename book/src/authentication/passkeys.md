# Passkey / WebAuthn

Barycenter supports passwordless authentication using [WebAuthn](https://www.w3.org/TR/webauthn-3/) (also known as FIDO2) passkeys. Passkeys provide phishing-resistant authentication tied to cryptographic key pairs stored on the user's device or in a cloud keychain.

## What Are Passkeys?

A passkey is a WebAuthn credential -- a public/private key pair where the private key never leaves the authenticator (device, security key, or cloud keychain). During authentication, the authenticator signs a challenge from the server, proving possession of the private key without transmitting any shared secret.

Passkeys offer several advantages over passwords:

- **Phishing-resistant**: credentials are bound to the relying party's origin, so they cannot be replayed on a different domain.
- **No shared secrets**: the server stores only the public key, so a database breach does not expose authentication credentials.
- **User-friendly**: on supported devices, authentication is a single biometric or PIN prompt.

## Authentication Modes

Barycenter supports passkeys in two distinct roles:

### Single-Factor Passkey Login

A passkey can serve as the sole authentication method. When a user authenticates with a passkey alone, the session is created with:

- `amr`: `["hwk"]` or `["swk"]` (depending on passkey type)
- `acr`: `"aal1"` (single-factor)

This mode is suitable for everyday access where the passkey itself provides sufficient assurance. See [Authenticating with a Passkey](./passkey-authentication.md).

### Two-Factor with Passkey as Second Factor

A passkey can serve as the second factor after a password login. When combined with password authentication, the session is upgraded to:

- `amr`: `["pwd", "hwk"]` or `["pwd", "swk"]`
- `acr`: `"aal2"` (two-factor)

This mode is triggered by [admin-enforced 2FA](./2fa-admin-enforced.md), [context-based 2FA](./2fa-context-based.md), or future user-optional 2FA settings. See [Two-Factor Authentication](./two-factor.md).

## Passkey Classification: hwk vs swk

Barycenter classifies passkeys based on their backup state, which indicates whether the credential can be synced across devices:

| AMR Value | Classification     | Examples                                         | Backup Eligible |
|-----------|--------------------|--------------------------------------------------|-----------------|
| `hwk`     | Hardware-bound key  | YubiKey, Titan Security Key, platform TPM        | No              |
| `swk`     | Software/cloud key  | iCloud Keychain, Google Password Manager, 1Password | Yes           |

The distinction is determined by examining the `backup_eligible` flag reported by the authenticator during registration and authentication. Hardware-bound passkeys that cannot be cloned or synced receive the `hwk` designation, while cloud-synced passkeys receive `swk`.

Both types are valid for authentication and 2FA. The AMR value is included in the [ID Token](../oidc/id-token.md) to allow relying parties to make authorization decisions based on authenticator strength.

## WASM Client

Browser-side WebAuthn operations are handled by a Rust WASM module compiled from the `client-wasm/` crate. The WASM client provides:

| Function                      | Description                                           |
|-------------------------------|-------------------------------------------------------|
| `supports_webauthn()`         | Check if the browser supports WebAuthn                |
| `supports_conditional_ui()`   | Check if the browser supports passkey autofill        |
| `register_passkey(options)`   | Create a new passkey credential                       |
| `authenticate_passkey(options, mediation)` | Authenticate with an existing passkey    |

The WASM module is loaded by the login page and abstracts the browser's `navigator.credentials` API into a clean interface that communicates with Barycenter's WebAuthn endpoints. See [How Passkeys Work](./passkeys-how.md) for architectural details.

## Passkey Management

Users can manage their registered passkeys through the account API:

| Endpoint                                   | Method   | Description                   |
|--------------------------------------------|----------|-------------------------------|
| `/account/passkeys`                        | `GET`    | List all registered passkeys  |
| `/account/passkeys/:credential_id`         | `DELETE` | Remove a passkey              |
| `/account/passkeys/:credential_id`         | `PATCH`  | Update passkey friendly name  |

Each passkey record stores the full WebAuthn `Passkey` object as JSON, including the signature counter for clone detection and the backup state for classification. Friendly names help users identify which device or authenticator a credential belongs to.

## Further Reading

- [How Passkeys Work](./passkeys-how.md) -- WebAuthn ceremonies and WASM architecture
- [Registering a Passkey](./passkey-registration.md) -- step-by-step registration flow
- [Authenticating with a Passkey](./passkey-authentication.md) -- step-by-step authentication flow
- [Conditional UI / Autofill](./conditional-ui.md) -- browser autofill integration
- [Two-Factor Authentication](./two-factor.md) -- using passkeys as a second factor
