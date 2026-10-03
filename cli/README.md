# Barycenter account invitations

`barycenter-admin` issues a single-use invitation through the daemon's dedicated
admin listener and sends it using authenticated, TLS-verified SMTP. Recipients
choose their own password; the operator does not generate or email passwords.
The CLI uses Python's standard library and is distributed as a Homebrew formula.

## Install

For this pilot, install the formula from a tap containing `Formula/barycenter-admin.rb`:

```sh
brew install toasty/barycenter-onboarding/barycenter-admin
barycenter-admin --help
```

The operator Mac's pilot tap pins an immutable released source archive and
checksum. Upgrade the tap/formula with each CLI release; `--HEAD` builds main for
development. Installing the CLI does not upgrade the remote daemon. Password
recovery requires daemon v0.2.0-beta.14 or later.

## Configure

Create `~/.config/barycenter-admin/config.json` with mode **0600**:

```json
{
  "admin_url": "http://127.0.0.1:18081",
  "public_url": "https://auth.aopc.cloud",
  "admin_token_file": "~/.config/barycenter-admin/admin-token",
  "smtp": {
    "host": "mail.wegmueller.it",
    "port": 587,
    "tls": "starttls",
    "from": "notes@aopc.cloud",
    "username": "notes@aopc.cloud",
    "password_file": "~/.config/barycenter-admin/smtp-password"
  }
}
```

Credential files must belong to the invoking user and have mode 0600. Obtain the
new onboarding capability and SMTP credential through the user's authorized
secret-delivery path. Do not borrow another workload's identity. The onboarding
capability is independent of OIDC client and SMTP credentials.

The server no longer creates a known-password default account. Existing accounts
are preserved; enroll the first user through an invitation or explicit user sync.

The server enables its new admin routes only when
`BARYCENTER_ONBOARDING_ADMIN_TOKEN_FILE` points to a provisioned random token of
at least 32 characters. Its `server.public_base_url` must be configured. The
onboarding endpoints require Bearer authentication; existing GraphQL endpoints
retain their current network security model and are not exposed by the public
route. Keep the admin listener private. For the homelab, use:

```sh
kubectl -n community-notes port-forward service/barycenter-admin 18081:8081
```

Alternatively set `admin_url` to a reachable, TLS-verified private admin endpoint.
The CLI allows plain HTTP only on loopback, rejects redirects, and does not
inherit HTTP proxy credentials/settings.

## Issue and send

```sh
barycenter-admin invite alice@example.org --username alice
```

Default validity is 24 hours. Choose a lifetime from 5 minutes to 7 days:

```sh
barycenter-admin invite alice@example.org --username alice --expires-in 172800
```

This replaces any unredeemed invitation for the same username and invalidates
its older token. Existing accounts cannot be invited using this API; use the dedicated reset command below.
The recipient opens the link and chooses a password of 12–128 UTF-8 bytes.
Successful redemption creates one enabled account with verified email and a
stable subject. No login session is automatically created. Invitations do not replace password recovery or account disablement.

Tokens contain 256 bits of OS randomness. Only SHA-256 token digests are stored
by the daemon. A transaction claims the unexpired invitation and creates the user
atomically, so replay/concurrent redemption cannot create a second account.
The link carries the token in a URL fragment; the page removes it from history
before submitting a JSON POST. GET requests and email scanners do not redeem it.
Apply production rate/body limits to the public activation endpoint, as for login.

## Retry or revoke

Before SMTP, the CLI saves a mode-0600 receipt under a mode-0700 directory:
`~/.local/state/barycenter-admin/invitations/`. It prints the receipt path, never
its token or activation URL. Treat receipts like passwords. To prepare without
sending email, use `invite ... --no-send`.

If SMTP fails, retry the **same** receipt:

```sh
barycenter-admin send --receipt ~/.local/state/barycenter-admin/invitations/UUID.json
```

No new invitation is issued by `send`. SMTP acknowledgement can be ambiguous;
a retry may deliver the same link twice. The server still allows one redemption.
“Accepted by SMTP” does not prove inbox delivery. Delete local receipts after
acceptance or expiry; the CLI does not automatically remove them.

```sh
barycenter-admin revoke --username alice
```

Revocation invalidates an invitation and does not disable an activated account.
An expired token needs a fresh invitation. No real-user emails are sent as part
of development tests; SMTP is mocked in CLI tests.

## Validation

```sh
python3 -m unittest discover -s cli/tests -v
cargo test --lib onboarding::tests
```

Tests cover authenticated issuance, token hashing, expiry, reissue, revocation,
weak-password retries, verified-account creation, replay and concurrent
redemption, private receipt modes, TLS/URL validation and failed SMTP retries.

## Reset an existing account password

```sh
barycenter-admin reset-password alice
barycenter-admin revoke-reset --username alice
```

The server chooses the account's existing email address. There is no
recipient override. Disabled accounts, missing email and missing accounts are ineligible. Default validity is one hour (`--expires-in` accepts 300–86400
seconds). `--no-send` saves a private receipt; `send --receipt PATH` retries its
email without issuing another token. Reissue or revoke invalidates old links.

The recipient chooses a 12–128 byte password through `/password-reset`. Tokens
are 256-bit, digest-only in the database, carried in a URL fragment, removed from
browser history and redeemed only by POST. Redemption is atomic and single-use.
It preserves the subject, email address, enabled status and MFA settings. Possession
of the mailed token verifies the stored email when redemption completes. A link cannot
survive an intervening password/email change or reactivate a disabled account.
It deletes the user's Barycenter sessions, authorization/device codes and revokes
access/refresh tokens. Independently maintained relying-party sessions (including
Docs sessions) require that application's logout/session expiry; this is not OIDC
back-channel logout. Existing passkeys and MFA requirements remain in place.

For homelab TLS, configure `admin_url` as `https://barycenter-admin.lab.home` and
`admin_ca_file` as `~/.config/barycenter-admin/ca-bundle.pem`. The file contains
public CA certificates, never private keys. HTTPS verification stays enabled.
The admin reset paths must be routed only on the internal gateway; only the reset
page, script and POST redemption endpoint belong on the public auth gateway.
