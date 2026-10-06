# Login copy rationale

Strings live in `docs/login-copy.json` and are injected as `{{copy_KEY}}`. They
are plain text and never contain user values. The template shows the provider
hostname (`issuer_host`), local domain and username itself, so the copy points
at them ("the provider shown above", "this account") rather than repeating them.

## Flow assumptions

- **Identifier step** has no password field. The copy asks for an *account
  name*, not an email address. The hint gives `username@domain` only to name
  the provider that holds the account. It does not suggest that any email
  address works.
- **Foreign domain** handling: `identifier_body` says the user "will be taken
  there to enter your password". That matches the server redirect. It promises
  no single sign-on, no passwordless federation and no matching by email. The
  copy says "partner provider" instead of "trusted federation" to avoid jargon.
- **Password step** happens only at the home provider. `password_body` names
  where the user is signing in by pointing at the hostname in the header, which
  helps against phishing. `change_account` goes back to the identifier step.

## Errors

- `generic_error` is the same whether the account is unknown or the password is
  wrong, so it never confirms that an account exists. It names the combination
  ("that account and password"), does not blame the user, and gives the most
  likely fix (re-check the password) plus the only real recovery path. Because
  the account stays on screen, it tells the user to check their password rather
  than retype everything.
- `identifier_error` is shown when the account name is empty or too long. It
  restates the expected format, so it works for both cases without explaining
  limits. It doesn't mention passwords, because no password step has happened.
- `unknown_provider` only shows the domain configuration, which is effectively
  public. It does not reveal any individual account.
- `no_auth_request` covers a missing or expired authorization request. It sends
  the user back to the app that started sign-in, because this page cannot
  restart the flow by itself.

## Recovery

- Invitation recipients must choose a password using their email link before signing in. The identifier and generic credential-error copy point them back to that link without revealing account state.

- No self-service "Forgot password" link or button. The only path is an
  administrator sending a link by CLI, so the copy says "ask your
  administrator".
- `recovery_help` says links expire and tells the user to ask for a new one.
  This covers the current case: an earlier link expired unused and a new one has
  been sent.
- The copy never says a reset happened or that the password changed. Nothing
  changes until the link is redeemed. It also never says an email "was
  delivered" or gives an arrival time. SMTP accepting the message does not
  guarantee it reaches the inbox, so the copy only suggests checking spam.
- `recovery_admin` says the administrator *sends a link*, and that the user
  picks the new password through it. It must not suggest that the administrator
  sets or knows the password.

## Continuation page

- `continuation_title` / `continuation_body` appear on the short same-origin
  page that is shown before the browser automatically opens the local
  `/authorize` again. The body says sign-in *isn't finished yet*, so it never
  suggests that authentication, consent or any second factor has completed
  before the callback.
- The fallback link reuses the existing `continue` key ("Continue"), and the
  body refers to it by that label. It doesn't mention a time, because how long
  the redirect takes depends on the browser.

## Passkeys

- The current UI does not show the passkey strings. `login.js` deliberately
  leaves passkeys unconnected: the earlier inline flow was blocked by CSP, and
  its finish-response contract was wrong. The strings are kept for a future,
  validated integration. When they are used, they offer passkeys as an
  *option* and never say that one is enrolled.
- `passkey_failed` does not distinguish "no passkey" from "cancelled" or
  "verifier rejected". That avoids revealing enrollment and covers the common
  case where the user dismissed the prompt.
- The copy says nothing about 2FA or MFA, because the login page does not show
  that step.

## Suggested next steps (not deployed)

1. Admin flow: show when the last reset link was sent and when it expires
   (`user2faStatus`-style query), so support can answer "has my link expired?"
   without guessing.
2. Reset landing page: give expired links a clear message ("This link has
   expired. Ask your administrator for a new one.") that matches
   `recovery_help`, separate from a "link already used" message.
3. Optionally let operators add a contact address or URL that gets appended to
   `recovery_admin` and `invitation_info`, so "your administrator" points to a
   real contact.
