# Error reporting

Errors must explain the failed operation, the known cause, and an actionable next
step. Preserve uncertainty and partial completion. An HTTP status alone is not an
operator-facing diagnosis.

## Rust errors and reports

Use typed `thiserror` errors for conditions callers must distinguish, and derive
`miette::Diagnostic` for stable codes, useful help, and documentation links.
Barycenter already uses miette; adding eyre is not necessary for context wrapping.
Use `WrapErr` at application boundaries to identify the operation while preserving
the source. Convert external errors with `IntoDiagnostic` only when they do not
already carry diagnostic metadata. Do not flatten typed errors into strings.
Enable fancy rendering in top-level applications rather than reusable libraries.

Define errors by actionable domain condition rather than only by dependency:
`invitation_pending`, `invitation_expired`, `not_found`, `disabled`,
`email_missing`, and `email_invalid` need different recovery instructions.
For reset issuance, an absent user requires checking invitation state before
claiming an invitation is pending. A local receipt cannot establish server state.

## HTTP boundary

Authenticated admin APIs should map typed errors to an explicit JSON contract:

```json
{
  "code": "barycenter::account::invitation_pending",
  "message": "Cannot reset the password: the account has not been activated.",
  "help": "Use or resend the existing invitation.",
  "request_id": "request-correlation-id"
}
```

Keep HTTP status semantics, but branch on stable codes rather than message text.
Codes are namespaced with `barycenter::`; messages may evolve independently.
Return only safe operator-facing fields. Retain underlying unexpected errors in
redacted internal diagnostics correlated by request ID; do not discard them in
an `internal()` helper. Never serialize an entire debug report into HTTP.
Detailed account states belong behind admin authorization. Public recovery
responses must not disclose account existence or eligibility.

This is the target server contract. The Python CLI accepts it now; existing
plain-text endpoints still need a separate server implementation.

## CLI behavior

The Python CLI renders equivalent diagnostic fields without a Rust dependency.
Use stderr for errors and exit nonzero. Include operation context, a stable code,
a useful message, help when available, and HTTP status/request ID when known.
`--error-format json` emits a diagnostic object on stderr for automation; it does
not change successful command output or argparse usage errors.

Read error responses with a size limit and validate their field types and lengths.
Never dump HTML/proxy bodies, arbitrary legacy text, raw transport exceptions,
credentials, password/reset URLs, or receipt contents. Sanitize terminal control
characters. A recognized legacy message can be shown, but a generic 409 must not
be promoted to a specific diagnosis. Distinguish configuration, transport, TLS,
HTTP, and SMTP errors and explain how to address each.

Report each completed stage accurately. If issuance succeeds and email delivery
fails, preserve the private receipt and print a shell-quoted `send --receipt`
command using the same configuration. Do not issue a second token as a delivery
retry. If a request or SMTP delivery has an unknown outcome, say so. If issuance
succeeds but receipt validation/storage fails, say that no email was sent and
explain that local recovery is required before issuing a replacement.

Do not prescribe retrying an expired link; distinguish invitation and reset
receipts in the recovery instructions. Never automatically send mail, reactivate
an account, or change its email in response to an error.

## Validation

Test different domain conditions, legacy/structured/malformed/oversized HTTP
errors, terminal controls, safe fallback output, and failures after successful
issuance. Check that delivery retries preserve receipts and do not issue another
link. Assert useful fields and recovery behavior rather than decorative layout.
For Python CLI changes, run `python3 -m unittest discover -s cli/tests -v`.
For Rust changes, use the repository's `cargo nextest` workflow.

References: [eyre](https://docs.rs/eyre/latest/eyre/),
[miette](https://docs.rs/miette/latest/miette/),
[Diagnostic](https://docs.rs/miette/latest/miette/trait.Diagnostic.html), and
[IntoDiagnostic](https://docs.rs/miette/latest/miette/trait.IntoDiagnostic.html).
