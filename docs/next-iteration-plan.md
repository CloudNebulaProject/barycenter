### Next Iteration Plan — OpenID Connect OP (dated 2025-11-24 16:48)

This plan builds on the current implementation (Authorization Code + PKCE, ID Token signing, UserInfo, client_secret_post and client_secret_basic, discovery, JWKS, dynamic registration). The goal of this iteration is to harden compliance, improve interoperability, and introduce a minimal authentication stub to replace the fixed demo subject.

Objectives
- Compliance hardening: headers, error models, metadata accuracy.
- Authentication stub: minimal user login and session handling to issue codes for a real subject instead of the demo placeholder.
- Documentation updates and basic validation scripts/tests.

Scope and tasks
1. Token endpoint response hygiene
   - Add headers per OAuth 2.0 recommendations:
     - Cache-Control: no-store
     - Pragma: no-cache
   - Ensure JSON error bodies conform to RFC 6749 (error, error_description, error_uri optional). Keep existing WWW-Authenticate for invalid_client. 

2. ID Token claims improvements
   - Include auth_time when the OP has a known authentication time for the end-user session (see task 3 for session stub).
   - Ensure kid in JWS header is set (already implemented) and alg matches discovery. Verify exp/iat handling and clock skew tolerance notes for verifiers (doc).

3. Minimal authentication + consent stub
   - Introduce a basic login flow used by /authorize:
     - GET /login renders a simple page (or JSON instruction) to submit username (subject) and a fixed password placeholder.
     - POST /login sets a secure, HTTP-only cookie session with subject and auth_time; redirects back to the original /authorize request (preserve request params via a return_to parameter).
     - If an active session cookie is present at /authorize, skip login.
   - Consent: for MVP, auto-consent to requested scopes; record a TODO for explicit consent later.
   - Optionally, persist sessions in-memory for this iteration; a DB table can be added in a later iteration.

4. Error handling and redirects at /authorize
   - Continue using redirect-based error responses per OIDC (error, error_description, state passthrough).
   - Validate and return errors for: missing/invalid parameters, unsupported response_type, scope lacking openid, PKCE missing/invalid.

5. Discovery metadata accuracy
   - Verify discovery includes: userinfo_endpoint, token_endpoint_auth_methods_supported [client_secret_post, client_secret_basic], code_challenge_methods_supported [S256], response_types_supported [code], id_token_signing_alg_values_supported [RS256]. (Current implementation already does this; re-check after changes.)

6. Documentation updates
   - Update docs/oidc-conformance.md to mention client_secret_basic support and the new login/session stub behavior.
   - Add a short README snippet or docs/flows.md with example end-to-end curl/browser steps including the login step.

7. Basic validation scripts/tests
   - Add a scripts/ directory (or docs snippets) with curl commands to verify:
     - Discovery document fields.
     - Authorization + login + token exchange (with PKCE S256) producing a valid ID Token and access token.
     - UserInfo with Bearer access token and proper WWW-Authenticate on failure.

Non-goals (deferred)
- Refresh tokens, rotation, revocation and introspection.
- Rich user model and persistence (beyond minimal session stub).
- OpenID Federation trust chain validation.
- Key rotation and multi-key JWKS.

Acceptance criteria
- /token responses include Cache-Control: no-store and Pragma: no-cache for both success and error responses.
- /token invalid_client responses continue to include a proper WWW-Authenticate: Basic realm header.
- ID Token includes auth_time when the user logs in during the flow (based on the session stub’s auth_time); includes nonce when provided; includes at_hash.
- /authorize uses the logged-in user from the new session cookie; if no session, prompts to login and returns to continue the flow; redirects carry state on error.
- Discovery still advertises capabilities accurately after changes.
- Docs updated to reflect client_secret_basic and the login/session stub.
- Example commands or scripts demonstrate a complete code flow using PKCE with a login step and successful token exchange and userinfo call.

Implementation notes
- Keep the session cookie scoped to the IdP origin; mark HttpOnly, Secure in production, SameSite=Lax.
- Use S256 exclusively for PKCE (plain not supported).
- Continue to generate/sign with RS256; ensure kid header is present and published in JWKS.
- Keep the issuer stable via server.public_base_url in production deployments.

Timeline and effort
- Estimated effort: 1–2 short iterations.
  - Day 1: headers, error refinements, discovery verification, docs updates.
  - Day 2: login/session stub, auth_time claim, validation scripts.
