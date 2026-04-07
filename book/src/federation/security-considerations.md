# Federation Security

Federated identity introduces trust boundaries that do not exist in a single-instance deployment. This page covers the security mechanisms Barycenter provides, the threats they address, and the configuration options available to operators.

## Verification Layers

As described in the [overview](overview.md), Barycenter verifies peers through up to three layers. Each layer protects against a different class of attack.

### Layer 1: WebFinger Resolution

**What it checks:** The domain in the federated identifier (e.g., `wegmueller.it` in `toasty@wegmueller.it`) has a WebFinger record pointing to the claimed OIDC issuer URL.

**What it protects against:** An attacker who registers a Barycenter instance and claims to be the IdP for a domain they do not control. Without a valid WebFinger record (which requires DNS control over the domain), the claim is rejected.

**Limitations:** If the attacker compromises the webfingerd instance or gains DNS control over the target domain, this layer can be bypassed.

### Layer 2: OIDC Discovery

**What it checks:** The issuer URL serves a valid `/.well-known/openid-configuration` document, the `issuer` field in that document matches the expected URL, and the JWKS endpoint is reachable.

**What it protects against:** A mismatch between the WebFinger record and the actual OIDC provider. For example, if a WebFinger record points to `https://auth.example.com` but that URL does not serve OIDC metadata, verification fails.

**Limitations:** An attacker who controls the server at the issuer URL can serve valid-looking OIDC metadata.

### Layer 3: Entity Proof

**What it checks:** The peer provides a cryptographic proof demonstrating control of the private key corresponding to the public key in its JWKS. This is typically a signed challenge-response exchange.

**What it protects against:** DNS hijack or CDN compromise scenarios where an attacker can serve content at the issuer URL but does not possess the original signing keys. Without the private key, the attacker cannot produce a valid entity proof.

**Limitations:** If the attacker obtains the peer's private signing key, this layer is bypassed.

### Configuring the Minimum Verification Level

```toml
[federation]
enabled = true
min_verification_level = "discovery_only"  # or "entity_proof"
```

| Level | Layers required | Recommended for |
|---|---|---|
| `discovery_only` | 1 + 2 | Most deployments; provides strong assurance when combined with HTTPS |
| `entity_proof` | 1 + 2 + 3 | High-security environments; protects against DNS and infrastructure compromise |

## JWKS Pinning

When Barycenter first verifies a peer, it fetches the peer's JWKS (public signing keys). JWKS pinning controls how Barycenter handles key changes after the initial verification.

### Pinning Modes

**`trust_discovery`** (default): Barycenter fetches the peer's JWKS on every token validation. If the peer rotates keys, Barycenter automatically picks up the new keys. This is the most flexible mode but offers the least protection against key compromise at the peer.

**`pin_on_first_use`**: Barycenter records the peer's JWKS on first verification and rejects tokens signed by keys not in the pinned set. If the peer rotates keys, the admin must explicitly update the pinned keys. This is analogous to SSH's "trust on first use" (TOFU) model.

**`pin_explicit`**: The admin provides the peer's expected JWKS (or a key fingerprint) when adding the peer. Only tokens signed by the explicitly pinned keys are accepted. This is the most secure mode but requires manual key management.

Configure pinning when adding a peer:

```graphql
mutation {
  addTrustedPeer(
    domain: "wegmueller.it"
    issuerUrl: "https://auth.wegmueller.it"
    clientId: "clt_abc123"
    clientSecret: "sec_xyz789"
    mappingPolicy: "auto_link_by_email"
    jwksPinning: "pin_on_first_use"
  ) {
    success
    peer { domain jwksPinning }
  }
}
```

To update pinned keys after a peer rotates:

```graphql
mutation {
  refreshPeerJwks(domain: "wegmueller.it") {
    success
    message
    previousKeyIds
    currentKeyIds
  }
}
```

## ACR Trust Propagation

When a user authenticates at a federated peer, the peer's ID token includes an `acr` (Authentication Context Reference) claim indicating the authentication strength (e.g., `aal1` for single-factor, `aal2` for two-factor).

Barycenter must decide whether to trust the peer's ACR claim or assign its own. This is controlled by the `trust_peer_acr` setting on each peer.

| Setting | Behavior |
|---|---|
| `true` | The peer's ACR claim is accepted and propagated to the local session. If the peer reports `aal2`, the local session reflects `aal2`. |
| `false` (default) | The peer's ACR claim is ignored. The local session is assigned `aal1` regardless of the peer's claim. If `aal2` is required locally, the user must complete a local 2FA step. |

```graphql
mutation {
  updateTrustedPeer(
    domain: "wegmueller.it"
    trustPeerAcr: true
  ) {
    success
    peer { domain trustPeerAcr }
  }
}
```

**Recommendation:** Only enable `trust_peer_acr` for peers you fully trust to enforce authentication strength equivalent to your own policies. If a peer has weaker 2FA requirements, trusting their ACR claim could allow users to bypass your local 2FA requirements.

## Peer Compromise Scenarios

### Scenario: A Trusted Peer's Signing Key Is Compromised

**Impact:** An attacker with the peer's signing key can forge ID tokens for any user at that peer's domain. If your instance trusts that peer, the attacker can log in as any federated user from that domain.

**Mitigation:**

1. Immediately suspend the peer:
   ```graphql
   mutation { suspendPeer(domain: "compromised-peer.com") { success } }
   ```
2. Invalidate existing sessions for users from that peer.
3. If using `pin_on_first_use` or `pin_explicit`, the compromised keys are already pinned -- they must be revoked. Remove the peer and re-add it after the peer has rotated keys.
4. Audit federated identity links for suspicious activity.

### Scenario: A Trusted Peer's Admin Account Is Compromised

**Impact:** The attacker can create users at the peer, potentially with email addresses matching your local accounts. With `auto_link_by_email`, this could allow account takeover.

**Mitigation:**

- Use `existing_only` mapping for high-value peers.
- Monitor the `federatedIdentities` query for unexpected new links.
- Consider requiring `entity_proof` verification level, which makes it harder for a compromised admin to impersonate the peer from a different infrastructure.

### Scenario: WebFinger Service Is Compromised

**Impact:** An attacker could redirect WebFinger lookups to a rogue OIDC issuer.

**Mitigation:**

- JWKS pinning (`pin_on_first_use` or `pin_explicit`) prevents the rogue issuer from being accepted unless it has the original signing keys.
- `entity_proof` verification catches rogue issuers that cannot produce a valid cryptographic proof.
- Monitor webfingerd logs for unauthorized resource modifications.

## Client Secret Storage

Federation client secrets (used for code exchange with peers) are stored in the database. In production:

- Use PostgreSQL with disk encryption for data at rest.
- Restrict database access to the Barycenter process only.
- Consider rotating client secrets periodically and updating the peer configuration on both sides.

Client secrets are redacted from debug logs and admin API query results (the API returns a masked value like `sec_***`).

## Security Checklist for Federation Deployments

- [ ] WebFinger integration is configured with HTTPS.
- [ ] `min_verification_level` is set to an appropriate level for your threat model.
- [ ] Identity mapping policies are reviewed per peer (avoid `auto_provision` for untrusted peers).
- [ ] `trust_peer_acr` is disabled for peers with unknown or weaker authentication policies.
- [ ] JWKS pinning is configured (`pin_on_first_use` at minimum for sensitive deployments).
- [ ] The admin GraphQL API is not exposed to the public internet.
- [ ] Database backups include the federated identity links table.
- [ ] A process exists for suspending peers in case of compromise.
- [ ] Federation client secrets are rotated periodically.
