# Identity Mapping Policies

When a user logs in through a federated peer for the first time, Barycenter must decide how to represent that user locally. The identity mapping policy, configured per peer, controls this decision. Choosing the right policy is a trade-off between security and convenience.

## The Three Policies

### `existing_only`

The most restrictive policy. Federated login succeeds only if an administrator has already linked the federated identity to a local account. No automatic linking or account creation occurs.

**How it works:**

1. User `toasty@wegmueller.it` authenticates at the peer IdP.
2. Barycenter receives the ID token with `sub: "user_abc123"` from `auth.wegmueller.it`.
3. Barycenter looks up the federated identity table for a row matching `peer_domain=wegmueller.it` and `peer_subject=user_abc123`.
4. If a mapping exists, the user is logged in as the linked local account.
5. If no mapping exists, login is denied with an error.

**Pre-linking an identity:**

Administrators create identity links through the admin GraphQL API:

```graphql
mutation {
  linkFederatedIdentity(
    localUserId: "usr_local456"
    peerDomain: "wegmueller.it"
    peerSubject: "user_abc123"
    peerEmail: "toasty@wegmueller.it"
  ) {
    success
    message
  }
}
```

**When to use:** High-security environments where every federated user must be explicitly approved. Suitable when the number of federated users is small and known in advance.

### `auto_link_by_email`

A balanced policy. On first federated login, Barycenter checks whether a local account exists with the same email address as the federated identity. If a match is found, the identities are linked automatically. If no match is found, login is denied.

**How it works:**

1. User `toasty@wegmueller.it` authenticates at the peer IdP.
2. Barycenter receives the ID token containing `email: "toasty@wegmueller.it"`.
3. Barycenter searches for a local account with email `toasty@wegmueller.it`.
4. If a local account is found, the federated identity is linked to it and the user is logged in.
5. If no local account matches, login is denied.
6. On subsequent logins, the existing link is used directly (no email re-matching).

**Important considerations:**

- This policy trusts the peer's email claim. If the peer does not verify email addresses, an attacker could claim an arbitrary email to gain access to a local account.
- The link is created once and is permanent. If the user's email changes at the peer, the existing link remains valid.
- If multiple local accounts share the same email, the link is ambiguous and login is denied. Ensure email uniqueness in your user database.

**When to use:** Organizations where users have accounts on multiple Barycenter instances under the same email address. Good for small communities and teams where email addresses are trustworthy.

### `auto_provision`

The most permissive policy. If no local account matches the federated identity, Barycenter creates a new local account automatically using claims from the peer's ID token.

**How it works:**

1. User `toasty@wegmueller.it` authenticates at the peer IdP.
2. Barycenter receives the ID token with `sub`, `email`, `name`, and other claims.
3. Barycenter checks for an existing identity link (uses it if found).
4. If no link exists, checks for a local account with a matching email (links if found).
5. If no local account matches, creates a new local account using the claims from the ID token and links it.
6. The user is logged in.

**Provisioned account details:**

- Username: derived from the email address (the local part, e.g., `toasty` from `toasty@wegmueller.it`). If a collision exists, a numeric suffix is appended.
- Email: taken from the peer's `email` claim.
- Display name: taken from the peer's `name` claim, if present.
- Password: not set (the user authenticates exclusively through federation).

**When to use:** Open communities where you want frictionless access for users from trusted peers. Suitable when the administrative overhead of pre-provisioning accounts is not justified.

## Setting the Policy Per Peer

The mapping policy is specified when adding a trusted peer:

```graphql
mutation {
  addTrustedPeer(
    domain: "wegmueller.it"
    issuerUrl: "https://auth.wegmueller.it"
    clientId: "clt_abc123"
    clientSecret: "sec_xyz789"
    mappingPolicy: "auto_link_by_email"
  ) {
    success
    peer { domain mappingPolicy }
  }
}
```

To change the policy for an existing peer:

```graphql
mutation {
  updateTrustedPeer(
    domain: "wegmueller.it"
    mappingPolicy: "existing_only"
  ) {
    success
    peer { domain mappingPolicy }
  }
}
```

Changing the policy does not affect existing identity links. Users who were already linked continue to use their existing link regardless of the new policy. The policy only applies to new, previously-unseen federated identities.

## Comparison Table

| | `existing_only` | `auto_link_by_email` | `auto_provision` |
|---|---|---|---|
| Requires admin action per user | Yes | No | No |
| Creates local accounts | No | No | Yes |
| Links by email match | No | Yes | Yes (as fallback) |
| Risk of unauthorized access | Lowest | Moderate (trusts peer email) | Highest (trusts peer claims) |
| User friction | Highest | Low (if email matches) | Lowest |
| Best for | High-security, small user sets | Teams with shared email domains | Open communities |

## Auditing Identity Links

List all federated identity links for a peer:

```graphql
query {
  federatedIdentities(peerDomain: "wegmueller.it") {
    localUserId
    peerSubject
    peerEmail
    linkedAt
    linkMethod
    lastLoginAt
  }
}
```

The `linkMethod` field indicates how the link was created:

| Value | Meaning |
|---|---|
| `admin` | Manually linked by an administrator |
| `email_match` | Auto-linked by email match |
| `auto_provision` | Account was auto-provisioned |

## Unlinking an Identity

To remove a federated identity link without deleting the local account:

```graphql
mutation {
  unlinkFederatedIdentity(
    peerDomain: "wegmueller.it"
    peerSubject: "user_abc123"
  ) {
    success
    message
  }
}
```

After unlinking, the user's next federated login will be treated as a first-time login, subject to the current mapping policy.
