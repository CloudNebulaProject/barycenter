# P2P Federation Overview

Barycenter supports peer-to-peer (P2P) federation, allowing multiple independent Barycenter instances to establish bilateral trust relationships. Users authenticated at one instance (their "home" IdP) can log in to services protected by a different instance (a "peer" IdP) without creating a separate account.

## P2P vs. Hierarchical Federation

OpenID Connect Federation 1.0 defines a hierarchical trust model based on Trust Anchors, Intermediate Authorities, and leaf entities. Trust flows downward from a central authority, and entities discover each other by walking the trust chain upward.

Barycenter takes a different approach. Instead of relying on a central Trust Anchor, each Barycenter instance establishes direct, bilateral trust with its peers. This model is well-suited for small-to-medium deployments -- self-hosted infrastructure, small organizations, and community servers -- where standing up a full federation hierarchy would be disproportionate overhead.

| Aspect | OIDC Federation 1.0 | Barycenter P2P |
|---|---|---|
| Trust model | Hierarchical (Trust Anchor at root) | Bilateral (peer-to-peer) |
| Discovery | Entity statements + trust chains | WebFinger + OIDC Discovery |
| Setup effort | Requires Trust Anchor infrastructure | Two admins exchange credentials |
| Best for | Large federations, academic identity | Small communities, self-hosted infra |

## The Role of WebFinger

Federation discovery relies on [webfingerd](setting-up-webfingerd.md), an external WebFinger service. When a user presents an identifier like `toasty@wegmueller.it`, Barycenter queries WebFinger to resolve the `acct:` URI to an OIDC issuer URL. This lookup is the first step in the verification chain -- it proves that the claimed domain actually points to a specific OIDC provider.

WebFinger serves as a neutral discovery layer. It does not make trust decisions; it simply maps identifiers to issuer URLs. Trust decisions are made by Barycenter based on its configured list of trusted peers.

## Three-Layer Verification Model

Barycenter verifies federated peers through three layers, each building on the previous one:

```
Layer 1: WebFinger Resolution
  acct:_federation@wegmueller.it  -->  https://auth.wegmueller.it
  Proves: the domain owner has registered this issuer at webfingerd.

Layer 2: OIDC Discovery
  https://auth.wegmueller.it/.well-known/openid-configuration
  Proves: the issuer URL serves valid OIDC metadata and the issuer
  field matches the expected URL.

Layer 3: Entity Proof (optional)
  Cryptographic proof that the peer controls the signing keys
  advertised in its JWKS. Protects against DNS hijack scenarios
  where an attacker could serve valid-looking OIDC metadata.
```

The `min_verification_level` configuration controls which layers are required. With `discovery_only` (the default), layers 1 and 2 must pass. With `entity_proof`, all three layers are required.

## Federated Login Flow

The following diagram shows the complete flow when a user authenticates through a federated peer. In this example, a Forgejo instance is protected by `auth.aopc.cloud`, and the user's home IdP is `auth.wegmueller.it`.

```
User        Forgejo         auth.aopc.cloud       webfingerd        auth.wegmueller.it
 |             |                   |                   |                     |
 |--login----->|                   |                   |                     |
 |             |--/authorize------>|                   |                     |
 |             |                   |                   |                     |
 |<--login page (enter identifier)-|                   |                     |
 |                                 |                   |                     |
 |--"toasty@wegmueller.it"------->|                   |                     |
 |             |                   |                   |                     |
 |             |                   |--WebFinger lookup->|                     |
 |             |                   |<--issuer URL-------|                     |
 |             |                   |                   |                     |
 |             |                   |--OIDC Discovery----|-------------------->|
 |             |                   |<--metadata---------|-------------------->|
 |             |                   |                   |                     |
 |<--redirect to auth.wegmueller.it/authorize----------|-------------------->|
 |                                 |                   |                     |
 |--authenticate at home IdP-------|-------------------|-------------------->|
 |<--redirect to auth.aopc.cloud/federation/callback---|-------------------->|
 |                                 |                   |                     |
 |             |                   |--exchange code-----|-------------------->|
 |             |                   |<--id_token---------|-------------------->|
 |             |                   |                   |                     |
 |             |                   |--map identity----->|                     |
 |             |                   |--create session--->|                     |
 |             |                   |                   |                     |
 |<--redirect to Forgejo with code-|                   |                     |
 |             |                   |                   |                     |
 |             |--exchange code--->|                   |                     |
 |             |<--tokens----------|                   |                     |
 |<--logged in-|                   |                   |                     |
```

1. The user initiates login at Forgejo, which redirects to `auth.aopc.cloud/authorize`.
2. The login page prompts for an identifier. The user enters `toasty@wegmueller.it`.
3. `auth.aopc.cloud` resolves the identifier via WebFinger and discovers the peer's OIDC configuration.
4. The user is redirected to `auth.wegmueller.it/authorize` to authenticate at their home IdP.
5. After successful authentication, `auth.wegmueller.it` redirects back to `auth.aopc.cloud/federation/callback` with an authorization code.
6. `auth.aopc.cloud` exchanges the code for an ID token, maps the federated identity to a local account, creates a session, and resumes the original authorization flow.
7. Forgejo receives its authorization code and exchanges it for tokens as usual.

## When to Use Federation

Federation is appropriate when:

- Multiple organizations or individuals run their own Barycenter instances and want to allow cross-instance login.
- A service (like Forgejo, Nextcloud, or a custom application) is protected by one Barycenter instance, but users from other instances need access.
- You want to avoid creating duplicate accounts across multiple identity providers.

Federation is not needed when:

- All users authenticate against a single Barycenter instance.
- You use an external IdP (such as a corporate SAML provider) as an upstream source -- that is a different integration pattern.

## Identity Mapping Policies

When a federated user logs in for the first time, Barycenter must decide how to represent them locally. The **mapping policy**, configured per peer, controls this behavior:

| Policy | Behavior | Risk level |
|---|---|---|
| `existing_only` | Only allows login if an admin has pre-linked the federated identity to a local account. No automatic account creation or linking. | Lowest |
| `auto_link_by_email` | Automatically links the federated identity to an existing local account if the email addresses match. Does not create new accounts. | Moderate |
| `auto_provision` | Creates a new local account automatically on first login if no matching account exists. | Highest |

See [Identity Mapping Policies](identity-mapping.md) for detailed guidance on choosing and configuring a policy.
