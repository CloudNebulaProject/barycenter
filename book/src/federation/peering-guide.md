# Establishing Peer Trust

This guide walks through the process of establishing a bilateral trust relationship between two Barycenter instances. The example uses two domains:

- **aopc.cloud** -- Admin A's instance, running at `https://auth.aopc.cloud`
- **wegmueller.it** -- Admin B's instance, running at `https://auth.wegmueller.it`

Both instances must have WebFinger and federation enabled before proceeding. See [Setting Up WebFinger](setting-up-webfingerd.md) if you have not completed that step.

## Overview

Establishing a peer relationship is a four-step process:

1. Each admin registers a federation client at the other's instance.
2. Each admin adds the other as a trusted peer via the admin GraphQL API.
3. Barycenter verifies the peer through the configured verification layers.
4. Test a federated login to confirm everything works.

## Step 1: Register Federation Clients

Each instance needs an OAuth client registered at the peer instance. This client is used during the federated login flow to exchange authorization codes for tokens.

**Admin A** registers a client at `auth.wegmueller.it`:

```bash
curl -X POST https://auth.wegmueller.it/connect/register \
  -H "Content-Type: application/json" \
  -d '{
    "redirect_uris": ["https://auth.aopc.cloud/federation/callback"],
    "client_name": "aopc.cloud federation",
    "token_endpoint_auth_method": "client_secret_basic"
  }'
```

Response:

```json
{
  "client_id": "clt_abc123",
  "client_secret": "sec_xyz789",
  "client_name": "aopc.cloud federation",
  "redirect_uris": ["https://auth.aopc.cloud/federation/callback"],
  "token_endpoint_auth_method": "client_secret_basic"
}
```

Save the `client_id` and `client_secret` -- Admin A will need these in step 2.

**Admin B** does the same in reverse, registering a client at `auth.aopc.cloud`:

```bash
curl -X POST https://auth.aopc.cloud/connect/register \
  -H "Content-Type: application/json" \
  -d '{
    "redirect_uris": ["https://auth.wegmueller.it/federation/callback"],
    "client_name": "wegmueller.it federation",
    "token_endpoint_auth_method": "client_secret_basic"
  }'
```

> **Note:** If `allow_public_registration` is `false` on either instance, the admin of that instance must register the client through the admin GraphQL API instead of the public `/connect/register` endpoint.

## Step 2: Add Trusted Peers

Each admin adds the other instance as a trusted peer using the admin GraphQL API. The admin API runs on a separate port (default: main port + 1).

**Admin A** adds `wegmueller.it` as a trusted peer:

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
    message
    peer {
      domain
      status
      verificationLevel
    }
  }
}
```

Using curl:

```bash
curl -s -X POST http://localhost:8081/admin/jobs \
  -H "Content-Type: application/json" \
  -d '{
    "query": "mutation { addTrustedPeer(domain: \"wegmueller.it\", issuerUrl: \"https://auth.wegmueller.it\", clientId: \"clt_abc123\", clientSecret: \"sec_xyz789\", mappingPolicy: \"auto_link_by_email\") { success message peer { domain status verificationLevel } } }"
  }'
```

**Admin B** does the same, adding `aopc.cloud` as a trusted peer with the client credentials received from Admin A's instance.

### Mutation Parameters

| Parameter | Type | Description |
|---|---|---|
| `domain` | String | The peer's domain (used for WebFinger lookups) |
| `issuerUrl` | String | The peer's OIDC issuer URL |
| `clientId` | String | Client ID registered at the peer |
| `clientSecret` | String | Client secret registered at the peer |
| `mappingPolicy` | String | How to map federated identities: `existing_only`, `auto_link_by_email`, or `auto_provision` |

## Step 3: Verify the Peer

After adding a peer, Barycenter automatically initiates verification. You can check the status:

```graphql
query {
  trustedPeer(domain: "wegmueller.it") {
    domain
    status
    verificationLevel
    verifiedAt
    issuerUrl
    mappingPolicy
  }
}
```

Possible `status` values:

| Status | Meaning |
|---|---|
| `pending` | Verification is in progress |
| `verified` | All required verification layers passed |
| `failed` | Verification failed (check logs for details) |
| `suspended` | Manually suspended by admin |

If verification fails, check that:

- The peer's WebFinger resource resolves correctly.
- The peer's `/.well-known/openid-configuration` is accessible and the `issuer` field matches `issuerUrl`.
- If `min_verification_level` is `entity_proof`, the peer supports entity proof exchange.

You can re-trigger verification after fixing issues:

```graphql
mutation {
  reverifyPeer(domain: "wegmueller.it") {
    success
    message
  }
}
```

## Step 4: Test Federated Login

With both sides configured, test the flow end-to-end.

1. Navigate to the login page at `https://auth.aopc.cloud/login`.
2. Enter a federated identifier: `toasty@wegmueller.it`.
3. You should be redirected to `https://auth.wegmueller.it/authorize`.
4. Authenticate at `auth.wegmueller.it` using your usual credentials (password, passkey, etc.).
5. After authentication, you should be redirected back to `auth.aopc.cloud` and logged in.

If the flow completes successfully, the peer relationship is working. You can verify the created session and identity mapping through the admin API:

```graphql
query {
  federatedIdentity(email: "toasty@wegmueller.it") {
    localUserId
    peerDomain
    peerSubject
    linkedAt
    lastLoginAt
  }
}
```

## Listing All Peers

To see all configured peers:

```graphql
query {
  trustedPeers {
    domain
    status
    verificationLevel
    mappingPolicy
    verifiedAt
  }
}
```

## Removing a Peer

To remove trust for a peer:

```graphql
mutation {
  removeTrustedPeer(domain: "wegmueller.it") {
    success
    message
  }
}
```

This revokes trust immediately. Existing sessions for federated users from that peer remain valid until they expire, but no new federated logins will be accepted. To also terminate existing sessions, run the session cleanup job after removing the peer.

## Suspending a Peer

If you need to temporarily disable federation with a peer without removing the configuration:

```graphql
mutation {
  suspendPeer(domain: "wegmueller.it") {
    success
    message
  }
}
```

Resume with:

```graphql
mutation {
  resumePeer(domain: "wegmueller.it") {
    success
    message
  }
}
```
