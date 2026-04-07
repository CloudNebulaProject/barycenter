# Setting Up WebFinger Integration

Barycenter uses an external [webfingerd](https://git.sr.ht/~toasty/webfingerd) instance for federated identity discovery. This page walks through registering your domain, creating a service token, and configuring Barycenter to publish its federation resource.

## Prerequisites

- A running webfingerd instance (either self-hosted or a shared community instance).
- DNS control over the domain you want to federate (e.g., `yourdomain.com`).
- A Barycenter instance with a publicly reachable `public_base_url` configured.

## Step 1: Register Your Domain

Register your domain with the webfingerd instance. This tells webfingerd that you are the owner of the domain and triggers a DNS verification challenge.

```bash
curl -X POST https://webfinger.example.com/api/v1/domains \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN" \
  -d '{"domain": "yourdomain.com"}'
```

The response includes a DNS challenge record:

```json
{
  "id": "dom_abc123",
  "domain": "yourdomain.com",
  "status": "pending_verification",
  "challenge": {
    "type": "dns_txt",
    "name": "_webfinger-verify.yourdomain.com",
    "value": "webfinger-verify=abc123def456"
  }
}
```

## Step 2: Create the DNS Record

Add the TXT record to your domain's DNS configuration:

```
_webfinger-verify.yourdomain.com.  IN  TXT  "webfinger-verify=abc123def456"
```

Wait for DNS propagation (typically a few minutes, up to 48 hours depending on TTL settings).

## Step 3: Verify Domain Ownership

Once the DNS record is in place, trigger verification:

```bash
curl -X POST https://webfinger.example.com/api/v1/domains/dom_abc123/verify \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN"
```

A successful response:

```json
{
  "id": "dom_abc123",
  "domain": "yourdomain.com",
  "status": "verified",
  "verified_at": "2026-04-07T10:30:00Z"
}
```

## Step 4: Create a Service Token

Create a service token scoped to Barycenter's needs. The token should be restricted to the OIDC issuer relation and your domain's `acct:` resources:

```bash
curl -X POST https://webfinger.example.com/api/v1/tokens \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN" \
  -d '{
    "name": "barycenter-federation",
    "domain_id": "dom_abc123",
    "allowed_rels": ["http://openid.net/specs/connect/1.0/issuer"],
    "resource_pattern": "acct:*@yourdomain.com"
  }'
```

The response contains the token credentials:

```json
{
  "token_id": "tok_xyz789",
  "secret": "sk_live_abcdef1234567890",
  "display": "tok_xyz789.sk_live_abcdef1234567890"
}
```

Save the `display` value -- this is the service token you will configure in Barycenter. The secret is only shown once.

## Step 5: Configure Barycenter

Add the WebFinger and federation sections to your `config.toml`:

```toml
[webfinger]
enabled = true
base_url = "https://webfinger.yourdomain.com"
service_token = "tok_xyz789.sk_live_abcdef1234567890"
resource_domain = "yourdomain.com"

[federation]
enabled = true
min_verification_level = "discovery_only"
```

### Configuration Reference

| Key | Type | Default | Description |
|---|---|---|---|
| `webfinger.enabled` | Boolean | `false` | Enable WebFinger integration |
| `webfinger.base_url` | String | `""` | Base URL of the webfingerd instance |
| `webfinger.service_token` | String | `""` | Service token (`token_id.secret` format) |
| `webfinger.service_token_file` | String | *none* | Path to a file containing the service token (alternative to inline) |
| `webfinger.resource_domain` | String | `""` | Domain for `acct:` URIs (e.g., `yourdomain.com`) |
| `federation.enabled` | Boolean | `false` | Enable P2P federation |
| `federation.min_verification_level` | String | `"discovery_only"` | Minimum peer verification level (`discovery_only` or `entity_proof`) |

### Using a Token File

For container deployments or environments where secrets are mounted as files, use `service_token_file` instead of `service_token`:

```toml
[webfinger]
enabled = true
base_url = "https://webfinger.yourdomain.com"
service_token_file = "/run/secrets/webfinger-token"
resource_domain = "yourdomain.com"
```

If both `service_token` and `service_token_file` are set, the file takes precedence.

### Environment Variable Override

You can also set the service token via environment variable:

```bash
export BARYCENTER__WEBFINGER__SERVICE_TOKEN="tok_xyz789.sk_live_abcdef1234567890"
```

## Step 6: Restart and Verify

Restart Barycenter. On startup with WebFinger enabled, it registers the federation resource at webfingerd:

```
acct:_federation@yourdomain.com
  rel: http://openid.net/specs/connect/1.0/issuer
  href: https://auth.yourdomain.com
```

You can verify the registration by querying WebFinger directly:

```bash
curl "https://webfinger.yourdomain.com/.well-known/webfinger?resource=acct:_federation@yourdomain.com&rel=http://openid.net/specs/connect/1.0/issuer"
```

Expected response:

```json
{
  "subject": "acct:_federation@yourdomain.com",
  "links": [
    {
      "rel": "http://openid.net/specs/connect/1.0/issuer",
      "href": "https://auth.yourdomain.com"
    }
  ]
}
```

## Next Steps

With WebFinger configured, you can now establish trust with other Barycenter instances. See [Establishing Peer Trust](peering-guide.md) for the step-by-step peering process.
