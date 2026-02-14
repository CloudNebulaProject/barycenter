# Rate Limiting

Rate limiting is not built into Barycenter itself. Instead, it should be enforced at the reverse proxy level in front of the application. This approach provides several advantages:

- **Separation of concerns**: The identity provider focuses on authentication logic; the proxy handles traffic management.
- **Infrastructure flexibility**: Rate limiting rules can be adjusted without redeploying the application.
- **Early rejection**: Abusive requests are dropped before they reach the application, conserving resources.
- **Proven implementations**: Reverse proxies like nginx and Traefik have mature, battle-tested rate limiting modules.

## Recommended Limits

The following per-endpoint rate limits are recommended based on the expected usage patterns of each endpoint:

| Endpoint | Suggested Limit | Rationale |
|----------|----------------|-----------|
| `POST /token` | 10 requests/min/IP | Protects against token endpoint abuse and brute-force attacks on authorization codes |
| `POST /login` | 5 requests/min/IP | Limits credential stuffing and password brute-force attempts |
| `GET /authorize` | 20 requests/min/IP | Prevents authorization flood attacks while allowing normal OAuth flows |
| `POST /webauthn/authenticate/start` | 10 requests/min/IP | Limits WebAuthn challenge generation |
| `POST /connect/register` | 5 requests/min/IP | Prevents mass client registration abuse |
| `GET /userinfo` | 30 requests/min/IP | Allows normal API usage while preventing excessive queries |

These limits should be tuned based on your deployment's actual traffic patterns. Start with these values and adjust based on monitoring.

## Nginx Configuration

The following example configures rate limiting in nginx for a Barycenter deployment.

### Define Rate Limit Zones

Add these directives to the `http` block in your nginx configuration:

```nginx
http {
    # Define rate limit zones based on client IP
    # Zone format: zone=name:size rate=requests/interval

    # Token endpoint: 10 requests per minute per IP
    limit_req_zone $binary_remote_addr zone=token:10m rate=10r/m;

    # Login endpoint: 5 requests per minute per IP
    limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;

    # Authorization endpoint: 20 requests per minute per IP
    limit_req_zone $binary_remote_addr zone=authorize:10m rate=20r/m;

    # General API: 30 requests per minute per IP
    limit_req_zone $binary_remote_addr zone=api:10m rate=30r/m;

    # Client registration: 5 requests per minute per IP
    limit_req_zone $binary_remote_addr zone=register:10m rate=5r/m;
}
```

The `10m` parameter allocates 10 megabytes of shared memory for tracking client IPs. Each zone can track approximately 160,000 unique IP addresses per 10 MB.

### Apply Rate Limits to Locations

Add these directives inside your `server` block:

```nginx
server {
    listen 443 ssl;
    server_name idp.example.com;

    # Token endpoint
    location = /token {
        limit_req zone=token burst=5 nodelay;
        limit_req_status 429;
        proxy_pass http://127.0.0.1:9090;
    }

    # Login endpoint
    location = /login {
        limit_req zone=login burst=3 nodelay;
        limit_req_status 429;
        proxy_pass http://127.0.0.1:9090;
    }

    # Authorization endpoint
    location = /authorize {
        limit_req zone=authorize burst=10 nodelay;
        limit_req_status 429;
        proxy_pass http://127.0.0.1:9090;
    }

    # Client registration
    location = /connect/register {
        limit_req zone=register burst=2 nodelay;
        limit_req_status 429;
        proxy_pass http://127.0.0.1:9090;
    }

    # All other endpoints
    location / {
        limit_req zone=api burst=15 nodelay;
        limit_req_status 429;
        proxy_pass http://127.0.0.1:9090;
    }
}
```

The `burst` parameter allows short bursts above the rate limit. For example, `burst=5 nodelay` allows up to 5 excess requests to be processed immediately rather than queued, accommodating legitimate bursts of activity (such as a token refresh immediately followed by a userinfo request).

The `nodelay` directive ensures that burst requests are processed immediately rather than being delayed to conform to the rate.

### Custom Error Response

Configure a proper JSON error response for rate-limited requests:

```nginx
# Return a JSON error body for rate-limited requests
error_page 429 @rate_limited;

location @rate_limited {
    default_type application/json;
    return 429 '{"error": "rate_limit_exceeded", "error_description": "Too many requests. Please try again later."}';
}
```

## Traefik Configuration

For deployments using Traefik, rate limiting can be configured using the RateLimit middleware:

```yaml
# traefik dynamic configuration
http:
  middlewares:
    token-ratelimit:
      rateLimit:
        average: 10
        period: 1m
        burst: 5

    login-ratelimit:
      rateLimit:
        average: 5
        period: 1m
        burst: 3

  routers:
    token:
      rule: "Path(`/token`)"
      middlewares:
        - token-ratelimit
      service: barycenter

    login:
      rule: "Path(`/login`)"
      middlewares:
        - login-ratelimit
      service: barycenter

  services:
    barycenter:
      loadBalancer:
        servers:
          - url: "http://127.0.0.1:9090"
```

## Monitoring Rate Limits

When rate limiting is active, monitor for:

- **429 response spikes**: May indicate an attack or misconfigured client.
- **Legitimate traffic being limited**: Adjust limits upward if real users are affected.
- **Distributed attacks**: A single IP limit may not catch attacks from botnets. Consider additional measures such as CAPTCHAs or account lockout after repeated failures.

Check nginx rate limit logs:

```bash
# Rate-limited requests appear in the error log
grep "limiting requests" /var/log/nginx/error.log
```

## Additional Recommendations

- **Use the real client IP**: If Barycenter is behind multiple proxies, configure `set_real_ip_from` and `real_ip_header` in nginx (or equivalent in your proxy) to rate-limit on the actual client IP rather than the proxy IP.
- **Separate admin API**: The admin GraphQL API (port 9091) should not be publicly accessible. Use firewall rules or network segmentation rather than rate limiting to protect it.
- **Fail2ban integration**: For persistent offenders, consider integrating fail2ban to temporarily block IPs that repeatedly trigger rate limits.
