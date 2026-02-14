# Reverse Proxy and TLS

Barycenter does not terminate TLS natively. In production, it should be placed behind a reverse proxy that handles TLS termination and forwards requests to Barycenter over HTTP on the local network or loopback interface.

## Why a Reverse Proxy

- **TLS termination** -- The proxy handles certificate management and encryption.
- **HTTP/2 and HTTP/3** -- Most reverse proxies support modern HTTP protocols transparently.
- **Rate limiting and request filtering** -- Additional protection before requests reach the application.
- **Static asset serving** -- The proxy can serve static files (CSS, JavaScript, WASM) directly if needed.
- **Centralized logging** -- Access logs in a standardized format.

## Port Mapping

Only the public OIDC server (port 8080) should be exposed through the reverse proxy. The admin (8081) and authorization (8082) ports should remain on the internal network.

```
Internet
   |
   v
[Reverse Proxy :443]  -->  [Barycenter :8080]   (public OIDC)
                           [Barycenter :8081]   (admin, internal only)
                           [Barycenter :8082]   (authz, internal only)
```

## nginx

### Basic Configuration

```nginx
server {
    listen 443 ssl http2;
    server_name idp.example.com;

    ssl_certificate     /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://localhost:8080;
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### With HTTP-to-HTTPS Redirect

```nginx
server {
    listen 80;
    server_name idp.example.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name idp.example.com;

    ssl_certificate     /etc/letsencrypt/live/idp.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/idp.example.com/privkey.pem;

    # TLS hardening
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    # HSTS - instruct browsers to always use HTTPS
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains" always;

    location / {
        proxy_pass http://localhost:8080;
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Timeouts
        proxy_read_timeout  30s;
        proxy_send_timeout  30s;
        proxy_connect_timeout 5s;

        # Buffer settings
        proxy_buffering on;
        proxy_buffer_size 4k;
        proxy_buffers 8 4k;
    }
}
```

### With Let's Encrypt (certbot)

Install certbot and obtain a certificate:

```bash
sudo certbot --nginx -d idp.example.com
```

Certbot modifies the nginx configuration to add TLS settings and sets up automatic renewal via a systemd timer or cron job.

## Caddy

Caddy provides automatic HTTPS with Let's Encrypt out of the box:

```
idp.example.com {
    reverse_proxy localhost:8080
}
```

This is the entire configuration needed. Caddy automatically obtains and renews TLS certificates from Let's Encrypt and redirects HTTP to HTTPS.

For more control:

```
idp.example.com {
    reverse_proxy localhost:8080 {
        header_up X-Real-IP {remote_host}
        header_up X-Forwarded-Proto {scheme}
    }

    header {
        Strict-Transport-Security "max-age=63072000; includeSubDomains"
        X-Content-Type-Options "nosniff"
        X-Frame-Options "DENY"
    }
}
```

## HAProxy

```
frontend https
    bind *:443 ssl crt /etc/haproxy/certs/idp.example.com.pem
    default_backend barycenter

backend barycenter
    server barycenter1 127.0.0.1:8080 check
    http-request set-header X-Real-IP %[src]
    http-request set-header X-Forwarded-Proto https
```

## Apache httpd

```apache
<VirtualHost *:443>
    ServerName idp.example.com

    SSLEngine on
    SSLCertificateFile    /path/to/cert.pem
    SSLCertificateKeyFile /path/to/key.pem

    ProxyPreserveHost On
    ProxyPass        / http://localhost:8080/
    ProxyPassReverse / http://localhost:8080/

    RequestHeader set X-Forwarded-Proto "https"
    RequestHeader set X-Real-IP "%{REMOTE_ADDR}e"
</VirtualHost>
```

## Important: Set the Public Base URL

Regardless of which reverse proxy you use, you must configure Barycenter's `public_base_url` to match the external URL:

```toml
[server]
public_base_url = "https://idp.example.com"
```

Or via environment variable:

```bash
BARYCENTER__SERVER__PUBLIC_BASE_URL=https://idp.example.com
```

This URL is used as the OAuth `iss` (issuer) claim in ID tokens and in the OpenID discovery document. If it does not match the URL that clients use to reach Barycenter, token validation will fail.

## TLS Best Practices

- **Use TLS 1.2 or 1.3 only.** Disable TLS 1.0 and 1.1.
- **Enable HSTS.** The `Strict-Transport-Security` header prevents protocol downgrade attacks.
- **Use strong cipher suites.** Prefer AEAD ciphers (AES-GCM, ChaCha20-Poly1305).
- **Automate certificate renewal.** Use Let's Encrypt with certbot, Caddy's built-in ACME, or cert-manager in Kubernetes.
- **Monitor certificate expiration.** Set up alerts for certificates approaching their expiry date.

## Restricting Admin and Authz Access

If you need to expose the admin or authorization ports through the proxy (for example, from a management network), use separate server blocks with IP-based access control:

```nginx
server {
    listen 443 ssl http2;
    server_name admin.idp.internal.example.com;

    ssl_certificate     /path/to/internal-cert.pem;
    ssl_certificate_key /path/to/internal-key.pem;

    allow 10.0.0.0/8;
    deny all;

    location / {
        proxy_pass http://localhost:8081;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## Further Reading

- [Production Checklist](./production-checklist.md) -- complete list of pre-launch checks
- [Docker Compose](./docker-compose.md) -- reverse proxy in front of a Compose stack
- [Ingress Configuration](./helm-ingress.md) -- TLS termination in Kubernetes
