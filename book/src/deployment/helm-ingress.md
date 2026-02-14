# Ingress Configuration

The Barycenter Helm chart can create a Kubernetes Ingress resource to expose the public OIDC server (port 8080) through an Ingress controller. This page covers common configurations using the nginx Ingress controller and cert-manager for automatic TLS certificates.

## Basic Ingress

Enable Ingress in your `values.yaml`:

```yaml
ingress:
  enabled: true
  className: nginx
  hosts:
    - host: idp.example.com
      paths:
        - path: /
          pathType: Prefix
```

This creates an Ingress resource that routes all traffic for `idp.example.com` to the Barycenter Service on port 8080.

## Ingress with TLS

### Manual TLS Secret

If you manage TLS certificates yourself, create a Kubernetes Secret and reference it:

```bash
kubectl create secret tls idp-tls \
  --cert=tls.crt \
  --key=tls.key \
  -n barycenter
```

```yaml
ingress:
  enabled: true
  className: nginx
  hosts:
    - host: idp.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: idp-tls
      hosts:
        - idp.example.com
```

### Automatic TLS with cert-manager

[cert-manager](https://cert-manager.io/) can automatically provision and renew TLS certificates from Let's Encrypt or other ACME-compatible CAs.

**Prerequisites:**

1. cert-manager installed in the cluster
2. A ClusterIssuer configured (e.g., `letsencrypt-prod`)

**Values:**

```yaml
ingress:
  enabled: true
  className: nginx
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
  hosts:
    - host: idp.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: idp-tls
      hosts:
        - idp.example.com
```

The `cert-manager.io/cluster-issuer` annotation tells cert-manager to issue a certificate using the named ClusterIssuer and store it in the Secret `idp-tls`. cert-manager handles renewal automatically.

## Ingress Annotations

Common nginx Ingress annotations for an identity provider:

```yaml
ingress:
  enabled: true
  className: nginx
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/proxy-body-size: "1m"
    nginx.ingress.kubernetes.io/proxy-read-timeout: "30"
    nginx.ingress.kubernetes.io/proxy-send-timeout: "30"
  hosts:
    - host: idp.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: idp-tls
      hosts:
        - idp.example.com
```

| Annotation | Purpose |
|------------|---------|
| `ssl-redirect: "true"` | Redirects HTTP to HTTPS |
| `proxy-body-size: "1m"` | Limits request body size. OIDC requests are small; 1 MB is generous |
| `proxy-read-timeout: "30"` | Timeout in seconds for reading a response from Barycenter |
| `proxy-send-timeout: "30"` | Timeout in seconds for sending a request to Barycenter |

## Multiple Hosts

To serve multiple domains (for example, a production domain and a staging alias):

```yaml
ingress:
  enabled: true
  className: nginx
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
  hosts:
    - host: idp.example.com
      paths:
        - path: /
          pathType: Prefix
    - host: idp-staging.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: idp-tls
      hosts:
        - idp.example.com
    - secretName: idp-staging-tls
      hosts:
        - idp-staging.example.com
```

> **Note:** The `config.server.publicBaseUrl` value must match the primary domain used as the OAuth issuer. OIDC clients validate the `iss` claim in ID tokens against this URL.

## Verifying the Ingress

After deploying, verify the Ingress was created and has an address assigned:

```bash
kubectl get ingress -n barycenter
```

Expected output:

```
NAME          CLASS   HOSTS              ADDRESS        PORTS     AGE
barycenter    nginx   idp.example.com    203.0.113.10   80, 443   2m
```

Test the OIDC discovery endpoint:

```bash
curl https://idp.example.com/.well-known/openid-configuration
```

## Alternative: Gateway API

If your cluster uses the Gateway API instead of Ingress, see [Gateway API](./gateway-api.md) for HTTPRoute configuration.
