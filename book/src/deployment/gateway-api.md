# Gateway API

The Barycenter Helm chart supports the [Kubernetes Gateway API](https://gateway-api.sigs.k8s.io/) as an alternative to Ingress. Gateway API provides a more expressive and role-oriented model for routing traffic into the cluster.

When `gatewayAPI.enabled` is `true`, the chart creates an HTTPRoute resource instead of (or in addition to) an Ingress.

## Prerequisites

- A Gateway API implementation installed in the cluster (e.g., Envoy Gateway, Istio, Cilium, or nginx Gateway Fabric)
- A `Gateway` resource already deployed that the HTTPRoute can attach to
- Gateway API CRDs installed (typically bundled with the implementation)

## Basic HTTPRoute

```yaml
gatewayAPI:
  enabled: true
  parentRefs:
    - name: main-gateway
      namespace: gateway-system
  hostnames:
    - idp.example.com
```

This creates an HTTPRoute that:

1. Attaches to the Gateway named `main-gateway` in the `gateway-system` namespace.
2. Matches requests for the hostname `idp.example.com`.
3. Routes all matching traffic to the Barycenter Service on port 8080.

## With Filters

HTTPRoute filters can modify requests before they reach Barycenter. For example, to add request headers:

```yaml
gatewayAPI:
  enabled: true
  parentRefs:
    - name: main-gateway
      namespace: gateway-system
  hostnames:
    - idp.example.com
  filters:
    - type: RequestHeaderModifier
      requestHeaderModifier:
        set:
          - name: X-Forwarded-Proto
            value: https
```

## TLS with Gateway API

TLS termination in the Gateway API model is handled by the `Gateway` resource, not the HTTPRoute. The Gateway references a certificate Secret:

```yaml
# Gateway resource (managed separately from the Barycenter Helm chart)
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: main-gateway
  namespace: gateway-system
spec:
  gatewayClassName: envoy
  listeners:
    - name: https
      protocol: HTTPS
      port: 443
      hostname: "idp.example.com"
      tls:
        mode: Terminate
        certificateRefs:
          - kind: Secret
            name: idp-tls
      allowedRoutes:
        namespaces:
          from: Selector
          selector:
            matchLabels:
              gateway-access: "true"
```

The Barycenter HTTPRoute then attaches to this listener. No TLS configuration is needed in the chart's `gatewayAPI` section.

If your Gateway API implementation supports cert-manager integration, certificate issuance and renewal can be automated by annotating the Gateway resource.

## Multiple Parent References

An HTTPRoute can attach to multiple Gateways. This is useful when you have separate Gateways for internal and external traffic:

```yaml
gatewayAPI:
  enabled: true
  parentRefs:
    - name: external-gateway
      namespace: gateway-system
      sectionName: https
    - name: internal-gateway
      namespace: gateway-system
      sectionName: https
  hostnames:
    - idp.example.com
    - idp.internal.example.com
```

## Combining with Ingress

The `ingress.enabled` and `gatewayAPI.enabled` flags are independent. You can enable both if your cluster uses a mix of Ingress and Gateway API, though in most cases you will choose one or the other.

## Verifying the HTTPRoute

After deploying, check the HTTPRoute status:

```bash
kubectl get httproute -n barycenter
```

Inspect the route details:

```bash
kubectl describe httproute barycenter -n barycenter
```

Look for the `Accepted` and `ResolvedRefs` conditions under the `status.parents` section. Both should be `True`.

Test the OIDC discovery endpoint:

```bash
curl https://idp.example.com/.well-known/openid-configuration
```

## Comparison: Ingress vs. Gateway API

| Feature | Ingress | Gateway API |
|---------|---------|-------------|
| TLS termination | Configured on Ingress resource | Configured on Gateway resource |
| Header manipulation | Via controller-specific annotations | Native `RequestHeaderModifier` filter |
| Traffic splitting | Limited, controller-specific | Native `BackendRef` weights |
| Role separation | Single resource | Gateway (infra team) + HTTPRoute (app team) |
| Multi-cluster | Controller-specific | Standardized across implementations |

For new clusters, Gateway API is the recommended approach. For existing clusters with established Ingress controllers, the Ingress path remains fully supported.

## Further Reading

- [Helm Chart Values](./helm-values.md) -- full reference of `gatewayAPI.*` values
- [Ingress Configuration](./helm-ingress.md) -- alternative Ingress-based setup
- [Kubernetes Gateway API documentation](https://gateway-api.sigs.k8s.io/)
