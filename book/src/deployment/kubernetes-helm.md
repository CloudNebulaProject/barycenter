# Kubernetes with Helm

Barycenter ships a Helm chart for deploying to Kubernetes clusters. The chart is located at `deploy/helm/barycenter/` in the repository and is currently at version `0.2.0-alpha.15`.

## Prerequisites

- Kubernetes 1.26 or later
- Helm 3.12 or later
- `kubectl` configured to access your cluster

## Quick Install

```bash
helm install barycenter ./deploy/helm/barycenter \
  --namespace barycenter \
  --create-namespace
```

This creates a namespace called `barycenter` and deploys Barycenter with default values: SQLite storage, a single replica, and no Ingress.

## Install with Custom Values

Create a `values.yaml` file to override defaults:

```yaml
config:
  server:
    publicBaseUrl: "https://idp.example.com"
  database:
    url: "postgresql://barycenter:secret@postgres.db.svc:5432/barycenter"

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

persistence:
  enabled: true
  size: 1Gi
```

Then install:

```bash
helm install barycenter ./deploy/helm/barycenter \
  --namespace barycenter \
  --create-namespace \
  -f values.yaml
```

## Upgrade

After changing values or pulling a new chart version:

```bash
helm upgrade barycenter ./deploy/helm/barycenter \
  --namespace barycenter \
  -f values.yaml
```

## Uninstall

```bash
helm uninstall barycenter --namespace barycenter
```

This removes the Deployment, Services, and related resources. Persistent Volume Claims are retained by default. To delete them as well:

```bash
kubectl delete pvc -l app.kubernetes.io/instance=barycenter -n barycenter
```

## What the Chart Creates

The Helm chart creates the following Kubernetes resources:

| Resource | Purpose |
|----------|---------|
| Deployment | Runs the Barycenter pod(s) |
| Service | Exposes ports 8080, 8081, and 8082 within the cluster |
| ConfigMap | Stores the generated `config.toml` |
| PersistentVolumeClaim | Provides persistent storage for keys and SQLite (when `persistence.enabled`) |
| Ingress or HTTPRoute | Exposes the public OIDC port externally (when enabled) |
| HorizontalPodAutoscaler | Scales pods based on CPU/memory (when `autoscaling.enabled`) |
| ServiceAccount | Identity for the Barycenter pods |
| NetworkPolicy | Restricts access to the authorization port (when `authz.networkPolicy.enabled`) |

## Security Defaults

The chart applies these security settings by default:

- **`runAsNonRoot: true`** -- the container does not run as root.
- **`readOnlyRootFilesystem: true`** -- the container filesystem is immutable.
- **`allowPrivilegeEscalation: false`** -- prevents privilege escalation.

These defaults follow Kubernetes Pod Security Standards at the `restricted` level.

## Architecture in Kubernetes

```
                          +-----------+
  Internet --> Ingress -->| Service   |
               or         | port 8080 |---> Barycenter Pod(s)
               HTTPRoute  +-----------+
                          +-----------+
  Internal -->            | Service   |
  (cluster)               | port 8081 |---> (Admin API)
                          +-----------+
                          +-----------+
  Internal -->            | Service   |
  (same ns)  NetworkPolicy| port 8082 |---> (Authz API)
                          +-----------+
```

Only port 8080 is exposed through the Ingress or Gateway API route. The admin and authorization ports are reachable only within the cluster, with optional NetworkPolicy restrictions on the authorization port.

## Further Reading

- [Helm Chart Values](./helm-values.md) -- complete reference of all configurable values
- [Ingress Configuration](./helm-ingress.md) -- setting up nginx Ingress with cert-manager
- [Gateway API](./gateway-api.md) -- using HTTPRoute instead of Ingress
- [User Sync in Kubernetes](./k8s-user-sync.md) -- provisioning users via init containers
- [Authorization Policies in Kubernetes](./k8s-authz-policies.md) -- deploying KDL policies
