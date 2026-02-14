# Helm Chart Values

This page documents all configurable values for the Barycenter Helm chart. Values are set in a `values.yaml` file or passed directly with `--set` on the Helm command line.

## Image

| Key | Default | Description |
|-----|---------|-------------|
| `image.repository` | `ghcr.io/cloudnebulaproject/barycenter` | Container image repository |
| `image.tag` | Chart `appVersion` | Image tag to deploy |
| `image.pullPolicy` | `IfNotPresent` | Kubernetes image pull policy |

Example:

```yaml
image:
  repository: ghcr.io/cloudnebulaproject/barycenter
  tag: "0.2.0"
  pullPolicy: IfNotPresent
```

## Application Configuration

These values are rendered into the `config.toml` ConfigMap that the pod mounts at startup.

| Key | Default | Description |
|-----|---------|-------------|
| `config.server.publicBaseUrl` | `""` | OAuth issuer URL. Must be the externally-reachable URL (e.g., `https://idp.example.com`) |
| `config.database.url` | `sqlite:///app/data/barycenter.db?mode=rwc` | Database connection string. Supports `sqlite://` and `postgresql://` |
| `config.authz.enabled` | `false` | Enable the authorization policy engine |

Example:

```yaml
config:
  server:
    publicBaseUrl: "https://idp.example.com"
  database:
    url: "postgresql://barycenter:secret@postgres.db.svc:5432/barycenter"
  authz:
    enabled: true
```

## Ingress

| Key | Default | Description |
|-----|---------|-------------|
| `ingress.enabled` | `false` | Create an Ingress resource |
| `ingress.className` | `""` | Ingress class name (e.g., `nginx`) |
| `ingress.annotations` | `{}` | Annotations for the Ingress resource |
| `ingress.hosts` | `[]` | List of host rules with paths |
| `ingress.tls` | `[]` | TLS configuration with secret names and hosts |

See [Ingress Configuration](./helm-ingress.md) for detailed examples.

## Gateway API

| Key | Default | Description |
|-----|---------|-------------|
| `gatewayAPI.enabled` | `false` | Create an HTTPRoute resource |
| `gatewayAPI.parentRefs` | `[]` | Gateway references the HTTPRoute attaches to |
| `gatewayAPI.hostnames` | `[]` | Hostnames the HTTPRoute matches |
| `gatewayAPI.filters` | `[]` | Optional HTTPRoute filters |

See [Gateway API](./gateway-api.md) for detailed examples.

## Persistence

| Key | Default | Description |
|-----|---------|-------------|
| `persistence.enabled` | `false` | Create a PersistentVolumeClaim for `/app/data` |
| `persistence.size` | `1Gi` | Storage request size |
| `persistence.storageClass` | `""` | Storage class name. Empty uses the cluster default |
| `persistence.accessModes` | `["ReadWriteOnce"]` | PVC access modes |

Example:

```yaml
persistence:
  enabled: true
  size: 5Gi
  storageClass: fast-ssd
```

When `persistence.enabled` is `false`, the data directory uses an `emptyDir` volume. Data is lost when the pod is rescheduled.

> **Note:** If you use PostgreSQL as your database, the PVC is still needed for RSA key material and JWKS files. You can reduce the size to the minimum (e.g., `100Mi`).

## User Sync

| Key | Default | Description |
|-----|---------|-------------|
| `userSync.enabled` | `false` | Run a user-sync init container before the main application starts |
| `userSync.users` | `""` | Inline JSON array of user objects |
| `userSync.existingSecret` | `""` | Name of an existing Secret containing user data under the key `users.json` |

See [User Sync in Kubernetes](./k8s-user-sync.md) for detailed examples.

## Authorization Policies

| Key | Default | Description |
|-----|---------|-------------|
| `authz.policies` | `""` | Inline KDL policy content |
| `authz.existingConfigMap` | `""` | Name of an existing ConfigMap containing policy files |
| `authz.networkPolicy.enabled` | `false` | Create a NetworkPolicy restricting access to port 8082 |

See [Authorization Policies in Kubernetes](./k8s-authz-policies.md) for detailed examples.

## Resources

| Key | Default | Description |
|-----|---------|-------------|
| `resources.requests.cpu` | (not set) | CPU request |
| `resources.requests.memory` | (not set) | Memory request |
| `resources.limits.cpu` | (not set) | CPU limit |
| `resources.limits.memory` | (not set) | Memory limit |

Example:

```yaml
resources:
  requests:
    cpu: 100m
    memory: 128Mi
  limits:
    cpu: 500m
    memory: 256Mi
```

Setting resource requests is recommended for production deployments to ensure the scheduler places pods appropriately and to prevent resource contention.

## Autoscaling

| Key | Default | Description |
|-----|---------|-------------|
| `autoscaling.enabled` | `false` | Create a HorizontalPodAutoscaler |
| `autoscaling.minReplicas` | `1` | Minimum number of replicas |
| `autoscaling.maxReplicas` | `10` | Maximum number of replicas |
| `autoscaling.targetCPUUtilizationPercentage` | `80` | Target CPU utilization for scaling |
| `autoscaling.targetMemoryUtilizationPercentage` | (not set) | Target memory utilization for scaling |

Example:

```yaml
autoscaling:
  enabled: true
  minReplicas: 2
  maxReplicas: 8
  targetCPUUtilizationPercentage: 70
```

> **Important:** When autoscaling is enabled with SQLite, only a single replica can safely write to the database. Use PostgreSQL for multi-replica deployments.

## Complete Example

A production-ready `values.yaml`:

```yaml
image:
  tag: "0.2.0"

config:
  server:
    publicBaseUrl: "https://idp.example.com"
  database:
    url: "postgresql://barycenter:secret@postgres.db.svc:5432/barycenter"
  authz:
    enabled: true

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

persistence:
  enabled: true
  size: 1Gi

resources:
  requests:
    cpu: 100m
    memory: 128Mi
  limits:
    cpu: 500m
    memory: 256Mi

autoscaling:
  enabled: true
  minReplicas: 2
  maxReplicas: 6
  targetCPUUtilizationPercentage: 75

userSync:
  enabled: true
  existingSecret: barycenter-users

authz:
  policies: |
    resource "document" {
      permission "read"
      permission "write"
    }
    role "editor" {
      permission "document:read"
      permission "document:write"
    }
  networkPolicy:
    enabled: true
```
