# Barycenter Helm Chart

OpenID Connect Identity Provider with built-in user management and federation support.

## Features

- OpenID Connect / OAuth 2.0 Authorization Server
- User synchronization from JSON files (idempotent)
- GraphQL Admin API for management
- Background job scheduler
- PostgreSQL and SQLite support
- Persistent storage for database and keys

## Prerequisites

- Kubernetes 1.20+
- Helm 3.0+
- PersistentVolume provisioner (optional, for production)

## Installing the Chart

### Basic Installation

```bash
helm install barycenter ./barycenter
```

### With Custom Values

```bash
helm install barycenter ./barycenter -f my-values.yaml
```

### Production Installation with User Sync

1. **Create users secret:**

```bash
# Copy the example
cp examples/user-sync-secret.yaml my-users-secret.yaml

# Edit with your users
nano my-users-secret.yaml

# Create the secret
kubectl create secret generic barycenter-users \
  --from-file=users.json=./users.json \
  -n default
```

2. **Install with user sync enabled:**

```bash
helm install barycenter ./barycenter \
  --set userSync.enabled=true \
  --set userSync.existingSecret=barycenter-users \
  --set config.server.publicBaseUrl=https://auth.example.com \
  --set ingress.enabled=true \
  --set ingress.hosts[0].host=auth.example.com
```

## Configuration

### Basic Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `replicaCount` | Number of replicas (use 1 for SQLite) | `1` |
| `image.repository` | Image repository | `barycenter` |
| `image.tag` | Image tag | `Chart.appVersion` |
| `image.pullPolicy` | Image pull policy | `IfNotPresent` |

### Service Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `service.type` | Service type | `ClusterIP` |
| `service.port` | Service port | `8080` |

### Barycenter Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `config.server.host` | Listen address | `0.0.0.0` |
| `config.server.port` | Listen port | `8080` |
| `config.server.publicBaseUrl` | Public base URL (OIDC issuer) | `""` |
| `config.database.url` | Database connection string | `sqlite:///app/data/barycenter.db?mode=rwc` |
| `config.keys.alg` | Signing algorithm | `RS256` |

### User Sync Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `userSync.enabled` | Enable user sync init container | `false` |
| `userSync.existingSecret` | Name of secret containing users.json | `""` |
| `userSync.secretKey` | Key in secret containing users.json | `users.json` |
| `userSync.resources` | Init container resources | See values.yaml |

### Persistence

| Parameter | Description | Default |
|-----------|-------------|---------|
| `persistence.enabled` | Enable persistent storage | `true` |
| `persistence.size` | PVC size | `10Gi` |
| `persistence.accessMode` | PVC access mode | `ReadWriteOnce` |
| `persistence.storageClass` | Storage class | `""` (default) |

### Ingress

| Parameter | Description | Default |
|-----------|-------------|---------|
| `ingress.enabled` | Enable ingress | `false` |
| `ingress.className` | Ingress class name | `nginx` |
| `ingress.hosts` | Ingress hosts | `[{host: idp.example.com, paths: [{path: /, pathType: Prefix}]}]` |
| `ingress.tls` | TLS configuration | `[]` |

## User Synchronization

The user sync feature allows you to manage users declaratively using a JSON file. This is perfect for:

- Initial user provisioning
- Kubernetes init containers
- CI/CD pipelines
- GitOps workflows

### How It Works

1. Create a Kubernetes Secret with your users.json
2. Enable user sync in Helm values
3. An init container runs before the main app
4. Users are created/updated idempotently
5. Main app starts with users ready

### User JSON Schema

```json
{
  "users": [
    {
      "username": "admin",
      "email": "admin@example.com",
      "password": "secure-password",
      "enabled": true,
      "email_verified": true,
      "properties": {
        "role": "administrator",
        "custom_field": "value"
      }
    }
  ]
}
```

### Creating a User Secret

**From a file:**

```bash
kubectl create secret generic barycenter-users \
  --from-file=users.json=./my-users.json \
  -n default
```

**From stdin (for CI/CD):**

```bash
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Secret
metadata:
  name: barycenter-users
type: Opaque
stringData:
  users.json: |
    {
      "users": [
        {
          "username": "admin",
          "email": "admin@example.com",
          "password": "${ADMIN_PASSWORD}",
          "enabled": true,
          "email_verified": true,
          "properties": {
            "role": "administrator"
          }
        }
      ]
    }
EOF
```

### Idempotent Behavior

The user sync is **idempotent** - safe to run multiple times:

- **New users**: Created with hashed passwords
- **Existing users**: Updated if changed (email, enabled, email_verified)
- **Passwords**: NOT updated for existing users (security)
- **Properties**: Always synced to match the JSON

### Example: GitOps Workflow

```yaml
# kustomization.yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

resources:
  - namespace.yaml
  - users-secret.yaml

helmCharts:
  - name: barycenter
    repo: https://charts.example.com
    version: 0.2.0
    releaseName: barycenter
    namespace: barycenter
    valuesInline:
      userSync:
        enabled: true
        existingSecret: barycenter-users
      config:
        server:
          publicBaseUrl: https://auth.example.com
```

## Examples

### Example 1: Development with SQLite

```bash
helm install barycenter ./barycenter \
  --set persistence.enabled=false \
  --set config.database.url="sqlite:///tmp/barycenter.db?mode=rwc"
```

### Example 2: Production with PostgreSQL

```bash
helm install barycenter ./barycenter \
  --set config.database.url="postgresql://user:pass@postgres:5432/barycenter" \
  --set replicaCount=3 \
  --set persistence.enabled=true \
  --set persistence.size=20Gi
```

### Example 3: With User Sync and Ingress

```yaml
# values-production.yaml
replicaCount: 1

config:
  server:
    publicBaseUrl: "https://auth.example.com"
  database:
    url: "postgresql://barycenter:password@postgres:5432/barycenter"

userSync:
  enabled: true
  existingSecret: "barycenter-users"

ingress:
  enabled: true
  className: nginx
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
  hosts:
    - host: auth.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: barycenter-tls
      hosts:
        - auth.example.com

persistence:
  enabled: true
  size: 20Gi
  storageClass: fast-ssd
```

Then install:

```bash
# Create users secret first
kubectl create secret generic barycenter-users \
  --from-file=users.json=./production-users.json

# Install with custom values
helm install barycenter ./barycenter -f values-production.yaml
```

## Upgrading

### Update User List

To update users after deployment:

```bash
# Method 1: Update secret and restart
kubectl create secret generic barycenter-users \
  --from-file=users.json=./updated-users.json \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl rollout restart deployment/barycenter

# Method 2: Run sync job manually (requires creating a Job)
kubectl run user-sync --rm -it --restart=Never \
  --image=barycenter:latest \
  -- barycenter sync-users --file /secrets/users.json
```

### Upgrade Chart

```bash
helm upgrade barycenter ./barycenter -f values.yaml
```

## Uninstalling

```bash
helm uninstall barycenter

# Also delete PVC if needed
kubectl delete pvc barycenter-data
```

## Troubleshooting

### Check Init Container Logs

```bash
# View user sync logs
kubectl logs deployment/barycenter -c user-sync

# Expected output:
# Loading users from /secrets/users.json
# Found 3 user(s) in file
# Creating user: alice
# User sync complete: 3 created, 0 updated, 0 unchanged
```

### Check Main Container

```bash
kubectl logs deployment/barycenter -c barycenter -f
```

### Verify Users Created

```bash
# Port forward to admin API
kubectl port-forward svc/barycenter 8081:8081

# Query users via GraphQL
curl -X POST http://localhost:8081/admin/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ user { nodes { username email enabled } } }"}'
```

### Common Issues

**Init container fails with "secret not found":**
- Ensure the secret exists: `kubectl get secret barycenter-users`
- Check the secret name in values.yaml matches

**Users not created:**
- Check init container logs for JSON parsing errors
- Verify users.json format matches the schema

**Permission denied on /app/data:**
- Check fsGroup in podSecurityContext (should be 1000)
- Verify PVC permissions

## Security Best Practices

1. **Never commit secrets to Git:**
   ```bash
   # Use .gitignore
   echo "my-users-secret.yaml" >> .gitignore
   ```

2. **Use secret management tools:**
   - Sealed Secrets
   - External Secrets Operator
   - HashiCorp Vault
   - Cloud provider secret managers

3. **Rotate passwords regularly:**
   - Update users.json with new passwords
   - Recreate the secret
   - Restart deployment

4. **Restrict admin API access:**
   - Use NetworkPolicies
   - Don't expose admin port publicly
   - Use VPN or bastion for access

## Support

- Documentation: https://github.com/CloudNebulaProject/barycenter
- Issues: https://github.com/CloudNebulaProject/barycenter/issues
