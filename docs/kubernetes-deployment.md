# Kubernetes Deployment Guide

This guide covers deploying Barycenter in Kubernetes with user sync, persistent storage, and proper configuration management.

## Table of Contents

- [Quick Start](#quick-start)
- [Architecture Overview](#architecture-overview)
- [Prerequisites](#prerequisites)
- [Configuration](#configuration)
- [Storage](#storage)
- [User Management](#user-management)
- [Deployment](#deployment)
- [Services](#services)
- [Complete Example](#complete-example)
- [Production Considerations](#production-considerations)

## Quick Start

```bash
# Create namespace
kubectl create namespace barycenter

# Apply all manifests
kubectl apply -f deploy/kubernetes/
```

## Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                     Kubernetes Cluster                   │
│                                                          │
│  ┌────────────────────────────────────────────────────┐ │
│  │              Barycenter Deployment                  │ │
│  │                                                     │ │
│  │  ┌─────────────────┐    ┌──────────────────────┐  │ │
│  │  │  Init Container │───▶│   Main Container     │  │ │
│  │  │  (User Sync)    │    │   (OIDC Server)      │  │ │
│  │  └─────────────────┘    └──────────────────────┘  │ │
│  │          │                        │                │ │
│  │          └────────────────────────┘                │ │
│  │                     │                              │ │
│  │                     ▼                              │ │
│  │          ┌────────────────────┐                    │ │
│  │          │ PersistentVolume   │                    │ │
│  │          │ (SQLite/Data)      │                    │ │
│  │          └────────────────────┘                    │ │
│  └─────────────────────────────────────────────────────┘ │
│                                                          │
│  ┌────────────────┐  ┌────────────────┐                 │
│  │   ConfigMap    │  │     Secret     │                 │
│  │ (config.toml)  │  │  (users.json)  │                 │
│  └────────────────┘  └────────────────┘                 │
│                                                          │
│  ┌─────────────────────────────────────────────────┐   │
│  │                   Services                       │   │
│  │  ┌──────────────┐        ┌──────────────────┐  │   │
│  │  │   Public     │        │      Admin       │  │   │
│  │  │  (Port 8080) │        │   (Port 8081)    │  │   │
│  │  └──────────────┘        └──────────────────┘  │   │
│  └─────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
```

## Prerequisites

- Kubernetes cluster (1.20+)
- `kubectl` configured
- Container registry access (or Docker Hub)
- Persistent storage provisioner (optional, for production)

## Configuration

### ConfigMap for Application Configuration

Create `barycenter-config.yaml`:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: barycenter-config
  namespace: barycenter
data:
  config.toml: |
    [server]
    host = "0.0.0.0"
    port = 8080
    admin_port = 8081
    # IMPORTANT: Set this to your actual domain in production
    public_base_url = "https://auth.example.com"
    allow_public_registration = false

    [database]
    # SQLite for simplicity (use PostgreSQL in production)
    url = "sqlite:///data/barycenter.db?mode=rwc"

    [keys]
    jwks_path = "/data/jwks.json"
    private_key_path = "/data/private_key.pem"
    alg = "RS256"

    [federation]
    trust_anchors = []
```

### Secret for User Data

Create `barycenter-users-secret.yaml`:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: barycenter-users
  namespace: barycenter
type: Opaque
stringData:
  users.json: |
    {
      "users": [
        {
          "username": "admin",
          "email": "admin@example.com",
          "password": "CHANGE-ME-IN-PRODUCTION",
          "enabled": true,
          "email_verified": true,
          "properties": {
            "role": "administrator",
            "display_name": "System Administrator"
          }
        },
        {
          "username": "app-service",
          "email": "service@example.com",
          "password": "service-account-password",
          "enabled": true,
          "email_verified": true,
          "properties": {
            "role": "service_account",
            "display_name": "Application Service Account"
          }
        }
      ]
    }
```

**IMPORTANT:** In production, generate this secret from a secure source:

```bash
# Generate from template with environment variables
cat users.json.template | envsubst | kubectl create secret generic barycenter-users \
  --namespace=barycenter \
  --from-file=users.json=/dev/stdin \
  --dry-run=client -o yaml | kubectl apply -f -
```

## Storage

### Development: EmptyDir (Data lost on pod restart)

```yaml
volumes:
- name: data
  emptyDir: {}
```

### Production: PersistentVolumeClaim

Create `barycenter-pvc.yaml`:

```yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: barycenter-data
  namespace: barycenter
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 10Gi
  # Optional: Use a specific storage class
  # storageClassName: fast-ssd
```

## User Management

### Init Container for User Sync

The init container runs before the main application starts and syncs users from the secret:

```yaml
initContainers:
- name: user-sync
  image: your-registry/barycenter:latest
  command:
    - barycenter
    - sync-users
    - --file
    - /secrets/users.json
  volumeMounts:
  - name: users-secret
    mountPath: /secrets
    readOnly: true
  - name: data
    mountPath: /data
  - name: config
    mountPath: /app
    readOnly: true
  env:
  - name: RUST_LOG
    value: info
```

### Standalone User Sync Job

For updating users without redeploying:

Create `barycenter-user-sync-job.yaml`:

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: barycenter-user-sync
  namespace: barycenter
spec:
  backoffLimit: 3
  template:
    metadata:
      labels:
        app: barycenter
        component: user-sync
    spec:
      restartPolicy: OnFailure
      containers:
      - name: user-sync
        image: your-registry/barycenter:latest
        command:
          - barycenter
          - sync-users
          - --file
          - /secrets/users.json
        volumeMounts:
        - name: users-secret
          mountPath: /secrets
          readOnly: true
        - name: data
          mountPath: /data
        - name: config
          mountPath: /app
          readOnly: true
        env:
        - name: RUST_LOG
          value: info
      volumes:
      - name: users-secret
        secret:
          secretName: barycenter-users
      - name: data
        persistentVolumeClaim:
          claimName: barycenter-data
      - name: config
        configMap:
          name: barycenter-config
```

Run with:
```bash
kubectl apply -f barycenter-user-sync-job.yaml

# Watch progress
kubectl logs -f job/barycenter-user-sync -n barycenter

# Clean up job after completion
kubectl delete job barycenter-user-sync -n barycenter
```

### CronJob for Periodic User Sync

Create `barycenter-user-sync-cronjob.yaml`:

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: barycenter-user-sync
  namespace: barycenter
spec:
  # Run every hour
  schedule: "0 * * * *"
  successfulJobsHistoryLimit: 3
  failedJobsHistoryLimit: 3
  jobTemplate:
    spec:
      backoffLimit: 2
      template:
        metadata:
          labels:
            app: barycenter
            component: user-sync
        spec:
          restartPolicy: OnFailure
          containers:
          - name: user-sync
            image: your-registry/barycenter:latest
            command:
              - barycenter
              - sync-users
              - --file
              - /secrets/users.json
            volumeMounts:
            - name: users-secret
              mountPath: /secrets
              readOnly: true
            - name: data
              mountPath: /data
            - name: config
              mountPath: /app
              readOnly: true
            resources:
              requests:
                memory: "128Mi"
                cpu: "100m"
              limits:
                memory: "256Mi"
                cpu: "200m"
          volumes:
          - name: users-secret
            secret:
              secretName: barycenter-users
          - name: data
            persistentVolumeClaim:
              claimName: barycenter-data
          - name: config
            configMap:
              name: barycenter-config
```

## Deployment

### Main Deployment

Create `barycenter-deployment.yaml`:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: barycenter
  namespace: barycenter
  labels:
    app: barycenter
spec:
  replicas: 1  # NOTE: SQLite supports only 1 replica. Use PostgreSQL for HA.
  selector:
    matchLabels:
      app: barycenter
  template:
    metadata:
      labels:
        app: barycenter
    spec:
      # Init container syncs users before app starts
      initContainers:
      - name: user-sync
        image: your-registry/barycenter:latest
        command:
          - barycenter
          - sync-users
          - --file
          - /secrets/users.json
        volumeMounts:
        - name: users-secret
          mountPath: /secrets
          readOnly: true
        - name: data
          mountPath: /data
        - name: config
          mountPath: /app
          readOnly: true
        env:
        - name: RUST_LOG
          value: info
        resources:
          requests:
            memory: "128Mi"
            cpu: "100m"
          limits:
            memory: "256Mi"
            cpu: "200m"

      # Main application container
      containers:
      - name: barycenter
        image: your-registry/barycenter:latest
        ports:
        - name: public
          containerPort: 8080
          protocol: TCP
        - name: admin
          containerPort: 8081
          protocol: TCP
        volumeMounts:
        - name: data
          mountPath: /data
        - name: config
          mountPath: /app
          readOnly: true
        env:
        - name: RUST_LOG
          value: info
        # Liveness probe - checks if app is alive
        livenessProbe:
          httpGet:
            path: /.well-known/openid-configuration
            port: public
          initialDelaySeconds: 10
          periodSeconds: 30
          timeoutSeconds: 5
          failureThreshold: 3
        # Readiness probe - checks if app is ready to serve traffic
        readinessProbe:
          httpGet:
            path: /.well-known/openid-configuration
            port: public
          initialDelaySeconds: 5
          periodSeconds: 10
          timeoutSeconds: 3
          failureThreshold: 3
        resources:
          requests:
            memory: "256Mi"
            cpu: "200m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        securityContext:
          runAsNonRoot: true
          runAsUser: 1000
          readOnlyRootFilesystem: false
          allowPrivilegeEscalation: false
          capabilities:
            drop:
            - ALL

      volumes:
      - name: users-secret
        secret:
          secretName: barycenter-users
      - name: data
        persistentVolumeClaim:
          claimName: barycenter-data
      - name: config
        configMap:
          name: barycenter-config

      # Security context for the pod
      securityContext:
        fsGroup: 1000
```

## Services

### Public Service (OIDC Endpoints)

Create `barycenter-service-public.yaml`:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: barycenter-public
  namespace: barycenter
  labels:
    app: barycenter
    component: public
spec:
  type: ClusterIP
  ports:
  - port: 8080
    targetPort: public
    protocol: TCP
    name: http
  selector:
    app: barycenter
```

### Admin Service (GraphQL API)

Create `barycenter-service-admin.yaml`:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: barycenter-admin
  namespace: barycenter
  labels:
    app: barycenter
    component: admin
spec:
  type: ClusterIP
  ports:
  - port: 8081
    targetPort: admin
    protocol: TCP
    name: http
  selector:
    app: barycenter
```

### Ingress (Optional)

Create `barycenter-ingress.yaml`:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: barycenter
  namespace: barycenter
  annotations:
    # cert-manager for TLS
    cert-manager.io/cluster-issuer: letsencrypt-prod
    # nginx ingress specific
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/force-ssl-redirect: "true"
spec:
  ingressClassName: nginx
  tls:
  - hosts:
    - auth.example.com
    secretName: barycenter-tls
  rules:
  # Public OIDC endpoints
  - host: auth.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: barycenter-public
            port:
              number: 8080
---
# Separate ingress for admin (restrict access)
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: barycenter-admin
  namespace: barycenter
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    # Restrict to internal IPs only
    nginx.ingress.kubernetes.io/whitelist-source-range: "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"
spec:
  ingressClassName: nginx
  tls:
  - hosts:
    - admin.auth.example.com
    secretName: barycenter-admin-tls
  rules:
  - host: admin.auth.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: barycenter-admin
            port:
              number: 8081
```

## Complete Example

Create a directory structure:

```
deploy/kubernetes/
├── namespace.yaml
├── configmap.yaml
├── secret.yaml
├── pvc.yaml
├── deployment.yaml
├── service-public.yaml
├── service-admin.yaml
└── ingress.yaml
```

### namespace.yaml

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: barycenter
  labels:
    name: barycenter
```

### Apply All Resources

```bash
# Create namespace first
kubectl apply -f deploy/kubernetes/namespace.yaml

# Apply configuration and storage
kubectl apply -f deploy/kubernetes/configmap.yaml
kubectl apply -f deploy/kubernetes/secret.yaml
kubectl apply -f deploy/kubernetes/pvc.yaml

# Deploy application
kubectl apply -f deploy/kubernetes/deployment.yaml

# Expose services
kubectl apply -f deploy/kubernetes/service-public.yaml
kubectl apply -f deploy/kubernetes/service-admin.yaml

# Optional: Create ingress
kubectl apply -f deploy/kubernetes/ingress.yaml
```

### Verify Deployment

```bash
# Check all resources
kubectl get all -n barycenter

# Check init container logs (user sync)
kubectl logs -n barycenter deployment/barycenter -c user-sync

# Check main container logs
kubectl logs -n barycenter deployment/barycenter -c barycenter -f

# Check services
kubectl get svc -n barycenter

# Port forward for testing
kubectl port-forward -n barycenter svc/barycenter-public 8080:8080
kubectl port-forward -n barycenter svc/barycenter-admin 8081:8081

# Test OIDC discovery
curl http://localhost:8080/.well-known/openid-configuration

# Test admin GraphQL
curl http://localhost:8081/admin/playground
```

## Production Considerations

### High Availability

**SQLite Limitation:**
- SQLite only supports single writer
- For HA, use PostgreSQL instead

**PostgreSQL Setup:**

1. Update `configmap.yaml`:
```yaml
[database]
url = "postgresql://barycenter:password@postgres-service:5432/barycenter"
```

2. Deploy PostgreSQL (or use cloud provider):
```yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: postgres
  namespace: barycenter
spec:
  serviceName: postgres
  replicas: 1
  selector:
    matchLabels:
      app: postgres
  template:
    metadata:
      labels:
        app: postgres
    spec:
      containers:
      - name: postgres
        image: postgres:16
        ports:
        - containerPort: 5432
        env:
        - name: POSTGRES_DB
          value: barycenter
        - name: POSTGRES_USER
          value: barycenter
        - name: POSTGRES_PASSWORD
          valueFrom:
            secretKeyRef:
              name: postgres-secret
              key: password
        volumeMounts:
        - name: data
          mountPath: /var/lib/postgresql/data
  volumeClaimTemplates:
  - metadata:
      name: data
    spec:
      accessModes: ["ReadWriteOnce"]
      resources:
        requests:
          storage: 20Gi
```

3. Scale deployment:
```yaml
spec:
  replicas: 3  # Now safe with PostgreSQL
```

### Security Hardening

1. **Network Policies:**

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: barycenter-network-policy
  namespace: barycenter
spec:
  podSelector:
    matchLabels:
      app: barycenter
  policyTypes:
  - Ingress
  - Egress
  ingress:
  # Allow from ingress controller
  - from:
    - namespaceSelector:
        matchLabels:
          name: ingress-nginx
    ports:
    - protocol: TCP
      port: 8080
  # Admin access only from internal
  - from:
    - podSelector:
        matchLabels:
          role: admin
    ports:
    - protocol: TCP
      port: 8081
  egress:
  # Allow DNS
  - to:
    - namespaceSelector:
        matchLabels:
          name: kube-system
    ports:
    - protocol: UDP
      port: 53
  # Allow PostgreSQL
  - to:
    - podSelector:
        matchLabels:
          app: postgres
    ports:
    - protocol: TCP
      port: 5432
```

2. **Pod Security Standards:**

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: barycenter
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
```

3. **Resource Quotas:**

```yaml
apiVersion: v1
kind: ResourceQuota
metadata:
  name: barycenter-quota
  namespace: barycenter
spec:
  hard:
    requests.cpu: "2"
    requests.memory: 4Gi
    limits.cpu: "4"
    limits.memory: 8Gi
    persistentvolumeclaims: "5"
```

### Monitoring

1. **ServiceMonitor (Prometheus Operator):**

```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: barycenter
  namespace: barycenter
spec:
  selector:
    matchLabels:
      app: barycenter
  endpoints:
  - port: http
    interval: 30s
    path: /metrics  # Add metrics endpoint to Barycenter
```

2. **Logging:**

```yaml
# Add to deployment
env:
- name: RUST_LOG
  value: "info,barycenter=debug"
```

### Backup

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: barycenter-backup
  namespace: barycenter
spec:
  schedule: "0 2 * * *"  # Daily at 2 AM
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: backup
            image: alpine:latest
            command:
            - sh
            - -c
            - |
              apk add --no-cache sqlite
              sqlite3 /data/barycenter.db ".backup /backup/barycenter-$(date +%Y%m%d-%H%M%S).db"
              # Upload to S3/GCS/etc
            volumeMounts:
            - name: data
              mountPath: /data
              readOnly: true
            - name: backup
              mountPath: /backup
          volumes:
          - name: data
            persistentVolumeClaim:
              claimName: barycenter-data
          - name: backup
            persistentVolumeClaim:
              claimName: barycenter-backup
          restartPolicy: OnFailure
```

## Troubleshooting

### Check Init Container

```bash
# View init container logs
kubectl logs -n barycenter deployment/barycenter -c user-sync

# Common issues:
# - Secret not found: Check kubectl get secret -n barycenter
# - Permission denied: Check fsGroup and securityContext
# - Database locked: Check if multiple pods are running with SQLite
```

### Check Main Container

```bash
# View logs
kubectl logs -n barycenter deployment/barycenter -c barycenter -f

# Exec into pod
kubectl exec -it -n barycenter deployment/barycenter -- sh

# Check database
ls -la /data/
```

### Update Users

```bash
# Method 1: Update secret and restart
kubectl delete secret barycenter-users -n barycenter
kubectl create secret generic barycenter-users \
  --from-file=users.json=./users.json \
  -n barycenter

kubectl rollout restart deployment/barycenter -n barycenter

# Method 2: Run sync job
kubectl apply -f barycenter-user-sync-job.yaml
kubectl logs -f job/barycenter-user-sync -n barycenter
```

## Summary

You now have:
- ✅ Complete Kubernetes deployment setup
- ✅ User sync via init containers
- ✅ Persistent storage configuration
- ✅ Service exposure (public + admin)
- ✅ Production-ready configurations
- ✅ HA setup with PostgreSQL
- ✅ Security hardening options
- ✅ Monitoring and backup strategies

For the actual Helm chart deployment, see `deploy/helm/barycenter/`.
