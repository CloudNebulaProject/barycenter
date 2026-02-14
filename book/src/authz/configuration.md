# Configuration and Deployment

The authorization policy engine is an optional component of Barycenter that must be explicitly enabled. This page covers the configuration options, file layout, and deployment considerations for running the engine in development and production environments.

## Enabling the Engine

The authorization engine is disabled by default. To enable it, add the `[authz]` section to your configuration file:

```toml
[authz]
enabled = true
```

When `enabled` is `false` or the `[authz]` section is absent, Barycenter does not start the authorization server, does not load policy files, and does not bind the authorization port.

## Configuration Reference

All authorization configuration lives under the `[authz]` section:

```toml
[authz]
enabled = true
port = 8082
policies_dir = "policies"
```

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | boolean | `false` | Whether to start the authorization policy engine. |
| `port` | integer | Main port + 2 (e.g., `8082`) | The TCP port the authorization REST API listens on. |
| `policies_dir` | string | `"policies"` | Path to the directory containing `.kdl` policy files. Relative paths are resolved from the working directory. |

### Environment Variable Overrides

Like all Barycenter settings, authorization configuration can be overridden with environment variables using the `BARYCENTER__` prefix and double underscores as separators:

```bash
export BARYCENTER__AUTHZ__ENABLED=true
export BARYCENTER__AUTHZ__PORT=9082
export BARYCENTER__AUTHZ__POLICIES_DIR="/etc/barycenter/policies"
```

## Policy Directory Layout

The engine loads all files with the `.kdl` extension from the configured `policies_dir` directory. Files are loaded in alphabetical order, but load order does not affect evaluation semantics -- all nodes are merged into a single `AuthzState`.

### Recommended Structure

```
policies/
  01-resources.kdl       # Resource type definitions
  02-roles.kdl           # Role definitions with inheritance
  10-grants-infra.kdl    # Infrastructure team grants
  10-grants-platform.kdl # Platform team grants
  10-grants-services.kdl # Service account grants
  20-rules.kdl           # ABAC rules and conditions
```

Using numeric prefixes makes the load order predictable for humans reading the directory listing, even though it does not change evaluation behavior.

### Minimal Example

A minimal policy directory with a single file:

```
policies/
  policy.kdl
```

```kdl
// policies/policy.kdl

resource "api" {
    permissions {
        - "read"
        - "write"
    }
}

role "api_reader" {
    permissions {
        - "api:read"
    }
}

role "api_writer" {
    includes {
        - "api_reader"
    }
    permissions {
        - "api:write"
    }
}

grant "api_writer" on="api/v1" to="user/admin"
```

## Port Allocation

Barycenter uses a three-port architecture. The authorization engine occupies the third port:

| Server | Default Port | Configuration Key |
|--------|-------------|-------------------|
| Public OIDC | 8080 | `server.port` |
| Admin GraphQL | 8081 | (main port + 1, not separately configurable) |
| Authorization API | 8082 | `authz.port` |

If you change the main server port, the authorization port default follows unless you set `authz.port` explicitly:

```toml
[server]
port = 9090

[authz]
enabled = true
# port defaults to 9092 (9090 + 2)
```

To use a fixed port regardless of the main server port:

```toml
[authz]
enabled = true
port = 8082
```

## Immutability and Reloading

Policies are immutable after loading. The `AuthzState` is built once during startup and shared as read-only state for the lifetime of the process. To apply policy changes:

1. Edit the `.kdl` files in `policies_dir`.
2. Restart the Barycenter process.

This design provides several guarantees:

- **Consistency**: All authorization decisions within a single process lifetime use the same policy set.
- **Performance**: No locks, mutexes, or file watchers are needed during evaluation.
- **Auditability**: The policy set active at any given time is the set of files present when the process started.

In containerized deployments, this maps naturally to a rolling update: build a new container image (or update a ConfigMap), and let the orchestrator replace old pods with new ones.

## Docker Deployment

Mount the policy directory into the container:

```bash
docker run -d \
  -p 8080:8080 \
  -p 8081:8081 \
  -p 8082:8082 \
  -v ./policies:/app/policies:ro \
  -v ./config.toml:/app/config.toml:ro \
  barycenter:latest
```

The `:ro` (read-only) mount flag is recommended since the engine only reads policy files at startup.

### Docker Compose

```yaml
services:
  barycenter:
    image: barycenter:latest
    ports:
      - "8080:8080"
      - "8081:8081"
      - "8082:8082"
    volumes:
      - ./config.toml:/app/config.toml:ro
      - ./policies:/app/policies:ro
    environment:
      - BARYCENTER__AUTHZ__ENABLED=true
```

## Kubernetes Deployment

### Helm Chart Values

If you are using the Barycenter Helm chart, enable the authorization engine in your values file:

```yaml
authz:
  enabled: true
  port: 8082

  # Policy files are stored in a ConfigMap
  policies:
    configMapName: barycenter-authz-policies
```

### Policy ConfigMap

Store your policy files in a Kubernetes ConfigMap:

```bash
kubectl create configmap barycenter-authz-policies \
  --from-file=policies/
```

Or declare it in a manifest:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: barycenter-authz-policies
data:
  resources.kdl: |
    resource "vm" {
        relations {
            - "owner"
            - "viewer"
        }
        permissions {
            - "start"
            - "stop"
            - "view_console"
        }
    }
  roles.kdl: |
    role "vm_viewer" {
        permissions {
            - "vm:view_console"
        }
    }
    role "vm_admin" {
        includes {
            - "vm_viewer"
        }
        permissions {
            - "vm:start"
            - "vm:stop"
        }
    }
  grants.kdl: |
    grant "vm_admin" on="vm/prod-web-1" to="user/alice"
    grant "vm_viewer" on="vm/prod-web-1" to="group/sre#member"
```

Mount the ConfigMap as a volume in the pod spec:

```yaml
spec:
  containers:
    - name: barycenter
      volumeMounts:
        - name: authz-policies
          mountPath: /app/policies
          readOnly: true
  volumes:
    - name: authz-policies
      configMap:
        name: barycenter-authz-policies
```

### Service Configuration

Expose the authorization port as a separate Kubernetes Service so that backend services can reach it independently:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: barycenter-authz
spec:
  selector:
    app: barycenter
  ports:
    - name: authz
      port: 8082
      targetPort: 8082
```

Backend services can then call the authorization API at `http://barycenter-authz:8082/v1/check`.

### NetworkPolicy Considerations

The authorization API should typically be accessible only from backend services within the cluster, not from external traffic. A NetworkPolicy can enforce this:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: barycenter-authz-policy
spec:
  podSelector:
    matchLabels:
      app: barycenter
  policyTypes:
    - Ingress
  ingress:
    # Allow authorization API traffic only from pods with the "uses-authz" label
    - from:
        - podSelector:
            matchLabels:
              uses-authz: "true"
      ports:
        - protocol: TCP
          port: 8082

    # Allow public OIDC traffic from the ingress controller
    - from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: ingress-nginx
      ports:
        - protocol: TCP
          port: 8080
```

This policy ensures that:

- Port 8082 (authorization) is only reachable from pods labeled `uses-authz: "true"`.
- Port 8080 (OIDC) is reachable from the ingress controller namespace.
- Port 8081 (admin) is not accessible from outside the pod (unless you add an explicit rule).

### Updating Policies in Kubernetes

Since policies are immutable at runtime, updating them requires a pod restart. The typical workflow is:

1. Update the ConfigMap with new policy files:

   ```bash
   kubectl create configmap barycenter-authz-policies \
     --from-file=policies/ \
     --dry-run=client -o yaml | kubectl apply -f -
   ```

2. Trigger a rollout restart to pick up the new policies:

   ```bash
   kubectl rollout restart deployment/barycenter
   ```

3. Verify the rollout:

   ```bash
   kubectl rollout status deployment/barycenter
   ```

For automated policy deployments, consider adding the ConfigMap hash as a pod annotation so that Kubernetes automatically restarts pods when policies change:

```yaml
spec:
  template:
    metadata:
      annotations:
        checksum/authz-policies: {{ include (print $.Template.BasePath "/configmap-authz.yaml") . | sha256sum }}
```

## Monitoring

### Health Check

The `/healthz` endpoint is available for liveness and readiness probes:

```bash
curl http://localhost:8082/healthz
```

See [Authz REST API](./rest-api.md) for details on probe configuration.

### Logging

The authorization engine uses the same `RUST_LOG` environment variable as the rest of Barycenter. To see authorization-specific logs:

```bash
RUST_LOG=barycenter::authz=debug cargo run
```

At the `debug` level, the engine logs:

- Policy file loading and parsing results
- Number of resources, roles, grants, and rules loaded
- Individual check request evaluations (principal, permission, resource, result)

At the `trace` level, additional detail is logged:

- Role inheritance resolution
- Tuple index construction
- Condition expression evaluation steps

## Further Reading

- [Overview](./overview.md) -- what the authorization engine is and how it works
- [KDL Policy Language](./kdl-policy-language.md) -- writing policy files
- [Authz REST API](./rest-api.md) -- the HTTP endpoints exposed by the engine
- [Architecture](../getting-started/architecture.md) -- the three-port design
