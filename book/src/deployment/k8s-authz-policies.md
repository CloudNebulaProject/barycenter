# Authorization Policies in Kubernetes

The Barycenter Helm chart provides two ways to deploy [KDL authorization policies](../authz/kdl-policy-language.md) into Kubernetes: inline in `values.yaml` or via an existing ConfigMap.

## Prerequisites

The authorization engine must be enabled in the chart configuration:

```yaml
config:
  authz:
    enabled: true
```

Without this, the authorization server on port 8082 does not start and policy files are ignored.

## Inline Policies

For simple policy sets, define the KDL content directly in `values.yaml`:

```yaml
authz:
  policies: |
    resource "document" {
      permission "read"
      permission "write"
      permission "delete"
    }

    resource "project" {
      permission "read"
      permission "manage"
    }

    role "viewer" {
      permission "document:read"
      permission "project:read"
    }

    role "editor" {
      include "viewer"
      permission "document:write"
    }

    role "admin" {
      include "editor"
      permission "document:delete"
      permission "project:manage"
    }

    grant "admin" on="project/proj-1" to="user/alice"
    grant "editor" on="project/proj-1" to="user/bob"
```

The chart renders this content into a ConfigMap and mounts it into the pod at the path the authorization engine expects.

## Using an Existing ConfigMap

For larger policy sets or when policies are managed through a separate GitOps pipeline, create a ConfigMap containing one or more `.kdl` files:

```bash
kubectl create configmap barycenter-policies \
  --from-file=policies.kdl=./policies.kdl \
  -n barycenter
```

Reference it in your values:

```yaml
authz:
  existingConfigMap: barycenter-policies
```

The ConfigMap can contain multiple files. All `.kdl` files in the ConfigMap are loaded by the authorization engine.

### Managing Policies with Kustomize

If you use Kustomize, you can generate the ConfigMap from a directory of policy files:

```yaml
# kustomization.yaml
configMapGenerator:
  - name: barycenter-policies
    files:
      - policies/base.kdl
      - policies/teams.kdl
      - policies/projects.kdl
```

Then set `authz.existingConfigMap` to the generated ConfigMap name (Kustomize appends a hash suffix by default).

## Network Policy

The authorization API (port 8082) should not be exposed to the public internet. By default, the chart's Service makes it reachable from anywhere within the cluster. To restrict access to only pods in the same namespace:

```yaml
authz:
  networkPolicy:
    enabled: true
```

This creates a NetworkPolicy that allows ingress to port 8082 only from pods in the same namespace as the Barycenter release. Pods in other namespaces and external traffic are denied.

If your services that need to call the authorization API are in a different namespace, you will need to customize the NetworkPolicy. The generated policy can be used as a starting point:

```bash
kubectl get networkpolicy -n barycenter -o yaml
```

## Updating Policies

KDL policies are loaded once at startup and are immutable at runtime. To apply policy changes:

1. Update the inline `authz.policies` content or the ConfigMap contents.
2. Run `helm upgrade` to update the ConfigMap.
3. Restart the Barycenter pods to reload policies:

```bash
kubectl rollout restart deployment barycenter -n barycenter
```

The restart is necessary because policy files are read at process startup. A ConfigMap change alone does not trigger a reload.

> **Tip:** To automate restarts on ConfigMap changes, consider using a tool like [Reloader](https://github.com/stakater/Reloader) or adding a checksum annotation to the Deployment template that changes when the ConfigMap content changes.

## Verifying Policies

After deployment, verify the authorization engine is running and policies are loaded:

```bash
# Check that port 8082 is listening
kubectl port-forward svc/barycenter 8082:8082 -n barycenter

# In another terminal, test a check request
curl -X POST http://localhost:8082/v1/check \
  -H "Content-Type: application/json" \
  -d '{
    "principal": "user/alice",
    "permission": "document:read",
    "resource": "project/proj-1"
  }'
```

A successful response indicates the policies are loaded and the engine is evaluating requests.

## Further Reading

- [Helm Chart Values](./helm-values.md) -- full reference of `authz.*` values
- [KDL Policy Language](../authz/kdl-policy-language.md) -- syntax and structure of policy files
- [Authorization Overview](../authz/overview.md) -- how the authorization engine works
- [Authz REST API](../authz/rest-api.md) -- the check endpoint and request format
