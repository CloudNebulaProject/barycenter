# Authz REST API

The authorization policy engine exposes a REST API on a dedicated port (default: 8082) for evaluating access control decisions. The API provides three endpoints: a permission check endpoint, a permission expansion endpoint, and a health check.

## Base URL

The authorization API runs on its own port, separate from the public OIDC server and the admin GraphQL API. By default, the port is the main server port plus 2:

| Server | Default Port |
|--------|-------------|
| Public OIDC | 8080 |
| Admin GraphQL | 8081 |
| **Authorization API** | **8082** |

All endpoints are prefixed with `/v1/` except the health check.

## POST /v1/check

Evaluates whether a principal has a specific permission on a resource. This is the primary endpoint that backend services call to make authorization decisions.

### Request

```
POST /v1/check
Content-Type: application/json
```

```json
{
    "principal": "user/alice",
    "permission": "vm:start",
    "resource": "vm/prod-web-1",
    "context": {}
}
```

#### Request Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `principal` | string | Yes | The subject requesting access, in `type/id` format (e.g., `"user/alice"`, `"service/deploy-agent"`). |
| `permission` | string | Yes | The fully-qualified permission being requested, in `type:action` format (e.g., `"vm:start"`). |
| `resource` | string | Yes | The target resource instance, in `type/id` format (e.g., `"vm/prod-web-1"`). |
| `context` | object | No | A JSON object containing contextual attributes for [ABAC rule](./abac-rules.md) evaluation. Defaults to an empty object if omitted. |

### Response

```json
{
    "allowed": true
}
```

#### Response Fields

| Field | Type | Description |
|-------|------|-------------|
| `allowed` | boolean | `true` if the principal has the requested permission on the resource, `false` otherwise. |

### Examples

**Basic permission check:**

```bash
curl -s -X POST http://localhost:8082/v1/check \
  -H "Content-Type: application/json" \
  -d '{
    "principal": "user/alice",
    "permission": "vm:start",
    "resource": "vm/prod-web-1"
  }' | jq .
```

```json
{
    "allowed": true
}
```

**Check with context for ABAC rule evaluation:**

```bash
curl -s -X POST http://localhost:8082/v1/check \
  -H "Content-Type: application/json" \
  -d '{
    "principal": "user/bob",
    "permission": "invoice:view",
    "resource": "invoice/inv-2024-001",
    "context": {
      "request": {
        "time": {
          "hour": 14,
          "day_of_week": "Wednesday"
        },
        "source": "internal"
      },
      "environment": {
        "maintenance_mode": false
      }
    }
  }' | jq .
```

```json
{
    "allowed": true
}
```

**Denied request:**

```bash
curl -s -X POST http://localhost:8082/v1/check \
  -H "Content-Type: application/json" \
  -d '{
    "principal": "user/mallory",
    "permission": "vm:delete",
    "resource": "vm/prod-db-1"
  }' | jq .
```

```json
{
    "allowed": false
}
```

### Integration Pattern

A typical integration pattern is to call the check endpoint from your application middleware before processing a request:

```python
import httpx

AUTHZ_URL = "http://localhost:8082/v1/check"

async def check_permission(principal: str, permission: str, resource: str, context: dict = None):
    response = await httpx.AsyncClient().post(AUTHZ_URL, json={
        "principal": principal,
        "permission": permission,
        "resource": resource,
        "context": context or {}
    })
    response.raise_for_status()
    return response.json()["allowed"]

# In a request handler:
if not await check_permission(f"user/{current_user.id}", "vm:start", f"vm/{vm_id}"):
    raise PermissionDenied("You are not allowed to start this VM.")
```

## POST /v1/expand

Returns the set of all subjects (principals) that have a specific permission on a resource. This is useful for building UIs that show "who has access to this resource" or for auditing purposes.

### Request

```
POST /v1/expand
Content-Type: application/json
```

```json
{
    "permission": "vm:start",
    "resource": "vm/prod-web-1"
}
```

#### Request Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `permission` | string | Yes | The fully-qualified permission to expand, in `type:action` format. |
| `resource` | string | Yes | The target resource instance, in `type/id` format. |

### Response

```json
{
    "subjects": [
        "user/alice",
        "group/sre#member"
    ]
}
```

#### Response Fields

| Field | Type | Description |
|-------|------|-------------|
| `subjects` | string[] | A list of subject references that have the requested permission on the resource. Includes both direct subjects and userset references. |

### Examples

**Expand all subjects with a permission:**

```bash
curl -s -X POST http://localhost:8082/v1/expand \
  -H "Content-Type: application/json" \
  -d '{
    "permission": "vm:start",
    "resource": "vm/prod-web-1"
  }' | jq .
```

```json
{
    "subjects": [
        "user/alice",
        "group/sre#member"
    ]
}
```

**Expand with no matching subjects:**

```bash
curl -s -X POST http://localhost:8082/v1/expand \
  -H "Content-Type: application/json" \
  -d '{
    "permission": "vm:delete",
    "resource": "vm/prod-web-99"
  }' | jq .
```

```json
{
    "subjects": []
}
```

> **Note**: The expand endpoint resolves grant-based access only. It does not evaluate ABAC rules, because rule evaluation depends on a specific principal and context that are not available in an expand query.

## GET /healthz

A simple health check endpoint that returns the status of the authorization engine.

### Request

```
GET /healthz
```

No request body or parameters are required.

### Response

A successful response indicates that the authorization engine is running and has loaded its policies:

```
HTTP/1.1 200 OK
Content-Type: application/json
```

```json
{
    "status": "ok"
}
```

### Example

```bash
curl -s http://localhost:8082/healthz | jq .
```

```json
{
    "status": "ok"
}
```

This endpoint is intended for use with container orchestrators (Kubernetes liveness/readiness probes), load balancers, and monitoring systems.

### Kubernetes Probe Configuration

```yaml
livenessProbe:
  httpGet:
    path: /healthz
    port: 8082
  initialDelaySeconds: 5
  periodSeconds: 10

readinessProbe:
  httpGet:
    path: /healthz
    port: 8082
  initialDelaySeconds: 3
  periodSeconds: 5
```

## Error Handling

The API returns standard HTTP status codes for error conditions:

| Status Code | Condition | Response Body |
|-------------|-----------|---------------|
| `200` | Request processed successfully | `{ "allowed": true/false }` or `{ "subjects": [...] }` |
| `400` | Malformed request body or missing required fields | `{ "error": "description of the problem" }` |
| `404` | Unknown endpoint | `{ "error": "not found" }` |
| `405` | Wrong HTTP method (e.g., GET on /v1/check) | `{ "error": "method not allowed" }` |
| `500` | Internal server error during evaluation | `{ "error": "internal error" }` |

### Error Response Format

Error responses include a descriptive message:

```json
{
    "error": "missing required field: principal"
}
```

### Common Errors

**Missing required field:**

```bash
curl -s -X POST http://localhost:8082/v1/check \
  -H "Content-Type: application/json" \
  -d '{"permission": "vm:start", "resource": "vm/prod-web-1"}' | jq .
```

```json
{
    "error": "missing required field: principal"
}
```

**Invalid JSON:**

```bash
curl -s -X POST http://localhost:8082/v1/check \
  -H "Content-Type: application/json" \
  -d 'not json' | jq .
```

```json
{
    "error": "invalid JSON in request body"
}
```

## Performance Considerations

The authorization engine is designed for low-latency evaluation:

- **In-memory evaluation**: All policies, grants, and indexes are held in memory. No database queries are made during check or expand operations.
- **Pre-computed indexes**: Role inheritance is resolved at load time. The `permission_roles` map and `TupleIndex` enable constant-time lookups for most checks.
- **No network hops**: The engine runs in the same process as Barycenter, so internal callers (such as future OIDC-to-authz integration) avoid network round-trips entirely.
- **Immutable state**: The `AuthzState` is read-only after loading, so no locks or synchronization are needed during evaluation.

For external callers, the primary latency factor is network round-trip time. Placing the authorization engine close to (or on the same host as) the calling service minimizes this overhead.

## Further Reading

- [Overview](./overview.md) -- the evaluation pipeline behind `/v1/check`
- [ABAC Rules and Conditions](./abac-rules.md) -- how the `context` field is used in rule evaluation
- [Configuration and Deployment](./configuration.md) -- setting the authorization port and policy directory
