# GraphQL Playground

Barycenter ships with built-in GraphiQL playgrounds for both admin GraphQL schemas. These browser-based interfaces allow you to explore the schema, compose queries and mutations, view documentation, and test operations interactively -- without installing any external tooling.

## Playground URLs

| Playground | URL | Schema |
|---|---|---|
| Entity CRUD | `GET /admin/playground` | Seaography auto-generated CRUD for all entities |
| Job and User Management | `GET /admin/jobs/playground` | Custom queries and mutations for jobs and 2FA |

Both playgrounds are served on the admin port. If your admin API runs on port 8081:

- Entity CRUD playground: `http://localhost:8081/admin/playground`
- Job management playground: `http://localhost:8081/admin/jobs/playground`

## Using the Playground

### Opening the Playground

Navigate to the playground URL in any modern browser. The GraphiQL interface loads with three main panels:

1. **Query editor** (left) -- write your GraphQL queries and mutations here.
2. **Result panel** (right) -- displays the JSON response after executing a query.
3. **Documentation explorer** (accessible via the "Docs" button) -- browse the full schema, including all available types, queries, mutations, and their arguments.

### Exploring the Schema

Click the **Docs** button (or the book icon) in the upper-left area to open the documentation explorer. From here you can:

- Browse all available **queries** and **mutations**.
- Inspect **input types** and **filter types** to understand what arguments each operation accepts.
- View **return types** and their fields.
- Navigate the type hierarchy by clicking on type names.

This is particularly useful for the Seaography entity schema, where filter types and pagination parameters are auto-generated and may not be obvious without schema exploration.

### Writing and Executing Queries

Type your query in the left panel and press the play button (or use `Ctrl+Enter` / `Cmd+Enter`) to execute it.

**Example in the Entity CRUD playground:**

```graphql
{
  user {
    findMany {
      nodes {
        id
        username
        email
        requires2fa
      }
      paginationInfo {
        total
      }
    }
  }
}
```

**Example in the Job Management playground:**

```graphql
{
  availableJobs {
    name
    description
    schedule
  }
}
```

### Using Variables

The playground supports GraphQL variables. Click the **Variables** panel at the bottom of the query editor to define variables as JSON:

**Query:**

```graphql
query GetUser2FA($name: String!) {
  user2faStatus(username: $name) {
    username
    requires2fa
    passkeyEnrolled
    passkeyCount
  }
}
```

**Variables:**

```json
{
  "name": "alice"
}
```

### Request Headers

If you need to pass custom headers (for example, for authentication in a future release), use the **Headers** panel at the bottom of the query editor:

```json
{
  "Authorization": "Bearer your-admin-token"
}
```

## Choosing the Right Playground

The two playgrounds serve different purposes. Use this table to determine which one you need:

| Task | Playground |
|---|---|
| List, create, update, or delete users | Entity CRUD (`/admin/playground`) |
| List, create, update, or delete clients | Entity CRUD (`/admin/playground`) |
| Inspect sessions, tokens, or auth codes | Entity CRUD (`/admin/playground`) |
| View job execution history via entity query | Entity CRUD (`/admin/playground`) |
| Trigger a background job on demand | Job Management (`/admin/jobs/playground`) |
| Query job logs with filtering | Job Management (`/admin/jobs/playground`) |
| List available jobs and schedules | Job Management (`/admin/jobs/playground`) |
| Enable or disable 2FA for a user | Job Management (`/admin/jobs/playground`) |
| Check user 2FA and passkey enrollment status | Job Management (`/admin/jobs/playground`) |

## Browser Compatibility

The GraphiQL playground works in all modern browsers including Chrome, Firefox, Safari, and Edge. No browser extensions or plugins are required.

## Production Usage

In production environments where the admin port is not directly accessible from a developer workstation, you have several options:

- **Port forwarding**: Use SSH tunneling or `kubectl port-forward` to access the admin port locally.
- **curl**: Use `curl` or any HTTP client to send GraphQL requests directly. See [Job Management](./job-management.md) and [Entity CRUD](./entity-crud.md) for curl examples.
- **GraphQL clients**: Tools like Insomnia, Postman, or Altair GraphQL Client can connect to the admin endpoint.

```bash
# SSH tunnel to a remote server
ssh -L 8081:localhost:8081 user@server

# Kubernetes port-forward
kubectl port-forward svc/barycenter-admin 8081:8081
```

## Further Reading

- [Entity CRUD (Seaography)](./entity-crud.md) -- operations available in the entity CRUD schema
- [Job Management](./job-management.md) -- operations available in the job management schema
- [User 2FA Management](./user-2fa.md) -- 2FA operations in the job management schema
