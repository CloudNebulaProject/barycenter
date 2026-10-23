# Generated Entity Schema (Seaography)

Barycenter retains a Seaography-generated schema at `POST /admin/graphql`, with
its playground at `GET /admin/playground` on the admin port. Entity reads are
currently unavailable: the schema does not supply a database connection to the
generated resolvers. This is the same wiring as on `main`.

The generated entity types include raw credential columns. Connecting those
resolvers to the database would expose those columns through an admin listener
that has no built-in GraphQL authentication layer. Do not enable generated entity
reads as a way to inspect client trust.

## Client Metadata and Trust

Use the hand-written schema at `POST /admin/jobs` instead. Its `client` and
`clients` queries return only `clientId`, `clientName`, `redirectUris`, and
`trusted`. They do not expose client secrets. For example:

```graphql
{
  clients {
    clientId
    clientName
    redirectUris
    trusted
  }
}
```

See [Admin GraphQL API](./graphql-api.md#client-trust) for lookup by client ID,
trust mutations, and access restrictions. Use the supported
[user management](./user-management.md), [user sync CLI](./user-sync.md), and
[job management](./job-management.md) paths for other administrative operations.
