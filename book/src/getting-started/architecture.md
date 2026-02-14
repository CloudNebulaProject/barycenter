# Architecture

Barycenter uses a three-port architecture where each port serves a distinct role. All three servers share a single database connection pool, JWKS manager, and application state.

## Three-Port Design

```mermaid
graph TB
    subgraph "Barycenter Process"
        subgraph "Public Server (port 8080)"
            OIDC["OIDC Endpoints"]
            Auth["Authentication"]
            WebAuthn["WebAuthn/Passkeys"]
            Device["Device Authorization"]
            UserInfo["UserInfo"]
        end

        subgraph "Admin Server (port 8081)"
            GQL["GraphQL API"]
            Jobs["Job Management"]
            UserMgmt["User Management"]
        end

        subgraph "Authz Server (port 8082)"
            Policy["Policy Evaluation"]
            KDL["KDL Policy Engine"]
        end

        State["Shared Application State"]
        JWKS["JWKS Manager"]
        Scheduler["Background Job Scheduler"]
    end

    DB[(Database<br/>SQLite or PostgreSQL)]

    OIDC --> State
    Auth --> State
    WebAuthn --> State
    Device --> State
    GQL --> State
    Policy --> State
    State --> DB
    State --> JWKS
    Scheduler --> DB

    Client["OIDC Clients"] --> OIDC
    Browser["User Browsers"] --> Auth
    Browser --> WebAuthn
    Admin["Admin Tools"] --> GQL
    Services["Backend Services"] --> Policy
```

### Public Server (default port 8080)

The public server handles all user-facing and client-facing OIDC operations:

- **Discovery**: `/.well-known/openid-configuration` and `/.well-known/jwks.json`
- **Client Registration**: `POST /connect/register`
- **Authorization**: `GET /authorize` with PKCE enforcement
- **Token Exchange**: `POST /token` (authorization code, refresh token, device code grants)
- **Token Revocation**: `POST /revoke`
- **UserInfo**: `GET /userinfo`
- **Authentication**: Login pages, password verification, WebAuthn flows
- **Device Authorization**: `POST /device/authorize` and `GET /device` verification page
- **Consent**: User consent approval and tracking

### Admin Server (default port 8081)

The admin server exposes a GraphQL API on the port immediately following the public port. It is intended for internal management and should not be exposed to the public internet.

- **User Management**: Query users, set 2FA requirements
- **Job Control**: Trigger background jobs manually, view execution history
- **System Queries**: List available jobs, check user status

### Authorization Policy Server (default port 8082)

The authorization policy server runs on the second port after the public port. It evaluates access control decisions using KDL-defined policies.

- **Policy Evaluation**: HTTP API for checking authorization decisions
- **ReBAC + ABAC**: Combines relationship-based and attribute-based access control

## Technology Stack

| Component | Technology | Purpose |
|-----------|-----------|---------|
| Language | Rust (stable) | Systems language with memory safety |
| Web framework | [axum](https://github.com/tokio-rs/axum) | Async HTTP framework built on tokio and hyper |
| Database ORM | [SeaORM](https://www.sea-ql.org/SeaORM/) | Async ORM supporting SQLite and PostgreSQL |
| JWT/JOSE | [josekit](https://github.com/nickel-org/josekit-rs) | JSON Web Token creation and signing |
| WebAuthn | [webauthn-rs](https://github.com/kanidm/webauthn-rs) | FIDO2/WebAuthn server implementation |
| GraphQL | [async-graphql](https://github.com/async-graphql/async-graphql) | GraphQL server for the admin API |
| Scheduling | [tokio-cron-scheduler](https://github.com/mvniekerk/tokio-cron-scheduler) | Cron-based background job scheduling |
| Password hashing | argon2 | Memory-hard password hashing |
| Configuration | config-rs + TOML | Layered configuration with file and environment support |
| WASM client | wasm-pack + wasm-bindgen | Browser-side WebAuthn operations |

## Startup Sequence

When Barycenter starts, it follows this initialization order:

```mermaid
sequenceDiagram
    participant CLI as CLI Parser
    participant Cfg as Settings
    participant DB as Database
    participant Mig as Migrations
    participant JWKS as JWKS Manager
    participant WA as WebAuthn
    participant GQL as GraphQL Schemas
    participant Sched as Scheduler
    participant Srv as Servers

    CLI->>Cfg: 1. Parse --config flag and subcommands
    Cfg->>Cfg: 2. Load defaults + config.toml + env vars
    Cfg->>DB: 3. Initialize database connection pool
    DB->>Mig: 4. Run pending migrations
    Mig->>JWKS: 5. Initialize JWKS (generate or load RSA keys)
    JWKS->>WA: 6. Initialize WebAuthn configuration
    WA->>GQL: 7. Build GraphQL schemas (admin + authz)
    GQL->>Sched: 8. Start background job scheduler
    Sched->>Srv: 9. Start all three servers concurrently
```

1. **Parse CLI**: Read `--config` path and any subcommands (e.g., `sync-users --file`)
2. **Load settings**: Merge default values, configuration file, and environment variables
3. **Initialize database**: Create connection pool to SQLite or PostgreSQL
4. **Run migrations**: Apply any pending schema migrations automatically
5. **Initialize JWKS**: Generate a 2048-bit RSA key pair on first run, or load existing keys from disk
6. **Initialize WebAuthn**: Configure the WebAuthn relying party based on the server's public URL
7. **Build GraphQL schemas**: Construct the async-graphql schemas for admin and authorization APIs
8. **Start scheduler**: Register cron jobs for cleanup of sessions, tokens, and challenges
9. **Start servers**: Launch all three HTTP servers concurrently on their respective ports

All three servers share the same tokio runtime and application state. If any server fails to bind its port, the entire process exits with an error.
