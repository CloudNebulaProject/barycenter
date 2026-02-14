# Building from Source

## Clone the Repository

```bash
git clone https://github.com/cloudnebulaproject/barycenter.git
cd barycenter
```

## Build

For a development build:

```bash
cargo build
```

For an optimized release build:

```bash
cargo build --release
```

The resulting binary is located at:

- Development: `target/debug/barycenter`
- Release: `target/release/barycenter`

## Run

Start the server with the default configuration:

```bash
cargo run
```

Or with a specific configuration file:

```bash
cargo run -- --config path/to/config.toml
```

In release mode:

```bash
cargo run --release
```

Or run the compiled binary directly:

```bash
./target/release/barycenter --config config.toml
```

## Workspace Structure

Barycenter is organized as a Cargo workspace with the following crates:

```
barycenter/
├── Cargo.toml          # Workspace root
├── src/                # Main application crate
│   ├── main.rs         # Entry point and CLI parsing
│   ├── settings.rs     # Configuration loading
│   ├── storage.rs      # Database layer
│   ├── web.rs          # HTTP endpoints and routing
│   ├── jwks.rs         # JWKS and JWT signing
│   ├── errors.rs       # Error types
│   └── ...
├── client-wasm/        # WebAuthn WASM client (browser-side)
│   ├── Cargo.toml
│   └── src/
├── migration/          # SeaORM database migrations
│   ├── Cargo.toml
│   └── src/
├── static/             # Static assets (HTML, CSS, JS, WASM)
├── book/               # mdbook documentation (this book)
├── config.toml         # Default configuration file
└── data/               # Runtime data (keys, database) -- created on first run
```

### Main Crate

The root crate (`src/`) contains the Barycenter server application. This is where the OIDC endpoints, authentication logic, admin API, and authorization policy engine live.

### client-wasm

The `client-wasm/` crate compiles to WebAssembly and runs in the browser. It handles WebAuthn API calls for passkey registration and authentication. See the [Prerequisites](./prerequisites.md) page for wasm-pack installation instructions.

To build the WASM module:

```bash
cd client-wasm
wasm-pack build --target web --out-dir ../static/wasm
```

The build output is placed in `static/wasm/` and served by the Barycenter web server automatically.

### migration

The `migration/` crate contains SeaORM migration definitions. Migrations run automatically when Barycenter starts -- there is no separate migration command to run. The migration crate handles creating and updating all database tables: clients, auth codes, access tokens, refresh tokens, sessions, users, passkeys, WebAuthn challenges, device codes, consents, job executions, and properties.

## CLI Arguments

```
barycenter [OPTIONS] [SUBCOMMAND]

Options:
  --config <PATH>    Path to configuration file (default: config.toml)

Subcommands:
  sync-users --file <PATH>    Sync users from a YAML/JSON file
```

## Verify the Build

After building, you can verify the binary runs correctly:

```bash
./target/release/barycenter --config config.toml
```

You should see log output indicating the three servers are starting on their respective ports. The default test user credentials are `admin` / `password123`.
