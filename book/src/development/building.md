# Building

Barycenter is built with Cargo, the Rust package manager and build system. The project is organized as a Cargo workspace with multiple crates.

## Quick Start

```bash
# Check the code compiles without producing a binary
cargo check

# Build in debug mode (faster compilation, unoptimized)
cargo build

# Build in release mode (slower compilation, optimized)
cargo build --release

# Run directly in debug mode
cargo run

# Run with a custom configuration file
cargo run -- --config path/to/config.toml

# Run in release mode
cargo run --release
```

## Workspace Structure

The repository is organized as a Cargo workspace with three crates:

```
barycenter/
├── Cargo.toml            # Workspace root
├── src/                  # Main application crate
│   ├── main.rs           # Entry point
│   ├── lib.rs            # Library root (module declarations)
│   └── ...
├── client-wasm/          # WebAssembly client crate
│   ├── Cargo.toml
│   └── src/
│       └── lib.rs
├── migration/            # SeaORM database migrations
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       └── m*.rs         # Individual migration files
└── static/               # Static assets served by the web server
    └── wasm/             # Built WASM output (generated)
```

### Main Crate (`barycenter`)

The primary application crate containing all server-side logic: HTTP endpoints, authentication, session management, database operations, JWKS handling, and the admin GraphQL API.

### Client WASM Crate (`client-wasm`)

A Rust library compiled to WebAssembly that runs in the browser. It provides the client-side WebAuthn/passkey functionality used by the login and account management pages. This crate is built separately with `wasm-pack` and is not part of the normal `cargo build`. See [WASM Client](wasm-client.md) for build instructions.

### Migration Crate (`migration`)

Contains SeaORM database migration files that define and evolve the database schema. Migrations run automatically on application startup. This crate is a dependency of the main crate.

## Build Profiles

### Debug Build

```bash
cargo build
```

The debug build is intended for development. It compiles faster but produces larger, slower binaries. Debug builds include:

- Debug symbols for debugger support
- Overflow checks on arithmetic operations
- Debug assertions
- No optimizations

The output binary is located at `target/debug/barycenter`.

### Release Build

```bash
cargo build --release
```

The release build is intended for production deployment. It takes longer to compile but produces optimized binaries. Release builds include:

- Full optimization (opt-level 3 by default)
- No debug assertions
- Smaller binary size (with strip if configured)

The output binary is located at `target/release/barycenter`.

## Checking Code

To verify that the code compiles without producing a binary:

```bash
cargo check
```

This is significantly faster than `cargo build` and is useful during development for catching compilation errors quickly.

## Logging

Barycenter uses the `RUST_LOG` environment variable to control log verbosity:

```bash
# Enable debug logging for all crates
RUST_LOG=debug cargo run

# Enable trace logging for Barycenter only
RUST_LOG=barycenter=trace cargo run

# Combine different levels for different crates
RUST_LOG=barycenter=debug,sea_orm=info cargo run
```

## Cross-Compilation

For building Docker images targeting different architectures (e.g., building an ARM64 image on an AMD64 host), see the Docker build configuration in the CI pipeline. The release process produces multi-platform images for both `amd64` and `arm64`.

## Next Steps

- [Testing](testing.md) -- Running the test suite
- [WASM Client](wasm-client.md) -- Building the WebAssembly client
- [Architecture](architecture.md) -- Understanding the codebase structure
