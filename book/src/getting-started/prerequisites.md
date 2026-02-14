# Prerequisites

## Required

### Rust Toolchain

Barycenter requires a stable Rust toolchain. Install it via [rustup](https://rustup.rs/):

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Verify the installation:

```bash
rustc --version
cargo --version
```

Any current stable release of Rust will work. The project does not require nightly features.

### Database Development Libraries

Barycenter supports SQLite and PostgreSQL. You need the development libraries for at least one of them.

**SQLite (default for development):**

```bash
# Debian / Ubuntu
sudo apt install libsqlite3-dev

# Fedora / RHEL
sudo dnf install sqlite-devel

# macOS (included with Xcode Command Line Tools)
xcode-select --install

# Arch Linux
sudo pacman -S sqlite
```

**PostgreSQL (recommended for production):**

```bash
# Debian / Ubuntu
sudo apt install libpq-dev

# Fedora / RHEL
sudo dnf install postgresql-devel

# macOS
brew install libpq

# Arch Linux
sudo pacman -S postgresql-libs
```

### Build Essentials

A C compiler and linker are required for building native dependencies (SQLite, argon2, etc.):

```bash
# Debian / Ubuntu
sudo apt install build-essential pkg-config

# Fedora / RHEL
sudo dnf groupinstall "Development Tools"

# macOS (included with Xcode Command Line Tools)
xcode-select --install
```

## Optional

These tools are not required to build or run Barycenter but are useful for development and testing.

### wasm-pack

Required only if you need to build the WebAuthn client WASM module:

```bash
cargo install wasm-pack
```

The WASM client handles browser-side WebAuthn API calls for passkey registration and authentication. Pre-built WASM artifacts may be included in releases.

### cargo-nextest

The project uses [cargo-nextest](https://nexte.st/) for running tests. Tests run in separate processes, which prevents port conflicts in integration tests.

```bash
cargo install cargo-nextest
```

### mdbook

Required only if you want to build this documentation locally:

```bash
cargo install mdbook
```

Then from the repository root:

```bash
mdbook serve book
```

## Operating System Support

Barycenter builds and runs on:

- **Linux** (primary development and deployment target) -- x86_64 and aarch64
- **macOS** -- x86_64 (Intel) and aarch64 (Apple Silicon)
- **Windows** -- Builds with MSVC toolchain; SQLite backend recommended

Linux is the recommended platform for production deployments. The Docker images are built for both `linux/amd64` and `linux/arm64`.
