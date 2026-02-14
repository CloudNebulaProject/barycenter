# Contributing

This page describes the development workflow, branching strategy, commit conventions, and CI pipeline for contributing to Barycenter.

## Branching Strategy

Barycenter follows the Gitflow workflow:

| Branch | Purpose | Merges Into |
|--------|---------|-------------|
| `main` | Production-ready code. Every commit on `main` is a release or release candidate. | -- |
| `develop` | Integration branch for features. Contains the latest development changes. | `main` (via release branch) |
| `feature/*` | New features and enhancements. One branch per feature. | `develop` |
| `release/*` | Release preparation. Version bumps, changelog updates, final fixes. | `main` and `develop` |
| `hotfix/*` | Urgent production fixes. Branched from `main`. | `main` and `develop` |

### Feature Branch Workflow

1. Create a feature branch from `develop`:
   ```bash
   git checkout develop
   git pull origin develop
   git checkout -b feature/my-feature
   ```

2. Make changes, commit with conventional commit messages (see below).

3. Push and open a pull request targeting `develop`:
   ```bash
   git push -u origin feature/my-feature
   ```

4. After code review and CI checks pass, merge the PR into `develop`.

### Release Workflow

1. Create a release branch from `develop`:
   ```bash
   git checkout -b release/1.2.0 develop
   ```

2. Update version numbers, finalize changelog, apply last-minute fixes.

3. Merge into `main` and tag:
   ```bash
   git checkout main
   git merge release/1.2.0
   git tag v1.2.0
   git push origin main --tags
   ```

4. Merge back into `develop`:
   ```bash
   git checkout develop
   git merge release/1.2.0
   ```

### Hotfix Workflow

1. Create a hotfix branch from `main`:
   ```bash
   git checkout -b hotfix/1.2.1 main
   ```

2. Apply the fix and update the version.

3. Merge into both `main` (with tag) and `develop`.

## Conventional Commits

All commit messages must follow the [Conventional Commits](https://www.conventionalcommits.org/) format:

```
<type>[optional scope]: <description>

[optional body]

[optional footer(s)]
```

### Commit Types

| Type | Usage |
|------|-------|
| `feat` | A new feature or capability |
| `fix` | A bug fix |
| `docs` | Documentation changes only |
| `chore` | Build process, dependencies, or auxiliary tool changes |
| `refactor` | Code change that neither fixes a bug nor adds a feature |
| `test` | Adding or updating tests |
| `perf` | Performance improvement |
| `ci` | CI/CD pipeline changes |
| `style` | Code style changes (formatting, whitespace) that do not affect logic |

### Examples

```
feat: add refresh token rotation

Implement refresh token rotation per RFC 6749. When a refresh token
is used, the old token is revoked and a new one is issued.

Closes #42
```

```
fix: prevent double consumption of authorization codes

Authorization codes were not atomically marked as consumed, allowing
a race condition where the same code could be exchanged twice.
```

```
docs: add PKCE security documentation
```

```
chore: update sea-orm to 1.1.0
```

### Breaking Changes

Breaking changes must include a `BREAKING CHANGE` footer or a `!` after the type:

```
feat!: change token endpoint to require PKCE for all clients

BREAKING CHANGE: Public clients without PKCE will now receive an
invalid_request error. All clients must include code_challenge and
code_challenge_method=S256 in authorization requests.
```

## Pull Request Process

1. **Create a feature branch** following the naming convention `feature/descriptive-name`.
2. **Write tests** for new functionality. All new features must include tests.
3. **Run the full CI check locally** before pushing:
   ```bash
   cargo fmt --check
   cargo clippy -- -D warnings
   cargo nextest run
   ```
4. **Open a PR** targeting `develop` (or `main` for hotfixes).
5. **Fill in the PR template** with a description of changes, testing steps, and any breaking changes.
6. **Address review feedback** by pushing additional commits (do not force-push during review).
7. **CI must pass** before the PR can be merged.

## CI Pipeline

Every pull request runs the following checks. All must pass before merging.

### Formatting Check

```bash
cargo fmt --check
```

Verifies that all code is formatted according to the project's `rustfmt` configuration. Run `cargo fmt` locally to auto-format before committing.

### Clippy Lints

```bash
cargo clippy -- -D warnings
```

Runs the Clippy linter with all warnings treated as errors. Clippy catches common mistakes, non-idiomatic code, and potential bugs. If Clippy produces a false positive, suppress it with an `#[allow]` attribute and a comment explaining why.

### Test Suite

```bash
cargo nextest run
```

Runs the full test suite using cargo-nextest. Tests must pass on both SQLite and PostgreSQL backends (if applicable). See [Testing](testing.md) for details on why nextest is required.

### Docker Build

The CI pipeline builds the Docker image to verify that the application compiles and packages correctly. This catches issues like missing dependencies or build script errors that might not appear in a local `cargo build`.

### Security Audit

```bash
cargo audit
```

Checks dependencies for known security vulnerabilities using the RustSec Advisory Database. Any crate with a known vulnerability must be updated or the advisory must be explicitly acknowledged with a justification.

## Code Style

### Formatting

The project uses the default `rustfmt` configuration. Run `cargo fmt` before committing.

### Error Handling

- Use `CrabError` for all errors that propagate through the application.
- Add miette diagnostics with actionable help text for configuration and runtime errors.
- See [Error Handling](error-handling.md) for patterns and guidelines.

### Database Access

- Always use SeaORM entities for database access. Never write raw SQL.
- Define new entities in `src/entities/` and add corresponding migrations in `migration/src/`.

### Testing

- Use `cargo nextest run`, not `cargo test`.
- Write unit tests in `#[cfg(test)]` modules within the source file.
- Write integration tests in the `tests/` directory.
- Use `#[tokio::test]` for async tests.

## Setting Up the Development Environment

1. **Install Rust** (stable toolchain):
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   ```

2. **Install development tools**:
   ```bash
   cargo install cargo-nextest
   cargo install wasm-pack
   cargo install sea-orm-cli
   ```

3. **Clone the repository**:
   ```bash
   git clone https://github.com/your-org/barycenter.git
   cd barycenter
   ```

4. **Build and run**:
   ```bash
   cargo build
   cargo run
   ```

5. **Run tests**:
   ```bash
   cargo nextest run
   ```
