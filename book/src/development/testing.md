# Testing

## Use cargo-nextest, Not cargo test

Barycenter uses [cargo-nextest](https://nexte.st/) as its test runner. **Do not use `cargo test`.**

This is a firm project requirement, not a suggestion. The standard `cargo test` runner executes tests as threads within a single process. Barycenter's integration tests start HTTP servers on specific ports, and running multiple such tests in the same process leads to port conflicts and flaky test failures.

cargo-nextest runs each test in its own process, providing:

- **Process isolation**: Each test gets its own address space, preventing port conflicts.
- **Reliable integration tests**: Tests that bind to ports cannot interfere with each other.
- **Better output**: Cleaner, more readable test output with per-test timing.
- **Faster execution**: Tests run in parallel across processes, with configurable concurrency.

## Installation

Install cargo-nextest if you do not already have it:

```bash
cargo install cargo-nextest
```

Verify the installation:

```bash
cargo nextest --version
```

## Running Tests

### Run All Tests

```bash
cargo nextest run
```

### Run with Verbose Output

```bash
cargo nextest run --verbose
```

### Run a Specific Test

```bash
cargo nextest run test_name
```

The test name can be a substring match. For example, `cargo nextest run token` runs all tests with "token" in their name.

### Run Tests in a Specific Module

```bash
cargo nextest run --filter-expr 'test(=web::tests::)'
```

### Run Tests with Output Capture Disabled

To see `println!` and log output during test execution:

```bash
cargo nextest run --no-capture
```

### Run Only Failed Tests from the Previous Run

```bash
cargo nextest run --run-ignored all --status-level fail
```

## Test Organization

Tests in Barycenter follow standard Rust conventions:

- **Unit tests**: Located in `#[cfg(test)]` modules within source files. These test individual functions and modules in isolation.
- **Integration tests**: Located in the `tests/` directory. These start the full HTTP server and make requests against it.

Integration tests are the primary reason cargo-nextest is required. Each integration test may start its own Barycenter server instance on a different port, and process isolation ensures these do not collide.

## Writing New Tests

When writing new tests, follow these guidelines:

1. **Use unique ports for integration tests** that start an HTTP server. Avoid hardcoding port numbers when possible.
2. **Do not rely on test execution order**. Each test must be independent.
3. **Clean up database state** in tests that modify the database. Use temporary SQLite databases or transactions that roll back.
4. **Use `#[tokio::test]`** for async tests, as the application uses the Tokio runtime.

Example integration test structure:

```rust
#[tokio::test]
async fn test_token_endpoint_requires_pkce() {
    // Set up a test server instance
    // Make HTTP requests to the server
    // Assert on the response
}
```

## Continuous Integration

The CI pipeline runs `cargo nextest run` as part of every pull request check. Tests must pass before a PR can be merged. See [Contributing](contributing.md) for the full list of CI checks.
