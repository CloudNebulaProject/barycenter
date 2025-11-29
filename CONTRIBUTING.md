# Contributing to Barycenter

Thank you for your interest in contributing to Barycenter! This document provides guidelines and instructions for contributing to the project.

## Code of Conduct

Be respectful, inclusive, and collaborative. We're here to build great software together.

## Development Workflow

We use **Gitflow** as our branching model. Please familiarize yourself with this workflow before contributing.

### Branch Structure

#### Main Branches

- `main` - Production-ready code. Only release and hotfix branches merge here.
- `develop` - Integration branch for features. Default branch for development.

#### Supporting Branches

- `feature/*` - New features and non-emergency bug fixes
- `release/*` - Release preparation (version bumps, final testing)
- `hotfix/*` - Emergency fixes for production issues

### Workflow Steps

#### Working on a New Feature

1. **Create a feature branch from `develop`:**
   ```bash
   git checkout develop
   git pull origin develop
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes** following our commit conventions (see below)

3. **Push your branch:**
   ```bash
   git push -u origin feature/your-feature-name
   ```

4. **Create a Pull Request** targeting `develop`

#### Creating a Release

1. **Create a release branch from `develop`:**
   ```bash
   git checkout develop
   git pull origin develop
   git checkout -b release/v1.2.0
   ```

2. **Update version numbers** and finalize changelog

3. **Create PR to `main`** and after merge, tag the release:
   ```bash
   git tag -a v1.2.0 -m "Release version 1.2.0"
   git push origin v1.2.0
   ```

4. **Merge back to `develop`** to include any release changes

#### Hotfix Process

1. **Create a hotfix branch from `main`:**
   ```bash
   git checkout main
   git pull origin main
   git checkout -b hotfix/v1.2.1
   ```

2. **Fix the issue** and update version number

3. **Create PR to `main`** and after merge, tag the hotfix

4. **Merge back to `develop`** to include the fix

## Commit Message Convention

We follow **Conventional Commits** specification. This leads to more readable commit history and enables automated changelog generation.

### Commit Message Format

```
<type>(<scope>): <subject>

<body>

<footer>
```

#### Type

Must be one of the following:

- `feat` - A new feature
- `fix` - A bug fix
- `docs` - Documentation only changes
- `style` - Changes that don't affect code meaning (formatting, whitespace)
- `refactor` - Code change that neither fixes a bug nor adds a feature
- `perf` - Performance improvement
- `test` - Adding or updating tests
- `build` - Changes to build system or dependencies
- `ci` - Changes to CI configuration files and scripts
- `chore` - Other changes that don't modify src or test files
- `revert` - Reverts a previous commit

#### Scope (Optional)

The scope should specify the place of the commit change:

- `auth` - Authentication/authorization
- `token` - Token endpoint and generation
- `jwks` - Key management and JWKS
- `storage` - Database and storage layer
- `config` - Configuration management
- `web` - Web server and routing
- `oidc` - OpenID Connect specific features
- `oauth` - OAuth 2.0 specific features

#### Subject

- Use imperative, present tense: "add" not "added" nor "adds"
- Don't capitalize first letter
- No period (.) at the end
- Maximum 50 characters

#### Body (Optional)

- Explain **what** and **why** (not how)
- Wrap at 72 characters
- Separate from subject with a blank line

#### Footer (Optional)

- Reference issues: `Closes #123` or `Fixes #456`
- Note breaking changes: `BREAKING CHANGE: description`

### Examples

#### Simple Feature
```
feat(auth): add PKCE S256 support

Implements code_challenge and code_verifier validation
according to RFC 7636.

Closes #42
```

#### Bug Fix
```
fix(token): validate token expiration correctly

Token validation was not properly checking the exp claim
against current time, allowing expired tokens to be used.
```

#### Breaking Change
```
feat(config)!: change database configuration format

BREAKING CHANGE: Database connection string now requires
explicit mode parameter. Update config.toml:

Old: connection_string = "sqlite://db.sqlite"
New: connection_string = "sqlite://db.sqlite?mode=rwc"
```

#### Documentation
```
docs: update README with configuration examples
```

#### Multiple Changes
```
refactor(storage): simplify client lookup logic

- Remove redundant database queries
- Add connection pooling
- Improve error messages

Related to #78
```

## Pull Request Process

1. **Update documentation** if you're changing functionality
2. **Add tests** for new features or bug fixes
3. **Ensure all tests pass**: `cargo test`
4. **Ensure code compiles**: `cargo check`
5. **Format your code**: `cargo fmt`
6. **Run clippy**: `cargo clippy`
7. **Update CHANGELOG.md** if applicable
8. **Reference related issues** in the PR description
9. **Request review** from maintainers

### PR Title

PR titles should also follow Conventional Commits format:

```
feat(auth): implement social login providers
fix(token): correct ID token expiration handling
docs: update API endpoint documentation
```

## Code Style

- Follow Rust standard style guidelines
- Run `cargo fmt` before committing
- Address `cargo clippy` warnings
- Use meaningful variable and function names
- Add comments for complex logic
- Keep functions focused and small

## Testing

- Write unit tests for new functions
- Add integration tests for new endpoints
- Test both success and error cases
- Aim for meaningful test coverage

```bash
# Run all tests
cargo test

# Run specific test
cargo test test_name

# Run with output
cargo test -- --nocapture
```

## Documentation

- Update `CLAUDE.md` for significant architectural changes
- Document all public APIs
- Include examples in documentation
- Update README.md for user-facing changes

## Questions or Problems?

- Open an issue for bugs or feature requests
- Tag issues appropriately (`bug`, `enhancement`, `question`)
- Provide detailed reproduction steps for bugs
- Search existing issues before creating new ones

## License

By contributing, you agree that your contributions will be licensed under the same license as the project.
