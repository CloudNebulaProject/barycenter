# Release Process

This document describes how to create a new release of Barycenter.

## Prerequisites

1. **Install cargo-release:**
   ```bash
   cargo install cargo-release
   ```

2. **Ensure you're on the main branch with a clean working tree:**
   ```bash
   git checkout main
   git pull origin main
   git status  # Should show clean working tree
   ```

3. **Verify all tests pass:**
   ```bash
   cargo nextest run
   cargo clippy -- -D warnings
   cargo fmt -- --check
   ```

## Release Steps

### 1. Update CHANGELOG.md

Before releasing, update the `CHANGELOG.md`:

1. Move all changes from `[Unreleased]` to a new version section
2. Add the release date
3. Ensure all changes are categorized (Added, Changed, Deprecated, Removed, Fixed, Security)

Example:
```markdown
## [Unreleased]

## [0.2.0] - 2025-12-01

### Added
- New feature X
- New feature Y

### Fixed
- Bug fix Z
```

### 2. Run cargo-release

cargo-release will:
- Bump the version in `Cargo.toml`
- Update the Helm chart versions
- Create a git commit
- Create a git tag
- Push to GitHub

**Dry run first (recommended):**
```bash
# Patch version bump (0.1.0 -> 0.1.1)
cargo release patch --dry-run

# Minor version bump (0.1.0 -> 0.2.0)
cargo release minor --dry-run

# Major version bump (0.1.0 -> 1.0.0)
cargo release major --dry-run

# Specific version
cargo release 1.0.0 --dry-run
```

**Execute the release:**
```bash
# Patch release
cargo release patch --execute

# Minor release
cargo release minor --execute

# Major release
cargo release major --execute

# Specific version
cargo release 1.0.0 --execute
```

### 3. Automated Release Process

Once the tag is pushed, GitHub Actions will automatically:

1. **Build Docker images** for multiple platforms:
   - linux/amd64
   - linux/arm64

2. **Push images to GitHub Container Registry** with tags:
   - `ghcr.io/[owner]/barycenter:v1.0.0` (full version)
   - `ghcr.io/[owner]/barycenter:1.0` (major.minor)
   - `ghcr.io/[owner]/barycenter:1` (major)
   - `ghcr.io/[owner]/barycenter:main-<sha>` (commit SHA)

3. **Create a GitHub Release** with:
   - Auto-generated changelog
   - Docker pull instructions
   - Links to documentation

4. **Generate attestations** for supply chain security

### 4. Verify the Release

After the release workflow completes:

1. **Check GitHub Releases:**
   - Visit https://github.com/[owner]/barycenter/releases
   - Verify the release notes are correct
   - Check that all assets are present

2. **Test the Docker image:**
   ```bash
   docker pull ghcr.io/[owner]/barycenter:v1.0.0
   docker run --rm ghcr.io/[owner]/barycenter:v1.0.0 --version
   ```

3. **Test the Helm chart:**
   ```bash
   helm install barycenter ./deploy/helm/barycenter \
     --dry-run \
     --namespace barycenter-test
   ```

## Versioning Strategy

We follow [Semantic Versioning](https://semver.org/):

- **MAJOR** version (1.0.0 → 2.0.0): Incompatible API changes
- **MINOR** version (1.0.0 → 1.1.0): Backwards-compatible new features
- **PATCH** version (1.0.0 → 1.0.1): Backwards-compatible bug fixes

### Pre-releases

For alpha, beta, or release candidates:

```bash
cargo release 1.0.0-alpha.1 --execute
cargo release 1.0.0-beta.1 --execute
cargo release 1.0.0-rc.1 --execute
```

Pre-release images are automatically marked as "pre-release" in GitHub.

## Hotfix Releases

For urgent fixes:

1. Create a hotfix branch from the release tag:
   ```bash
   git checkout -b hotfix/v1.0.1 v1.0.0
   ```

2. Make the fix and commit:
   ```bash
   git add .
   git commit -m "fix: critical security issue"
   ```

3. Run cargo-release:
   ```bash
   cargo release patch --execute
   ```

4. Merge back to main:
   ```bash
   git checkout main
   git merge hotfix/v1.0.1
   git push
   ```

## Rollback

If you need to rollback a release:

1. **Delete the tag locally and remotely:**
   ```bash
   git tag -d v1.0.0
   git push origin :refs/tags/v1.0.0
   ```

2. **Delete the GitHub Release:**
   - Go to Releases page
   - Click Edit on the release
   - Click Delete

3. **Delete the container images:**
   - Go to Packages page
   - Select the version
   - Delete the package version

4. **Revert the version bump commit:**
   ```bash
   git revert HEAD
   git push
   ```

## Troubleshooting

### cargo-release fails with dirty working tree

Ensure all changes are committed:
```bash
git status
git add .
git commit -m "chore: prepare for release"
```

### GitHub Actions workflow fails

Check the workflow logs:
1. Go to Actions tab
2. Click on the failing workflow
3. Review the error messages
4. Fix the issue and re-run the workflow

### Docker image build fails

Common issues:
- Platform-specific build errors: Check Dockerfile for platform compatibility
- Cache issues: Clear GitHub Actions cache and retry
- Dependency issues: Ensure Cargo.lock is up to date

## Post-Release Tasks

After a successful release:

1. **Announce the release:**
   - Update project documentation
   - Post to social media/forums
   - Notify users of breaking changes

2. **Monitor for issues:**
   - Watch GitHub Issues
   - Check container pull metrics
   - Monitor error reports

3. **Plan next release:**
   - Create milestone for next version
   - Triage issues and features
   - Update roadmap
