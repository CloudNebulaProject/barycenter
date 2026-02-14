# Release Process

Barycenter uses tag-triggered releases. Pushing a Git tag matching the `v*.*.*` pattern triggers the CI pipeline to build artifacts, publish container images, and create a GitHub release.

## Triggering a Release

### 1. Prepare the Release

Ensure all changes for the release are merged into `main`. Update version numbers in `Cargo.toml` and finalize the changelog.

```bash
git checkout main
git pull origin main
```

### 2. Create and Push the Tag

```bash
git tag v1.2.0
git push origin v1.2.0
```

The tag name must match the `v*.*.*` pattern (e.g., `v1.0.0`, `v1.2.3`, `v2.0.0-rc.1`). The CI pipeline triggers automatically on tag push.

### 3. Monitor the Pipeline

The release pipeline performs several steps in sequence. Monitor it through the GitHub Actions UI or the CLI:

```bash
gh run list --workflow=release
gh run watch
```

## Release Pipeline Steps

### Step 1: Build Multi-Platform Docker Images

The pipeline builds Docker images for two architectures:

| Platform | Architecture | Use Case |
|----------|-------------|----------|
| `linux/amd64` | x86_64 | Standard servers, cloud instances |
| `linux/arm64` | AArch64 | ARM servers, AWS Graviton, Apple Silicon |

Both images are built from the same Dockerfile using Docker's `--platform` build argument. Platform-specific build caches are used to optimize parallel builds and avoid cache conflicts between architectures.

The images are tagged with:
- The version tag (e.g., `v1.2.0`)
- `latest` (for the most recent stable release)

### Step 2: Publish to GitHub Container Registry

Built images are published to GitHub Container Registry (GHCR):

```
ghcr.io/your-org/barycenter:v1.2.0
ghcr.io/your-org/barycenter:latest
```

A multi-architecture manifest is created so that `docker pull ghcr.io/your-org/barycenter:v1.2.0` automatically selects the correct image for the host platform.

### Step 3: Create GitHub Release

The pipeline creates a GitHub release with:

- **Release title**: The tag name (e.g., `v1.2.0`)
- **Changelog**: Auto-generated from commits since the previous release tag, organized by conventional commit type
- **Binary artifacts**: The compiled `barycenter` binary for each platform (if configured)

The changelog groups commits by type:

```markdown
## What's Changed

### Features
- feat: add refresh token rotation (#42)
- feat: add device code flow support (#45)

### Bug Fixes
- fix: prevent double consumption of authorization codes (#43)

### Other Changes
- chore: update sea-orm to 1.1.0 (#44)
- docs: add PKCE security documentation (#46)
```

### Step 4: Generate Artifact Attestation

The pipeline generates [artifact attestation](https://docs.github.com/en/actions/security-guides/using-artifact-attestations-and-reusable-workflows-to-verify-builds) for the published container images. Attestation provides a cryptographic proof that the container image was built by the CI pipeline from a specific commit in the repository.

This allows consumers to verify the provenance of the image:

```bash
gh attestation verify oci://ghcr.io/your-org/barycenter:v1.2.0 \
  --owner your-org
```

## Version Numbering

Barycenter follows [Semantic Versioning](https://semver.org/):

| Component | When to Increment | Example |
|-----------|-------------------|---------|
| **Major** (X.0.0) | Breaking changes to the public API, configuration format, or database schema that requires manual migration | `v1.0.0` to `v2.0.0` |
| **Minor** (0.X.0) | New features, non-breaking additions to the API or configuration | `v1.0.0` to `v1.1.0` |
| **Patch** (0.0.X) | Bug fixes, security patches, documentation updates | `v1.0.0` to `v1.0.1` |

Pre-release versions use a suffix: `v1.2.0-rc.1`, `v1.2.0-beta.1`.

## Hotfix Releases

For urgent production fixes:

1. Create a hotfix branch from the latest release tag:
   ```bash
   git checkout -b hotfix/1.2.1 v1.2.0
   ```

2. Apply the fix and commit with conventional commit format.

3. Merge into `main` and tag:
   ```bash
   git checkout main
   git merge hotfix/1.2.1
   git tag v1.2.1
   git push origin main --tags
   ```

4. Merge back into `develop`:
   ```bash
   git checkout develop
   git merge hotfix/1.2.1
   git push origin develop
   ```

The tag push triggers the same release pipeline.

## Post-Release Checklist

After a release is published:

- [ ] Verify the GitHub release page has the correct changelog and artifacts
- [ ] Verify the Docker image is pullable from GHCR: `docker pull ghcr.io/your-org/barycenter:vX.Y.Z`
- [ ] Verify the multi-arch manifest works on both amd64 and arm64
- [ ] Verify artifact attestation: `gh attestation verify oci://ghcr.io/your-org/barycenter:vX.Y.Z --owner your-org`
- [ ] Update deployment configurations to reference the new version
- [ ] Announce the release to stakeholders if it contains user-facing changes
- [ ] Merge the release branch (or `main`) back into `develop` if not already done
