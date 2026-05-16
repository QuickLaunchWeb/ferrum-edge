# CI/CD Pipeline Documentation

Ferrum Edge includes comprehensive CI/CD pipelines for automated testing, building, and releasing.

## Table of Contents

- [Pipeline Overview](#pipeline-overview)
- [CI Pipeline (ci.yml)](#ci-pipeline-ciyml)
- [Release Pipeline (release.yml)](#release-pipeline-releaseyml)
- [How Releases Work](#how-releases-work)
- [Creating a New Release](#creating-a-new-release)
- [Binaries and Downloads](#binaries-and-downloads)
- [GitHub Actions Secrets](#github-actions-secrets)

## Pipeline Overview

Two main workflows handle different aspects of the development lifecycle:

| Workflow | Trigger | Purpose |
|----------|---------|---------|
| **CI** (`ci.yml`) | Pull Requests, push to `main` | PR validation; latest binaries and Docker images on `main` |
| **Release** (`release.yml`) | Push tag matching `v*` | Versioned binaries, GitHub release, and Docker tags |

### CI Pipeline Flow

```
Pull Request
    ├─► Format
    ├─► Unit / inline-lib / integration / functional-shard tests
    ├─► Lint, eBPF change check, performance regression check
    └─► Five target release builds

Push to main
    └─► Five target release builds
            ├─► Replace latest GitHub prerelease
            └─► Push Docker images to Docker Hub and GHCR
```

### Release Pipeline Flow

```
Push tag v* (e.g., v0.2.0)
        │
        ├─► Build linux-x86_64
        ├─► Build linux-aarch64 (ARM)
        ├─► Build macos-x86_64
        ├─► Build macos-aarch64 (Apple Silicon)
        ├─► Build windows-x86_64
        └─► Push versioned Docker images to Docker Hub and GHCR
                └─► Create Docker manifest tags
                        └─► Create GitHub Release with binaries and checksums
```

## CI Pipeline (ci.yml)

The CI workflow is triggered by every pull request and every push to `main`, but the jobs differ by event. Test, lint, eBPF, and performance jobs are PR-only. Pushes to `main` run the cross-platform build matrix and, after successful builds, publish the `latest` prerelease and Docker images in parallel.

CI uses `concurrency.group: ci-publish-${{ github.ref }}` with `cancel-in-progress: true`, so a newer push to the same branch cancels the older CI run.

### Jobs

#### 1. Format Job

**Runs**: `ubuntu-latest`

Checks Rust formatting on pull requests:

```bash
cargo fmt --all -- --check
```

**Failures**:
- Indicate formatting drift
- Must be fixed before merging

#### 2. Test Jobs

**Runs**: `ubuntu-latest`

Runs the PR test matrix in parallel:

```bash
cargo test --test unit_tests
cargo test --lib
cargo test --test integration_tests
cargo build --bin ferrum-edge
cargo nextest run --test functional_tests --run-ignored=all --no-fail-fast ...
```

**What it tests**:
- Unit tests in `tests/unit_tests.rs`
- Inline `#[cfg(test)]` modules in `src/`
- Integration tests
- Functional tests split across harness, admin/routing, data-plane, plugins, protocols, and resilience shards. CI builds the gateway binary once in `build-gateway-binary`, uploads it as an artifact, and each functional shard downloads it with `FERRUM_SKIP_GATEWAY_BUILD=1`. The data-plane shard runs serialized with `nextest_jobs: 1`, and Redis/MongoDB service containers are available for the shards that need them.

**Output**:
- Test pass/fail status
- Failures block PR merges (if branch protection enabled)

#### 3. Lint Job

**Runs**: `ubuntu-latest`

Enforces code quality:

```bash
cargo clippy --all-targets -- -D warnings
```

**What it checks**:
- Code style and idioms (clippy)

**Failures**:
- Indicate quality issues
- Must be fixed before merging

#### 4. eBPF Build Job

**Runs**: `ubuntu-latest`

The job runs on every PR, but eBPF validation steps only run when files under `ebpf/` changed relative to the PR base. When eBPF changes are present, CI installs the nightly toolchain, builds `ferrum-ebpf`, runs `cargo test -p ferrum-ebpf-common`, and uploads the compiled `ebpf-programs` artifact with 14-day retention. When no eBPF files changed, the job no-ops and reports success.

#### 5. Performance Regression Job

**Runs**: `ubuntu-latest`

Builds the gateway in the `ci-release` profile, builds `tests/performance/backend_server`, starts both services, and runs:

```bash
python3 tests/performance/ci_overhead_bench.py \
  --concurrency 50 \
  --duration 5 \
  --iterations 3 \
  --warmup 2 \
  --overhead-threshold 50
```

**Failures**:
- Indicate performance regression issues
- Must be fixed before merging

#### 6. Cross-Platform Build Jobs

**Runs**: `ubuntu-latest`, `macos-latest`, `windows-latest`

Builds optimized release binaries for Linux x86_64, Linux ARM64, macOS x86_64, macOS ARM64, and Windows x86_64. These run on PRs and on pushes to `main`. All CI binary builds use `--features cloud-secrets` so Vault/AWS/Azure/GCP secret backends are included. The macOS x86_64 build uses the ARM64 `macos-latest` runner and targets `x86_64-apple-darwin`, so it is a cross-compile target.

#### 7. Latest Release and Docker Jobs

**Runs**: `ubuntu-latest`

On pushes to `main`, the `latest-release` job and Docker publishing jobs both depend on the completed build matrix and then run in parallel. A Docker failure on `main` does not block replacing the `latest` prerelease; version-tag releases are stricter and gate GitHub Release creation on `docker-manifest`. Docker Hub publishing requires the `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN` repository secrets. GHCR publishing uses `GITHUB_TOKEN` and the job-level `packages: write` permission. The Docker manifests publish both `latest` and `main-${{ github.sha }}` tags.

## Release Pipeline (release.yml)

The Release pipeline creates official releases when a version tag is pushed.

Release runs use `concurrency.group: release-${{ github.ref }}` with `cancel-in-progress: false`, so a versioned release is never canceled by a later tag push.

### Trigger

Push a tag matching the pattern `v*`:

```bash
# Create and push tag
git tag v0.2.0
git push origin v0.2.0
```

### Release Build Job

**Runs**: `ubuntu-latest`, `macos-latest`, `windows-latest` (matrix)

Builds optimized release binaries for all target platforms:

**Targets**:
- `x86_64-unknown-linux-gnu` - Linux x86_64
- `aarch64-unknown-linux-gnu` - Linux ARM64
- `x86_64-apple-darwin` - macOS x86_64
- `aarch64-apple-darwin` - macOS ARM64 (Apple Silicon)
- `x86_64-pc-windows-msvc` - Windows x86_64

**Build Process**:
1. Checkout code at tag commit
2. Install Rust toolchain with target
3. Install protobuf compiler
4. Build release binary in `--release` mode with `--features cloud-secrets`
5. Generate SHA256 checksum
6. Upload artifact

**Cross-Compilation**:
- Linux ARM64 uses `cross` tool for seamless compilation
- Other targets use standard `cargo build`; macOS x86_64 is cross-compiled on the ARM64 `macos-latest` runner.

**Output**:
- Binary: `ferrum-edge-{platform}`
- Checksum: `ferrum-edge-{platform}.sha256`

### Create Release Job

**Depends On**: Release Build Job and Docker Manifest Job

Creates a GitHub Release with all binaries and checksums only after the versioned Docker manifests have been pushed. A Docker Hub or GHCR manifest failure blocks GitHub Release creation.

**Release Content**:
1. Release title: Version tag (e.g., `v0.2.0`)
2. Release description: Generated release notes including:
   - List of binary platforms
   - SHA256 checksums for verification
   - Download instructions
3. Attachments: All platform-specific binaries

**Release Notes Example**:
```markdown
# Release v0.2.0

## Binaries

- ferrum-edge-linux-x86_64
- ferrum-edge-linux-aarch64
- ferrum-edge-macos-x86_64
- ferrum-edge-macos-aarch64
- ferrum-edge-windows-x86_64.exe

## Checksums

abc123... ferrum-edge-linux-x86_64
def456... ferrum-edge-linux-aarch64
...
```

## How Releases Work

### Version Management

**Current Version**: Defined in `Cargo.toml`

```toml
[package]
name = "ferrum-edge"
version = "<current-version>" # See Cargo.toml
```

**Release Process**:
1. Update `Cargo.toml` version before tagging
2. Tag: `git tag v<version>` (matching the new version)
3. Release: GitHub Actions automatically builds and publishes

### Version Numbering

Follow semantic versioning:

- **MAJOR.MINOR.PATCH** (e.g., `1.2.3`)
- **v** prefix for tags (e.g., `v1.2.3`)
- **Examples**:
  - `v0.1.0` - Initial release
  - `v0.2.0` - Minor feature addition
  - `v0.2.1` - Bug fix
  - `v1.0.0` - Major release

### Git Tag Naming

Always use `v` prefix and match `Cargo.toml` version:

```bash
# Correct
git tag v0.2.0   # matches Cargo.toml version = "0.2.0"

# Incorrect (won't trigger release)
git tag 0.2.0
git tag release-0.2.0
```

## Creating a New Release

### Prerequisites

- Modify `Cargo.toml` with new version
- All tests passing on `main` branch
- GitHub repo with Actions enabled
- Write permission to repository

### Step-by-Step

**1. Update Version in Cargo.toml**

```bash
# Edit Cargo.toml
cat > Cargo.toml << EOF
[package]
name = "ferrum-edge"
version = "0.2.0"
...
EOF
```

**2. Commit Changes**

```bash
git add Cargo.toml
git commit -m "chore: bump version to 0.2.0"
git push origin main
```

**3. Wait for CI to Pass**

- Push to main triggers CI pipeline
- The main-push build and publish jobs must pass; PR-only test, lint, eBPF, and performance gates should already have passed before merge
- Check GitHub Actions tab for status

**4. Create and Push Version Tag**

```bash
# Create tag pointing to HEAD
git tag -a v0.2.0 -m "Release version 0.2.0"

# Push tag to GitHub
git push origin v0.2.0
```

**5. Release Triggered Automatically**

- GitHub Actions detects tag matching `v*`
- Release pipeline starts automatically
- Binaries built for all platforms
- Release created with checksums

**6. Verify Release**

```bash
# GitHub CLI
gh release view v0.2.0

# Check binaries
gh release download v0.2.0 --dir ./binaries

# Verify checksums
sha256sum -c ferrum-edge-*.sha256
```

### Alternative: Manual Release Creation

If automatic release fails:

```bash
# Build binaries manually with the same release features as CI
cargo build --features cloud-secrets --release --target x86_64-unknown-linux-gnu
cargo build --features cloud-secrets --release --target aarch64-unknown-linux-gnu
cargo build --features cloud-secrets --release --target x86_64-apple-darwin
cargo build --features cloud-secrets --release --target aarch64-apple-darwin
cargo build --features cloud-secrets --release --target x86_64-pc-windows-msvc

# Generate checksums
find target \( -path '*/release/ferrum-edge' -o -path '*/release/ferrum-edge.exe' \) \
  -exec sha256sum {} \; > checksums.txt

# Create release in GitHub UI or via gh:
release_assets=$(find target \( -path '*/release/ferrum-edge' -o -path '*/release/ferrum-edge.exe' \))
gh release create v0.2.0 \
  $release_assets \
  checksums.txt \
  --title "Release v0.2.0" \
  --notes "$(cat release-notes.md)"
```

## Binaries and Downloads

### GitHub Releases Page

All released binaries available at:
```
https://github.com/ferrum-edge/ferrum-edge/releases
```

### Download Latest Release

```bash
# Using GitHub CLI
gh release download --repo ferrum-edge/ferrum-edge -p "*linux-x86_64"

# Using curl
RELEASE_URL=$(curl -s https://api.github.com/repos/ferrum-edge/ferrum-edge/releases/latest | \
  jq -r '.assets[] | select(.name == "ferrum-edge-linux-x86_64") | .browser_download_url')
curl -L -o ferrum-edge $RELEASE_URL
chmod +x ferrum-edge
```

### Platform-Specific Binaries

**Linux x86_64** (Intel/AMD 64-bit)
```bash
gh release download v0.2.0 -p "ferrum-edge-linux-x86_64"
chmod +x ferrum-edge-linux-x86_64
./ferrum-edge-linux-x86_64 run
```

**Linux ARM64** (ARM 64-bit, Graviton, etc.)
```bash
gh release download v0.2.0 -p "ferrum-edge-linux-aarch64"
chmod +x ferrum-edge-linux-aarch64
./ferrum-edge-linux-aarch64 run
```

**macOS x86_64** (Intel Macs)
```bash
gh release download v0.2.0 -p "ferrum-edge-macos-x86_64"
chmod +x ferrum-edge-macos-x86_64
./ferrum-edge-macos-x86_64 run
```

**macOS ARM64** (Apple Silicon M1/M2/M3)
```bash
gh release download v0.2.0 -p "ferrum-edge-macos-aarch64"
chmod +x ferrum-edge-macos-aarch64
./ferrum-edge-macos-aarch64 run
```

### Checksum Verification

Always verify binary integrity using SHA256:

```bash
# Download release files
gh release download v0.2.0

# Verify checksums
sha256sum -c *.sha256

# Expected output:
# ferrum-edge-linux-x86_64: OK
# ferrum-edge-linux-aarch64: OK
# ferrum-edge-macos-x86_64: OK
# ferrum-edge-macos-aarch64: OK
# ferrum-edge-windows-x86_64.exe: OK
```

### Docker Images

Pre-built Docker images are published to Docker Hub and GitHub Container Registry by the main-push and version-tag workflows. Docker Hub credentials must be configured before those publish workflows run:

```bash
docker pull ferrumedge/ferrum-edge:latest
docker pull ferrumedge/ferrum-edge:main-<git-sha>
docker pull ferrumedge/ferrum-edge:v1.2.3
docker pull ferrumedge/ferrum-edge:1.2.3
docker pull ferrumedge/ferrum-edge:1.2

docker pull ghcr.io/ferrum-edge/ferrum-edge:latest
docker pull ghcr.io/ferrum-edge/ferrum-edge:main-<git-sha>
docker pull ghcr.io/ferrum-edge/ferrum-edge:v1.2.3
docker pull ghcr.io/ferrum-edge/ferrum-edge:1.2.3
docker pull ghcr.io/ferrum-edge/ferrum-edge:1.2
```

The GHCR path is `ghcr.io/${{ github.repository }}` in the workflows, so it tracks the GitHub repository owner/name if the repository is moved or forked.

## GitHub Actions Secrets

Configure secrets for Docker image publishing and releases.

### Accessing Secrets Settings

1. Go to GitHub repository
2. Settings → Secrets and variables → Actions
3. Create new repository secrets

### Required Secrets

#### Docker Registry

Required for pushing Docker Hub images. The workflows unconditionally run the Docker Hub login step on main-push and version-tag Docker jobs, so missing secrets fail publishing:

- `DOCKERHUB_USERNAME` - Docker Hub username
- `DOCKERHUB_TOKEN` - Docker Hub access token

**Generate Docker Token**:
1. Log in to Docker Hub
2. Account Settings → Security
3. Create new access token
4. Copy token to `DOCKERHUB_TOKEN`

For GHCR publishing, the workflows use `GITHUB_TOKEN`. The workflows declare job-level `permissions: { contents: write }` for release creation and `permissions: { contents: read, packages: write }` for Docker/GHCR publishing. No repository-wide permission broadening is required as long as the default `GITHUB_TOKEN` permissions allow those per-job grants.

### Secret Usage in Workflows

The Docker Hub login steps use:

```yaml
with:
  username: ${{ secrets.DOCKERHUB_USERNAME }}
  password: ${{ secrets.DOCKERHUB_TOKEN }}
```

### Setting Secrets

```bash
# Using GitHub CLI
gh secret set DOCKERHUB_USERNAME --body "your-username"
gh secret set DOCKERHUB_TOKEN --body "your-token"

# Via web UI
1. Settings → Secrets → New repository secret
2. Name: DOCKERHUB_USERNAME
3. Value: your-username
4. Click "Add secret"
```

## Customizing CI/CD

### Adding New Targets

Edit `.github/workflows/release.yml`:

```yaml
strategy:
  matrix:
    include:
      # Example: add a Linux musl target
      - os: ubuntu-latest
        target: x86_64-unknown-linux-musl
        artifact_name: ferrum-edge
        asset_name: ferrum-edge-linux-x86_64-musl
```

### Skipping Steps

Skip specific jobs per commit:

```bash
# Skip CI for documentation changes
git commit -m "docs: update README [skip ci]"

# Automatically skips test/lint/build jobs
```

### Custom Build Flags

Modify build commands in workflows:

```yaml
- name: Build with custom features
  run: cargo build --release --features "vendored-openssl"
```

### Notification Integration

Add notifications to CI failures:

```yaml
- name: Notify Slack
  if: failure()
  uses: slackapi/slack-github-action@v1
  with:
    webhook-url: ${{ secrets.SLACK_WEBHOOK }}
```

## Troubleshooting

### Release Not Triggering

**Check**:
- Tag format: Must be `v*` (e.g., `v0.2.0`)
- Tag exists: `git tag` lists tags
- Push origin: `git push origin v0.2.0`

```bash
# Verify tag
git tag -l "v*"
git show v0.2.0

# Check GitHub Actions
# Settings → Actions → All workflows
```

### Build Failures

**Check logs**:
1. Go to GitHub Actions tab
2. Click failing workflow
3. Expand job logs for details

**Common Issues**:
- `protoc` not installed: Fixed in CI (installs protoc)
- Missing dependencies: Check `Cargo.toml`
- Rust version: Workflows use `stable` Rust toolchain

### Docker Push Failing

**Verify secrets**:
```bash
gh secret list
# Should show DOCKERHUB_USERNAME and DOCKERHUB_TOKEN
```

**Test credentials**:
```bash
# Local login test
docker login -u $USERNAME -p $PASSWORD

# Update secrets if needed
gh secret set DOCKERHUB_TOKEN --body "new-token"
```

## See Also

- [Docker Deployment](docker.md) - Building and running Docker images
- [Main README](../README.md) - Project overview and configuration
- [GitHub Actions Documentation](https://docs.github.com/en/actions)
