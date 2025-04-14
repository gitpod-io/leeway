# Tech Context

*   **Technologies Used:**
    *   Primary Language: Go
    *   Build Targets: Go, Yarn (Node.js), Docker
    *   Configuration: YAML (`WORKSPACE.yaml`, `BUILD.yaml`)
    *   Scripting: Bash (for `scripts`), JavaScript ES5.1 (via Goja for `BUILD.js`)
    *   Provenance: SLSA v0.2, in-toto attestation bundles (JSONL)
*   **Development Setup:**
    *   OS: Linux or macOS required.
    *   Installation: Download pre-built release binaries.
    *   Environment Variables: `LEEWAY_WORKSPACE_ROOT` (required), `LEEWAY_REMOTE_CACHE_STORAGE`, `LEEWAY_REMOTE_CACHE_BUCKET`, `LEEWAY_CACHE_DIR`, `LEEWAY_BUILD_DIR`, `LEEWAY_YARN_MUTEX`, `LEEWAY_PROVENANCE_KEYPATH`, `LEEWAY_EXPERIMENTAL`.
    *   macOS Specific: Requires GNU `coreutils` (`brew install coreutils`).
    *   Tooling: Assumes Go, Yarn, Docker, and cloud CLIs (gsutil/aws) are installed and configured.
*   **Technical Constraints:**
    *   Windows is not supported.
    *   Relies on external tools being present in the environment.
    *   Provenance bundle size can impact memory usage (`LEEWAY_MAX_PROVENANCE_BUNDLE_SIZE`).
*   **Dependencies:**
    *   Go: Managed via Go Modules (`go.mod`, `go.sum`).
    *   Yarn: Managed via `yarn.lock`.
    *   Remote Cache: Google Cloud Storage (GCS) or AWS S3. Requires respective CLI tools (`gsutil`, `aws`).
    *   Linting (Go): `golangci-lint` (default).
*   **Tool Usage Patterns:**
    *   Configuration: Centralized in `WORKSPACE.yaml` (workspace settings, defaults, variants, env manifest) and `BUILD.yaml` (component constants, packages, scripts). Dynamic config via `BUILD.js`. Overrides via `WORKSPACE.args.yaml`.
    *   Build Commands: Uses standard tool commands (`go build/test/fmt/generate`, `yarn install/build/test`, `docker build`). Allows command overrides in package configs.
    *   CLI: `leeway` command is the main entry point for building (`build`), inspecting (`collect`, `describe`), running scripts (`run`), managing provenance (`provenance`), etc.
    *   GitHub Actions Integration: The `--report-github` flag (automatically enabled when `GITHUB_OUTPUT` env var is present) writes build success/failure status to GitHub Actions outputs. Uses the format `{pkg.FilesystemSafeName()}={success}`, where `FilesystemSafeName()` converts component:package format to component--package (e.g., `backend:docker` becomes `backend--docker`). Currently only reports boolean success/failure values.
    *   Releasing: Uses GoReleaser triggered by Git tags via GitHub Actions.
