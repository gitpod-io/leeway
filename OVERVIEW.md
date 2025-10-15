# Leeway

## Overview
**Developer**: Gitpod | **Release**: 2020 | **Version**: v0.10.5 | **Access**: Open Source (Apache 2.0)

## Capabilities
- **Strengths**: Source-dependent versioning, Two-level caching (local + remote GCS), Parallel dependency-aware builds
- **Best For**: Monorepo build orchestration, Multi-language projects (Go/Yarn/Docker), CI/CD pipelines with shared build caches
- **Build Types**: Go packages, Yarn/TypeScript packages, Docker images, Generic shell commands

## Quick Start
```bash
# Install leeway
wget https://github.com/gitpod-io/leeway/releases/latest/download/leeway-linux-amd64
chmod +x leeway-linux-amd64 && mv leeway-linux-amd64 /usr/local/bin/leeway

# Initialize workspace
touch WORKSPACE.yaml
export LEEWAY_WORKSPACE_ROOT=$PWD

# Create a component with packages
cat > BUILD.yaml <<EOF
packages:
- name: my-app
  type: go
  srcs:
  - "**/*.go"
  config:
    packaging: app
EOF

# Build a package
leeway build some/component:package

# Collect all packages in workspace
leeway collect
```

## Performance
| Feature | Capability |
|---------|-----------|
| Caching | Local + Remote (GCS/S3) |
| Parallelism | Automatic based on dependency graph |
| Version Computation | Content-addressable (sources + deps + config) |
| SBOM Generation | Built-in with Syft (CycloneDX, SPDX) |
| Vulnerability Scanning | Integrated Grype scanning |

## Variants
- **Package Types**: Go (library/app), Yarn (library/app), Docker (multi-stage builds), Generic (shell commands)
- **Build Variants**: Workspace-level variants for conditional builds (modify sources, env vars, config)
- **Scripts**: Development automation with package dependencies

## Limitations
- Linux/macOS only (Windows not supported)
- Requires external tools (go, yarn, docker) to be pre-installed
- Remote cache requires GCS or S3 bucket configuration
- Build arguments are string-only (no complex types)
- Environment manifest must match across build environments

## Resources
- [Documentation](https://github.com/gitpod-io/leeway/blob/main/README.md)
- [Releases](https://github.com/gitpod-io/leeway/releases)
- [Repository](https://github.com/gitpod-io/leeway)
- [Issues](https://github.com/gitpod-io/leeway/issues)

## Pricing
Free and open source (Apache 2.0 License). Remote caching requires your own GCS bucket or S3 storage (standard cloud storage costs apply).

---
*Updated: 2025-01-15*
