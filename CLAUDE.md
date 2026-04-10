# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## About Leeway

Leeway is a heavily caching meta-build system for Go, Yarn (Node.js), and Docker projects. It accelerates build times through intelligent dependency-aware caching and parallel execution.

## Development Commands

### Building
```bash
# Build the leeway binary
go build .

# Build with version info (for releases)
go build -ldflags "-X github.com/gitpod-io/leeway/pkg/leeway.Version=dev-$(git rev-parse --short HEAD)" .

# Build using leeway itself (self-hosted build)
./leeway build //:app
```

### Testing
```bash
# Run all tests
go test ./...

# Run tests with verbose output
go test -v ./...

# Run specific test package
go test ./pkg/leeway/...

# Run specific test
go test -run TestBuildDockerDeps ./pkg/leeway/

# Run tests with build tags for integration tests
go test -tags integration ./...
```

### Linting
```bash
# Run golangci-lint (if configured)
golangci-lint run

# Format code
go fmt ./...

# Vet code
go vet ./...
```

## Architecture Overview

### Core Concepts Hierarchy
1. **Workspace** (`WORKSPACE.yaml`) - Root configuration defining build environment
2. **Components** (`BUILD.yaml`) - Individual software modules within the workspace  
3. **Packages** - Buildable units within components, referenced as `component:package`

### Key Architectural Patterns

**Build System Core** (`pkg/leeway/build.go`):
- Main build orchestration with dependency resolution
- Package-type-specific build strategies (Go, Yarn, Docker, Generic)
- Parallel execution with `errgroup` coordination
- Build phases: prep → pull → lint → test → build → package

**Workspace Management** (`pkg/leeway/workspace.go`):
- Component discovery and loading
- Package linking and dependency resolution
- Environment manifest computation
- Variant support for conditional builds

**Caching Strategy** (`pkg/leeway/cache/`):
- Content-addressable versioning
- Local and remote cache implementations (S3, GCS)
- Package dependency-aware cache invalidation

**Configuration System**:
- YAML-based declarative configuration
- Build argument substitution with `${var}` syntax
- Package variants for conditional source/config inclusion
- Dynamic package generation via JavaScript (`BUILD.js`)

### Package Types and Build Strategies

**Go Packages**:
- Module-aware builds with `go.mod` support
- Workspace mode for multi-module repositories
- Dependency extraction to `_deps/` directory
- Test coverage collection and reporting

**Yarn Packages**:
- Offline mirror support for reproducible builds
- Library vs Application packaging modes
- yarn.lock management for dependency resolution
- TypeScript compilation support

**Docker Packages**:
- Multi-stage builds with dependency injection
- Image extraction for non-pushed containers
- Build argument propagation (`DEP_COMPONENT__PACKAGE`)
- Metadata and provenance embedding

**Generic Packages**:
- Arbitrary command execution
- Dependency layout in build directory
- Flexible packaging with tar compression

### Testing Architecture

The test suite uses fixture-based integration testing with `pkg/testutil`:
- `CommandFixtureTest` for end-to-end CLI testing
- Workspace setup with programmatic package definitions
- Mock implementations for external dependencies (Docker, etc.)
- Output validation through substring matching and custom eval functions

### Version Computation

Package versions are computed from:
- Package definition hash (BUILD.yaml content)
- Source file content hashes
- Transitive dependency versions
- Environment manifest (tool versions)
- Build process version constants

Arguments passed via `-D` flags do NOT affect versions unless declared in `argdeps`.

## Working with the Codebase

### Adding New Package Types
1. Define config struct implementing `PackageConfig` interface
2. Add build method `buildXXX()` in `build.go` following existing patterns
3. Update package type constants and switch statements
4. Add tests in `build_test.go` with fixture setup

### Modifying Build Process
- Increment `buildProcessVersions` constant when changing build logic
- Update phase execution in `executeBuildPhase()` 
- Consider cache invalidation implications

### Cache Implementation
- Implement `cache.LocalCache` or `cache.RemoteCache` interfaces
- Handle package serialization/deserialization
- Ensure atomic operations for cache consistency

### CLI Commands
Add new commands in `cmd/` directory following Cobra patterns. Use `getWorkspace()` helper for workspace loading and `applyBuildOpts()` for consistent build option handling.