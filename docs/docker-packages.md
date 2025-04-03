# Docker Packages in Leeway

This document explains how Docker packages work in Leeway, including configuration options, build process, dependency handling, and advanced features.

## Introduction

Docker packages in Leeway allow you to build, package, and optionally push Docker images as part of your build process. Leeway provides a consistent way to define Docker packages alongside other package types (Go, Yarn, Generic) and handles dependencies between them automatically.

Docker packages can operate in two modes:
- **Push mode**: Build and push images to registries
- **Extract mode**: Build and extract the image filesystem content

## Configuration

Docker packages are defined in a component's `BUILD.yaml` file. Here's a basic example:

```yaml
packages:
- name: my-docker-image
  type: docker
  srcs:
  - "**/*.go"
  - "go.mod"
  - "go.sum"
  - "Dockerfile"
  deps:
  - :go-app  # Dependency on another package
  config:
    dockerfile: Dockerfile
    image:
    - example/myapp:latest
    - example/myapp:${__pkg_version}
    buildArgs:
      GO_VERSION: "1.18"
    metadata:
      description: "My Docker application"
      version: "1.0.0"
```

### Configuration Options

The `config` section of a Docker package supports the following fields:

| Field | Type | Description |
|-------|------|-------------|
| `dockerfile` | string | Path to the Dockerfile relative to the component root. Defaults to `Dockerfile` if not specified. |
| `image` | []string | List of image tags to push to. If empty, the image will be built but not pushed. |
| `buildArgs` | map[string]string | Build arguments passed to `docker build` using `--build-arg`. |
| `squash` | bool | If true, adds the `--squash` flag to `docker build`. |
| `metadata` | map[string]string | Metadata included in the build output. |

### Build Arguments

Build arguments can include:
- Static values: `GO_VERSION: "1.18"`
- Leeway build arguments: `VERSION: ${version}`
- Built-in variables:
  - `${__pkg_version}`: The package version hash
  - `${__git_commit}`: The current Git commit
  - `${__git_commit_short}`: The shortened Git commit (first 7 characters)

## Build Process

When Leeway builds a Docker package, it follows these steps:

### 1. Preparation Phase

- Copies the Dockerfile to the build directory
- Extracts dependencies into the build directory
- Sets up build arguments for dependencies

### 2. Build Phase

- Runs `docker build` with appropriate arguments
- Tags the image with a version derived from the package's content hash

### 3. Packaging Phase

Depending on whether `image` tags are specified:

#### Push Mode (with `image` tags)

If `image` tags are specified:
- Tags the image with each specified tag
- Pushes the image to the specified registries
- Creates a minimal archive containing:
  - `imgnames.txt`: List of pushed image names
  - `metadata.yaml`: Package metadata

#### Extract Mode (without `image` tags)

If no `image` tags are specified:
- Extracts the image filesystem using OCI libraries
- Creates a directory structure with:
  - `content/`: The extracted filesystem
  - `imgnames.txt`: The local image name
  - `metadata.yaml`: Package metadata
  - `image-metadata.json`: Detailed image information
- Packages everything into a tar archive

## Dependency Handling

Docker packages can depend on other packages, including other Docker packages.

### Using Dependencies

Dependencies are extracted into the build directory and can be referenced in your Dockerfile:

```dockerfile
# Copy files from a dependency
COPY go-app/ /app/
```

### Docker Dependencies

When a Docker package depends on another Docker package, Leeway automatically creates a build argument that can be used in the Dockerfile:

```dockerfile
# Use a Docker dependency as a base image
FROM ${DEP_COMPONENT_NESTED__DOCKER}
```

The build argument name is derived from the dependency's package name by:
- Replacing `/` with `_`
- Replacing `:` with `__`
- Converting to uppercase

For example, a dependency on `component/nested:docker` becomes `${DEP_COMPONENT_NESTED__DOCKER}`.

## Examples

### Basic Docker Package

```yaml
packages:
- name: simple-app
  type: docker
  srcs:
  - "Dockerfile"
  - "app/**/*.go"
  config:
    dockerfile: Dockerfile
    image:
    - example/simple-app:latest
```

### Docker Package with Dependencies

```yaml
packages:
- name: base-image
  type: docker
  srcs:
  - "base.Dockerfile"
  config:
    dockerfile: base.Dockerfile
    image:
    - example/base:latest

- name: app-image
  type: docker
  srcs:
  - "app.Dockerfile"
  - "app/**/*"
  deps:
  - :base-image
  config:
    dockerfile: app.Dockerfile
    image:
    - example/app:latest
    buildArgs:
      VERSION: "1.0.0"
```

In `app.Dockerfile`, you can reference the base image:

```dockerfile
FROM ${DEP_BASE_IMAGE}

COPY app/ /app/
# ...
```

### Multi-stage Build with Go Dependency

```yaml
packages:
- name: go-app
  type: go
  srcs:
  - "**/*.go"
  - "go.mod"
  - "go.sum"
  config:
    packaging: app

- name: docker-image
  type: docker
  srcs:
  - "Dockerfile"
  deps:
  - :go-app
  config:
    dockerfile: Dockerfile
    image:
    - example/app:latest
```

In `Dockerfile`:

```dockerfile
FROM golang:1.18 AS builder
COPY go-app/ /app/
WORKDIR /app
RUN go build -o /bin/app

FROM alpine:3.15
COPY --from=builder /bin/app /bin/app
ENTRYPOINT ["/bin/app"]
```

## Advanced Features

### Metadata

The `metadata` field allows you to include arbitrary key-value pairs in the build output:

```yaml
config:
  metadata:
    description: "My application"
    version: "1.0.0"
    maintainer: "team@example.com"
```

This metadata is stored in `metadata.yaml` in the build output and can be used by downstream tools.

### SBOM and Provenance

When enabled in the workspace configuration, Leeway can generate Software Bill of Materials (SBOM) and provenance information for Docker packages:

```yaml
# In WORKSPACE.yaml
sbom:
  enabled: true
  scanVulnerabilities: true

provenance:
  enabled: true
  slsa: true
```

This adds:
- SBOM files in multiple formats (CycloneDX, SPDX, Syft JSON)
- Vulnerability scan results (if enabled)
- SLSA provenance attestation

### Docker Build Options

You can pass additional options to `docker build` using the `--docker-build-options` flag:

```bash
leeway build --docker-build-options="platform=linux/amd64,network=host" component:docker-package
```

## Implementation Details

The Docker package implementation is spread across several files in the Leeway codebase:

- `pkg/leeway/package.go`: Contains the `DockerPkgConfig` struct
- `pkg/leeway/build.go`: Implements the `buildDocker` function
- `pkg/leeway/container_image.go`: Handles Docker image extraction

## Troubleshooting

### Common Issues

1. **Image push fails**: Ensure you're logged in to the Docker registry (`docker login`)
2. **Dependency not found**: Check that the dependency is correctly specified and built
3. **Build arguments not resolved**: Ensure build arguments are correctly defined and passed

### Debugging

Use the `--werft` flag for more detailed build output:

```bash
leeway build --werft component:docker-package
```

For even more detailed output, use the debug log level:

```bash
LEEWAY_LOG_LEVEL=debug leeway build component:docker-package
