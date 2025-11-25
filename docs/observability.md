# Observability

Leeway supports distributed tracing using OpenTelemetry to provide visibility into build performance and behavior.

## Overview

OpenTelemetry tracing in leeway captures:
- Build lifecycle (start to finish)
- Individual package builds
- Build phase durations (prep, pull, lint, test, build, package)
- Cache hit/miss information
- GitHub Actions context (when running in CI)
- Parent trace context propagation from CI systems

## Architecture

### Span Hierarchy

```
Root Span (leeway.build)
├── Package Span 1 (leeway.package)
│   ├── Phase Span (leeway.phase: prep)
│   ├── Phase Span (leeway.phase: pull)
│   ├── Phase Span (leeway.phase: lint)
│   ├── Phase Span (leeway.phase: test)
│   ├── Phase Span (leeway.phase: build)
│   └── Phase Span (leeway.phase: package)
├── Package Span 2 (leeway.package)
│   ├── Phase Span (leeway.phase: prep)
│   └── Phase Span (leeway.phase: build)
└── Package Span N (leeway.package)
    └── ...
```

- **Root Span**: Created when `BuildStarted` is called, represents the entire build operation
- **Package Spans**: Created for each package being built, as children of the root span
- **Phase Spans**: Created for each build phase (prep, pull, lint, test, build, package) as children of package spans

Phase spans provide detailed timeline visualization and capture individual phase errors. Only phases with commands are executed and create spans.

### Context Propagation

Leeway supports W3C Trace Context propagation, allowing builds to be part of larger distributed traces:

1. **Parent Context**: Accepts `traceparent` and `tracestate` headers from upstream systems
2. **Root Context**: Creates a root span linked to the parent context
3. **Package Context**: Each package span is a child of the root span
4. **Phase Context**: Each phase span is a child of its package span

## Configuration

### Environment Variables

- `OTEL_EXPORTER_OTLP_ENDPOINT`: OTLP endpoint URL (e.g., `localhost:4318` or `api.honeycomb.io:443`)
- `OTEL_EXPORTER_OTLP_INSECURE`: Disable TLS for OTLP endpoint (`true` or `false`, default: `false`)
- `OTEL_EXPORTER_OTLP_HEADERS`: HTTP headers for OTLP requests (e.g., `x-honeycomb-team=YOUR_API_KEY`)
- `OTEL_EXPORTER_OTLP_TRACES_HEADERS`: Trace-specific headers (takes precedence over `OTEL_EXPORTER_OTLP_HEADERS`)
- `TRACEPARENT`: W3C Trace Context traceparent header (format: `00-{trace-id}-{span-id}-{flags}`)
- `TRACESTATE`: W3C Trace Context tracestate header (optional)

**Note:** The OpenTelemetry SDK automatically reads `OTEL_EXPORTER_OTLP_HEADERS` and `OTEL_EXPORTER_OTLP_TRACES_HEADERS` from the environment. No additional configuration is required.

### CLI Flags

- `--otel-endpoint`: OTLP endpoint URL (overrides `OTEL_EXPORTER_OTLP_ENDPOINT`)
- `--otel-insecure`: Disable TLS for OTLP endpoint (overrides `OTEL_EXPORTER_OTLP_INSECURE`)
- `--trace-parent`: W3C traceparent header (overrides `TRACEPARENT`)
- `--trace-state`: W3C tracestate header (overrides `TRACESTATE`)

### Precedence

CLI flags take precedence over environment variables:
```
CLI flag → Environment variable → Default (disabled)
```

### TLS Configuration

By default, leeway uses **secure TLS connections** to the OTLP endpoint. For local development with tools like Jaeger, you can disable TLS:

```bash
# Local development (insecure)
export OTEL_EXPORTER_OTLP_INSECURE=true
export OTEL_EXPORTER_OTLP_ENDPOINT=localhost:4318
leeway build :my-package

# Production (secure, default)
export OTEL_EXPORTER_OTLP_ENDPOINT=api.honeycomb.io:443
export OTEL_EXPORTER_OTLP_HEADERS="x-honeycomb-team=YOUR_API_KEY"
leeway build :my-package
```

## Span Attributes

### Root Span Attributes

| Attribute | Type | Description | Example |
|-----------|------|-------------|---------|
| `leeway.version` | string | Leeway version | `"0.7.0"` |
| `leeway.workspace.root` | string | Workspace root path | `"/workspace"` |
| `leeway.target.package` | string | Target package being built | `"components/server:app"` |
| `leeway.target.version` | string | Target package version | `"abc123def"` |
| `leeway.packages.total` | int | Total packages in build | `42` |
| `leeway.packages.cached` | int | Packages cached locally | `35` |
| `leeway.packages.remote` | int | Packages in remote cache | `5` |
| `leeway.packages.downloaded` | int | Packages downloaded | `3` |
| `leeway.packages.to_build` | int | Packages to build | `2` |

### Package Span Attributes

| Attribute | Type | Description | Example |
|-----------|------|-------------|---------|
| `leeway.package.name` | string | Package full name | `"components/server:app"` |
| `leeway.package.type` | string | Package type | `"go"`, `"yarn"`, `"docker"`, `"generic"` |
| `leeway.package.version` | string | Package version | `"abc123def"` |
| `leeway.package.builddir` | string | Build directory | `"/tmp/leeway/build/..."` |
| `leeway.package.last_phase` | string | Last completed phase | `"build"` |
| `leeway.package.duration_ms` | int64 | Total build duration (ms) | `15234` |
| `leeway.package.test.coverage_percentage` | int | Test coverage % | `85` |
| `leeway.package.test.functions_with_test` | int | Functions with tests | `42` |
| `leeway.package.test.functions_without_test` | int | Functions without tests | `8` |

### Phase Span Attributes

Phase spans are created for each build phase (prep, pull, lint, test, build, package) that has commands to execute.

| Attribute | Type | Description | Example |
|-----------|------|-------------|---------|
| `leeway.phase.name` | string | Phase name | `"prep"`, `"build"`, `"test"`, etc. |

**Span Status:**
- `OK`: Phase completed successfully
- `ERROR`: Phase failed (error details in span events)

**Span Duration:** The span's start and end times capture the phase execution duration automatically.

### GitHub Actions Attributes

When running in GitHub Actions (`GITHUB_ACTIONS=true`), the following attributes are added to the root span:

| Attribute | Environment Variable | Description |
|-----------|---------------------|-------------|
| `github.workflow` | `GITHUB_WORKFLOW` | Workflow name |
| `github.run_id` | `GITHUB_RUN_ID` | Unique run identifier |
| `github.run_number` | `GITHUB_RUN_NUMBER` | Run number |
| `github.job` | `GITHUB_JOB` | Job name |
| `github.actor` | `GITHUB_ACTOR` | User who triggered the workflow |
| `github.repository` | `GITHUB_REPOSITORY` | Repository name |
| `github.ref` | `GITHUB_REF` | Git ref |
| `github.sha` | `GITHUB_SHA` | Commit SHA |
| `github.server_url` | `GITHUB_SERVER_URL` | GitHub server URL |
| `github.workflow_ref` | `GITHUB_WORKFLOW_REF` | Workflow reference |

## Usage Examples

### Basic Usage

```bash
# Set OTLP endpoint
export OTEL_EXPORTER_OTLP_ENDPOINT=localhost:4318

# Build with tracing enabled
leeway build :my-package
```

### With CLI Flags

```bash
leeway build :my-package \
  --otel-endpoint=localhost:4318
```

### With Parent Trace Context

```bash
# Propagate trace context from CI system
leeway build :my-package \
  --otel-endpoint=localhost:4318 \
  --trace-parent="00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
```

### In GitHub Actions

```yaml
name: Build
on: [push]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Build with tracing
        env:
          OTEL_EXPORTER_OTLP_ENDPOINT: ${{ secrets.OTEL_ENDPOINT }}
        run: |
          leeway build :my-package
```

### With Jaeger (Local Development)

```bash
# Start Jaeger all-in-one
docker run -d --name jaeger \
  -p 4318:4318 \
  -p 16686:16686 \
  jaegertracing/all-in-one:latest

# Build with tracing (insecure for local development)
export OTEL_EXPORTER_OTLP_ENDPOINT=localhost:4318
export OTEL_EXPORTER_OTLP_INSECURE=true
leeway build :my-package

# View traces at http://localhost:16686
```

### With Honeycomb (Production)

```bash
# Configure Honeycomb endpoint with API key
export OTEL_EXPORTER_OTLP_ENDPOINT=api.honeycomb.io:443
export OTEL_EXPORTER_OTLP_HEADERS="x-honeycomb-team=YOUR_API_KEY"

# Build with tracing (secure by default)
leeway build :my-package

# View traces in Honeycomb UI
```

### In CI/CD with Distributed Tracing

```bash
# Propagate trace context from parent CI system
export OTEL_EXPORTER_OTLP_ENDPOINT=api.honeycomb.io:443
export OTEL_EXPORTER_OTLP_HEADERS="x-honeycomb-team=YOUR_API_KEY"
export TRACEPARENT="00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"

leeway build :my-package
```

## Error Handling

Leeway implements graceful degradation for tracing:

- **Tracer initialization failures**: Logged as warnings, build continues without tracing
- **Span creation failures**: Logged as warnings, build continues
- **OTLP endpoint unavailable**: Spans are buffered and flushed on shutdown (with timeout)
- **Invalid trace context**: Logged as warning, new trace is started

Tracing failures never cause build failures.

## Performance Considerations

- **Overhead**: Minimal (<1% in typical builds)
- **Concurrent builds**: Thread-safe with RWMutex protection
- **Shutdown timeout**: 5 seconds to flush pending spans
- **Batch export**: Spans are batched for efficient export

## Troubleshooting

### No spans appearing in backend

1. Verify OTLP endpoint is reachable:
   ```bash
   curl -v http://localhost:4318/v1/traces
   ```

2. Check leeway logs for warnings:
   ```bash
   leeway build :package 2>&1 | grep -i otel
   ```

3. Verify environment variables:
   ```bash
   echo $OTEL_EXPORTER_OTLP_ENDPOINT
   ```

### Invalid trace context errors

Validate traceparent format:
```
Format: 00-{32-hex-trace-id}-{16-hex-span-id}-{2-hex-flags}
Example: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01
```

### Spans not linked to parent

Ensure both `traceparent` and `tracestate` (if present) are provided:
```bash
leeway build :package \
  --trace-parent="00-..." \
  --trace-state="..."
```

## Implementation Details

### Thread Safety

- Single `sync.RWMutex` protects `packageCtxs` and `packageSpans` maps
- Safe for concurrent package builds
- Read locks for lookups, write locks for modifications

### Shutdown

- Automatic shutdown with 5-second timeout
- Registered as deferred function in `getBuildOpts`
- Ensures all spans are flushed before exit

### Testing

Tests use in-memory exporters (`tracetest.NewInMemoryExporter()`) to verify:
- Span creation and hierarchy
- Attribute correctness
- Concurrent package builds
- Parent context propagation
- Graceful degradation with nil tracer

## Future Enhancements

Potential improvements for future iterations:

- **Phase-level spans**: Create individual spans for each build phase (prep, pull, lint, test, build, package) instead of just attributes
- **Span events**: Add timeline events for build milestones (e.g., cache hit, dependency resolution)
- **Metrics integration**: Export metrics alongside traces (build duration histograms, cache hit rates, concurrent build count)
- **Sampling configuration**: Add configurable sampling strategies for high-volume builds
- **Additional exporters**: Support for Zipkin, Jaeger native protocol, or Prometheus
