package telemetry

import (
	"context"
	"os"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/xerrors"
)

// InitTracer initializes the OpenTelemetry tracer with OTLP HTTP exporter.
// The endpoint parameter specifies the OTLP endpoint URL (e.g., "localhost:4318").
// Returns the TracerProvider which must be shut down when done.
func InitTracer(ctx context.Context, endpoint string) (*sdktrace.TracerProvider, error) {
	if endpoint == "" {
		return nil, xerrors.Errorf("OTLP endpoint not provided")
	}

	// Create OTLP HTTP exporter
	exporter, err := otlptracehttp.New(ctx,
		otlptracehttp.WithEndpoint(endpoint),
		otlptracehttp.WithInsecure(), // Use insecure for local development; configure TLS in production
	)
	if err != nil {
		return nil, xerrors.Errorf("failed to create OTLP exporter: %w", err)
	}

	// Create resource with service information
	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceNameKey.String("leeway"),
			semconv.ServiceVersionKey.String(getLeewayVersion()),
		),
	)
	if err != nil {
		return nil, xerrors.Errorf("failed to create resource: %w", err)
	}

	// Create tracer provider
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
	)

	// Set global tracer provider
	otel.SetTracerProvider(tp)

	// Set global propagator for W3C Trace Context
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	return tp, nil
}

// Shutdown flushes any pending spans and shuts down the tracer provider.
// It uses a timeout context to ensure shutdown completes within a reasonable time.
func Shutdown(ctx context.Context, tp *sdktrace.TracerProvider) error {
	if tp == nil {
		return nil
	}

	// Create a timeout context for shutdown
	shutdownCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if err := tp.Shutdown(shutdownCtx); err != nil {
		return xerrors.Errorf("failed to shutdown tracer provider: %w", err)
	}

	return nil
}

// ParseTraceContext parses W3C Trace Context headers (traceparent and tracestate)
// and returns a context with the extracted trace information.
// Format: traceparent = "00-{trace-id}-{span-id}-{flags}"
func ParseTraceContext(traceparent, tracestate string) (context.Context, error) {
	if traceparent == "" {
		return context.Background(), nil
	}

	// Create a carrier with the trace context headers
	carrier := propagation.MapCarrier{
		"traceparent": traceparent,
	}
	if tracestate != "" {
		carrier["tracestate"] = tracestate
	}

	// Extract the trace context using W3C Trace Context propagator
	ctx := context.Background()
	propagator := propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	)
	ctx = propagator.Extract(ctx, carrier)

	// Verify that we extracted a valid span context
	spanCtx := trace.SpanContextFromContext(ctx)
	if !spanCtx.IsValid() {
		return nil, xerrors.Errorf("invalid trace context: traceparent=%s", traceparent)
	}

	return ctx, nil
}

// getLeewayVersion returns the leeway version for telemetry.
// This is a placeholder that should be replaced with actual version retrieval.
func getLeewayVersion() string {
	// This will be imported from the leeway package
	version := os.Getenv("LEEWAY_VERSION")
	if version == "" {
		version = "unknown"
	}
	return version
}

// FormatTraceContext formats a span context into W3C Trace Context format.
// This is useful for propagating trace context to child processes.
func FormatTraceContext(spanCtx trace.SpanContext) (traceparent, tracestate string) {
	if !spanCtx.IsValid() {
		return "", ""
	}

	// Use the propagator to format the trace context properly
	carrier := propagation.MapCarrier{}
	propagator := propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	)
	ctx := trace.ContextWithSpanContext(context.Background(), spanCtx)
	propagator.Inject(ctx, carrier)

	traceparent = carrier.Get("traceparent")
	tracestate = carrier.Get("tracestate")

	return traceparent, tracestate
}

// ValidateTraceParent validates the format of a traceparent header.
func ValidateTraceParent(traceparent string) error {
	if traceparent == "" {
		return nil
	}

	parts := strings.Split(traceparent, "-")
	if len(parts) != 4 {
		return xerrors.Errorf("invalid traceparent format: expected 4 parts, got %d", len(parts))
	}

	// Validate version
	if parts[0] != "00" {
		return xerrors.Errorf("unsupported traceparent version: %s", parts[0])
	}

	// Validate trace ID length (32 hex chars)
	if len(parts[1]) != 32 {
		return xerrors.Errorf("invalid trace ID length: expected 32, got %d", len(parts[1]))
	}

	// Validate span ID length (16 hex chars)
	if len(parts[2]) != 16 {
		return xerrors.Errorf("invalid span ID length: expected 16, got %d", len(parts[2]))
	}

	// Validate flags length (2 hex chars)
	if len(parts[3]) != 2 {
		return xerrors.Errorf("invalid flags length: expected 2, got %d", len(parts[3]))
	}

	return nil
}
