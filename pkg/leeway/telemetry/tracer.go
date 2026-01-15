package telemetry

import (
	"context"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/xerrors"
)

var (
	// leewayVersion is set by the build system and used for telemetry
	leewayVersion = "unknown"

	// tracerProvider holds the global tracer provider
	tracerProvider *sdktrace.TracerProvider

	// initialized tracks whether tracing has been initialized
	initialized bool
)

// SetLeewayVersion sets the leeway version for telemetry reporting
func SetLeewayVersion(version string) {
	if version != "" {
		leewayVersion = version
	}
}

// Initialize sets up the OpenTelemetry tracer with OTLP HTTP exporter.
// This should be called once at application startup.
// Returns an error if initialization fails, or nil if tracing is disabled (empty endpoint).
func Initialize(ctx context.Context, endpoint string, insecure bool) error {
	if endpoint == "" {
		return nil
	}

	if initialized {
		return nil
	}

	// Create OTLP HTTP exporter with optional TLS
	opts := []otlptracehttp.Option{
		otlptracehttp.WithEndpoint(endpoint),
	}
	if insecure {
		opts = append(opts, otlptracehttp.WithInsecure())
	}

	exporter, err := otlptracehttp.New(ctx, opts...)
	if err != nil {
		return xerrors.Errorf("failed to create OTLP exporter: %w", err)
	}

	// Create resource with service information
	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceNameKey.String("leeway"),
			semconv.ServiceVersionKey.String(leewayVersion),
		),
	)
	if err != nil {
		return xerrors.Errorf("failed to create resource: %w", err)
	}

	// Create tracer provider
	tracerProvider = sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
	)

	// Set global tracer provider
	otel.SetTracerProvider(tracerProvider)

	// Set global propagator for W3C Trace Context
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	initialized = true
	return nil
}

// Shutdown flushes any pending spans and shuts down the tracer provider.
func Shutdown(ctx context.Context) error {
	if tracerProvider == nil {
		return nil
	}

	shutdownCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	err := tracerProvider.Shutdown(shutdownCtx)
	tracerProvider = nil
	initialized = false
	return err
}

// Enabled returns true if tracing has been initialized.
func Enabled() bool {
	return initialized
}

// Tracer returns the global tracer for leeway.
func Tracer() trace.Tracer {
	return otel.GetTracerProvider().Tracer("github.com/gitpod-io/leeway")
}

// StartSpan creates a new span with the given name and attributes.
func StartSpan(ctx context.Context, name string, attrs ...attribute.KeyValue) (context.Context, trace.Span) {
	return Tracer().Start(ctx, name, trace.WithAttributes(attrs...))
}

// FinishSpan ends a span and sets its status based on the error.
// Usage: defer telemetry.FinishSpan(span, &err)
func FinishSpan(span trace.Span, err *error) {
	if span == nil {
		return
	}
	if err != nil && *err != nil {
		span.RecordError(*err)
		span.SetStatus(codes.Error, (*err).Error())
	} else {
		span.SetStatus(codes.Ok, "")
	}
	span.End()
}

// ParseTraceContext parses W3C Trace Context headers (traceparent and tracestate)
// and returns a context with the extracted trace information.
func ParseTraceContext(traceparent, tracestate string) (context.Context, error) {
	if traceparent == "" {
		return context.Background(), nil
	}

	carrier := propagation.MapCarrier{
		"traceparent": traceparent,
	}
	if tracestate != "" {
		carrier["tracestate"] = tracestate
	}

	ctx := context.Background()
	propagator := propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	)
	ctx = propagator.Extract(ctx, carrier)

	spanCtx := trace.SpanContextFromContext(ctx)
	if !spanCtx.IsValid() {
		return nil, xerrors.Errorf("invalid trace context: traceparent=%s", traceparent)
	}

	return ctx, nil
}

// FormatTraceContext formats a span context into W3C Trace Context format.
func FormatTraceContext(spanCtx trace.SpanContext) (traceparent, tracestate string) {
	if !spanCtx.IsValid() {
		return "", ""
	}

	carrier := propagation.MapCarrier{}
	propagator := propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	)
	ctx := trace.ContextWithSpanContext(context.Background(), spanCtx)
	propagator.Inject(ctx, carrier)

	return carrier.Get("traceparent"), carrier.Get("tracestate")
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

	if parts[0] != "00" {
		return xerrors.Errorf("unsupported traceparent version: %s", parts[0])
	}

	if len(parts[1]) != 32 {
		return xerrors.Errorf("invalid trace ID length: expected 32, got %d", len(parts[1]))
	}

	if len(parts[2]) != 16 {
		return xerrors.Errorf("invalid span ID length: expected 16, got %d", len(parts[2]))
	}

	if len(parts[3]) != 2 {
		return xerrors.Errorf("invalid flags length: expected 2, got %d", len(parts[3]))
	}

	return nil
}
