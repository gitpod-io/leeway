package telemetry

import (
	"context"
	"testing"

	"go.opentelemetry.io/otel/trace"
)

func TestParseTraceContext(t *testing.T) {
	tests := []struct {
		name        string
		traceparent string
		tracestate  string
		wantErr     bool
		wantValid   bool
	}{
		{
			name:        "valid traceparent",
			traceparent: "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
			tracestate:  "",
			wantErr:     false,
			wantValid:   true,
		},
		{
			name:        "valid traceparent with tracestate",
			traceparent: "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
			tracestate:  "congo=t61rcWkgMzE",
			wantErr:     false,
			wantValid:   true,
		},
		{
			name:        "empty traceparent",
			traceparent: "",
			tracestate:  "",
			wantErr:     false,
			wantValid:   false,
		},
		{
			name:        "invalid traceparent",
			traceparent: "invalid",
			tracestate:  "",
			wantErr:     true,
			wantValid:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, err := ParseTraceContext(tt.traceparent, tt.tracestate)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseTraceContext() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil {
				spanCtx := trace.SpanContextFromContext(ctx)
				if spanCtx.IsValid() != tt.wantValid {
					t.Errorf("ParseTraceContext() span context valid = %v, want %v", spanCtx.IsValid(), tt.wantValid)
				}
			}
		})
	}
}

func TestValidateTraceParent(t *testing.T) {
	tests := []struct {
		name        string
		traceparent string
		wantErr     bool
	}{
		{
			name:        "valid traceparent",
			traceparent: "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
			wantErr:     false,
		},
		{
			name:        "empty traceparent",
			traceparent: "",
			wantErr:     false,
		},
		{
			name:        "invalid format - too few parts",
			traceparent: "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7",
			wantErr:     true,
		},
		{
			name:        "invalid format - too many parts",
			traceparent: "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-extra",
			wantErr:     true,
		},
		{
			name:        "invalid version",
			traceparent: "ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
			wantErr:     true,
		},
		{
			name:        "invalid trace ID length",
			traceparent: "00-4bf92f3577b34da6a3ce929d0e0e473-00f067aa0ba902b7-01",
			wantErr:     true,
		},
		{
			name:        "invalid span ID length",
			traceparent: "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b-01",
			wantErr:     true,
		},
		{
			name:        "invalid flags length",
			traceparent: "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-1",
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateTraceParent(tt.traceparent)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateTraceParent() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestFormatTraceContext(t *testing.T) {
	// Create a valid span context
	traceID, _ := trace.TraceIDFromHex("4bf92f3577b34da6a3ce929d0e0e4736")
	spanID, _ := trace.SpanIDFromHex("00f067aa0ba902b7")
	spanCtx := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    traceID,
		SpanID:     spanID,
		TraceFlags: trace.FlagsSampled,
	})

	traceparent, tracestate := FormatTraceContext(spanCtx)

	// Validate format
	if err := ValidateTraceParent(traceparent); err != nil {
		t.Errorf("FormatTraceContext() produced invalid traceparent: %v", err)
	}

	// Verify it can be parsed back
	ctx, err := ParseTraceContext(traceparent, tracestate)
	if err != nil {
		t.Errorf("FormatTraceContext() produced unparseable traceparent: %v", err)
	}

	parsedSpanCtx := trace.SpanContextFromContext(ctx)
	if !parsedSpanCtx.IsValid() {
		t.Error("FormatTraceContext() produced invalid span context after round-trip")
	}

	if parsedSpanCtx.TraceID() != traceID {
		t.Errorf("FormatTraceContext() trace ID mismatch: got %v, want %v", parsedSpanCtx.TraceID(), traceID)
	}
}

func TestFormatTraceContext_Invalid(t *testing.T) {
	// Test with invalid span context
	spanCtx := trace.SpanContext{}
	traceparent, tracestate := FormatTraceContext(spanCtx)

	if traceparent != "" {
		t.Errorf("FormatTraceContext() with invalid span context should return empty traceparent, got %v", traceparent)
	}
	if tracestate != "" {
		t.Errorf("FormatTraceContext() with invalid span context should return empty tracestate, got %v", tracestate)
	}
}

func TestInitTracer_NoEndpoint(t *testing.T) {
	_, err := InitTracer(context.Background(), "", false)
	if err == nil {
		t.Error("InitTracer() should fail when endpoint is empty")
	}
}

func TestShutdown_NilProvider(t *testing.T) {
	// Should not panic with nil provider
	err := Shutdown(context.Background(), nil)
	if err != nil {
		t.Errorf("Shutdown() with nil provider should not return error, got %v", err)
	}
}
