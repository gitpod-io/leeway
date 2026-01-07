package leeway

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func TestGoTestTracer_ParseJSONOutput(t *testing.T) {
	// Create a test tracer provider with in-memory exporter
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSyncer(exporter),
	)
	defer func() { _ = tp.Shutdown(context.Background()) }()

	tracer := tp.Tracer("test")
	ctx, parentSpan := tracer.Start(context.Background(), "parent")
	defer parentSpan.End()

	goTracer := NewGoTestTracer(tracer, ctx)

	// Simulate go test -json output
	jsonOutput := `{"Time":"2024-01-01T10:00:00Z","Action":"start","Package":"example.com/pkg"}
{"Time":"2024-01-01T10:00:00.001Z","Action":"run","Package":"example.com/pkg","Test":"TestOne"}
{"Time":"2024-01-01T10:00:00.002Z","Action":"output","Package":"example.com/pkg","Test":"TestOne","Output":"=== RUN   TestOne\n"}
{"Time":"2024-01-01T10:00:00.100Z","Action":"output","Package":"example.com/pkg","Test":"TestOne","Output":"--- PASS: TestOne (0.10s)\n"}
{"Time":"2024-01-01T10:00:00.100Z","Action":"pass","Package":"example.com/pkg","Test":"TestOne","Elapsed":0.1}
{"Time":"2024-01-01T10:00:00.101Z","Action":"run","Package":"example.com/pkg","Test":"TestTwo"}
{"Time":"2024-01-01T10:00:00.200Z","Action":"fail","Package":"example.com/pkg","Test":"TestTwo","Elapsed":0.1}
{"Time":"2024-01-01T10:00:00.201Z","Action":"run","Package":"example.com/pkg","Test":"TestThree"}
{"Time":"2024-01-01T10:00:00.250Z","Action":"skip","Package":"example.com/pkg","Test":"TestThree","Elapsed":0.05}
{"Time":"2024-01-01T10:00:00.300Z","Action":"pass","Package":"example.com/pkg","Elapsed":0.3}
`

	var outputBuf bytes.Buffer
	err := goTracer.parseJSONOutput(strings.NewReader(jsonOutput), &outputBuf)
	if err != nil {
		t.Fatalf("parseJSONOutput failed: %v", err)
	}

	// End parent span to flush
	parentSpan.End()

	// Check that spans were created
	spans := exporter.GetSpans()

	// We expect: parent span + package span + 3 test spans = 5 spans
	// But the parent span is ended after, so we check for at least 4
	if len(spans) < 4 {
		t.Errorf("expected at least 4 spans, got %d", len(spans))
		for i, s := range spans {
			t.Logf("span %d: %s", i, s.Name)
		}
	}

	// Verify test spans exist with correct names
	spanNames := make(map[string]bool)
	for _, s := range spans {
		spanNames[s.Name] = true
	}

	expectedSpans := []string{
		"test: pkg/TestOne",
		"test: pkg/TestTwo",
		"test: pkg/TestThree",
		"package: example.com/pkg",
	}

	for _, expected := range expectedSpans {
		if !spanNames[expected] {
			t.Errorf("expected span %q not found", expected)
		}
	}

	// Verify span statuses
	for _, s := range spans {
		switch s.Name {
		case "test: pkg/TestOne":
			if s.Status.Code != codes.Ok {
				t.Errorf("TestOne should have Ok status, got %v", s.Status.Code)
			}
		case "test: pkg/TestTwo":
			if s.Status.Code != codes.Error {
				t.Errorf("TestTwo should have Error status, got %v", s.Status.Code)
			}
		case "test: pkg/TestThree":
			if s.Status.Code != codes.Ok {
				t.Errorf("TestThree (skipped) should have Ok status, got %v", s.Status.Code)
			}
		}
	}

	// Verify output was written
	output := outputBuf.String()
	if !strings.Contains(output, "=== RUN   TestOne") {
		t.Error("expected test output to be written")
	}
}

func TestGoTestTracer_ParallelTests(t *testing.T) {
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSyncer(exporter),
	)
	defer func() { _ = tp.Shutdown(context.Background()) }()

	tracer := tp.Tracer("test")
	ctx, parentSpan := tracer.Start(context.Background(), "parent")
	defer parentSpan.End()

	goTracer := NewGoTestTracer(tracer, ctx)

	// Simulate parallel test execution with pause/cont events
	jsonOutput := `{"Time":"2024-01-01T10:00:00Z","Action":"run","Package":"example.com/pkg","Test":"TestParallel"}
{"Time":"2024-01-01T10:00:00.001Z","Action":"pause","Package":"example.com/pkg","Test":"TestParallel"}
{"Time":"2024-01-01T10:00:00.100Z","Action":"cont","Package":"example.com/pkg","Test":"TestParallel"}
{"Time":"2024-01-01T10:00:00.200Z","Action":"pass","Package":"example.com/pkg","Test":"TestParallel","Elapsed":0.2}
`

	var outputBuf bytes.Buffer
	err := goTracer.parseJSONOutput(strings.NewReader(jsonOutput), &outputBuf)
	if err != nil {
		t.Fatalf("parseJSONOutput failed: %v", err)
	}

	parentSpan.End()
	spans := exporter.GetSpans()

	// Find the test span
	var testSpan *tracetest.SpanStub
	for i := range spans {
		if spans[i].Name == "test: pkg/TestParallel" {
			testSpan = &spans[i]
			break
		}
	}

	if testSpan == nil {
		t.Fatal("TestParallel span not found")
	}

	// Verify pause and cont events were recorded
	eventNames := make([]string, 0)
	for _, e := range testSpan.Events {
		eventNames = append(eventNames, e.Name)
	}

	if len(eventNames) != 2 {
		t.Errorf("expected 2 events (pause, cont), got %d: %v", len(eventNames), eventNames)
	}
}

func TestGoTestTracer_NoTracer(t *testing.T) {
	// Test that nil tracer doesn't panic
	goTracer := NewGoTestTracer(nil, context.Background())

	jsonOutput := `{"Time":"2024-01-01T10:00:00Z","Action":"run","Package":"example.com/pkg","Test":"TestOne"}
{"Time":"2024-01-01T10:00:00.100Z","Action":"pass","Package":"example.com/pkg","Test":"TestOne","Elapsed":0.1}
`

	var outputBuf bytes.Buffer
	err := goTracer.parseJSONOutput(strings.NewReader(jsonOutput), &outputBuf)
	if err != nil {
		t.Fatalf("parseJSONOutput failed: %v", err)
	}
}

func TestEnsureJSONFlag(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected []string
	}{
		{
			name:     "already has -json",
			input:    []string{"go", "test", "-json", "./..."},
			expected: []string{"go", "test", "-json", "./..."},
		},
		{
			name:     "needs -json after test",
			input:    []string{"go", "test", "-v", "./..."},
			expected: []string{"go", "test", "-json", "-v", "./..."},
		},
		{
			name:     "simple test command",
			input:    []string{"go", "test"},
			expected: []string{"go", "test", "-json"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ensureJSONFlag(tt.input)

			// Check that -json is present
			hasJSON := false
			for _, arg := range result {
				if arg == "-json" {
					hasJSON = true
					break
				}
			}
			if !hasJSON {
				t.Errorf("result %v does not contain -json", result)
			}
		})
	}
}

func TestSpanKey(t *testing.T) {
	tests := []struct {
		pkg      string
		test     string
		expected string
	}{
		{"example.com/pkg", "TestOne", "example.com/pkg/TestOne"},
		{"example.com/pkg", "", "example.com/pkg"},
		{"pkg", "TestSub/case1", "pkg/TestSub/case1"},
	}

	for _, tt := range tests {
		result := spanKey(tt.pkg, tt.test)
		if result != tt.expected {
			t.Errorf("spanKey(%q, %q) = %q, want %q", tt.pkg, tt.test, result, tt.expected)
		}
	}
}

func TestFormatTestSpanName(t *testing.T) {
	tests := []struct {
		pkg      string
		test     string
		expected string
	}{
		{"example.com/pkg", "TestOne", "test: pkg/TestOne"},
		{"github.com/org/repo/internal/service", "TestCreate", "test: service/TestCreate"},
		{"simple", "TestSimple", "test: simple/TestSimple"},
	}

	for _, tt := range tests {
		result := formatTestSpanName(tt.pkg, tt.test)
		if result != tt.expected {
			t.Errorf("formatTestSpanName(%q, %q) = %q, want %q", tt.pkg, tt.test, result, tt.expected)
		}
	}
}

func TestGoTestEvent_Parsing(t *testing.T) {
	// Test that goTestEvent can parse real go test -json output
	jsonLine := `{"Time":"2024-01-15T10:30:45.123456789Z","Action":"pass","Package":"github.com/example/pkg","Test":"TestExample","Elapsed":1.234}`

	var event goTestEvent
	err := json.Unmarshal([]byte(jsonLine), &event)
	if err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}

	if event.Action != "pass" {
		t.Errorf("expected action 'pass', got %q", event.Action)
	}
	if event.Package != "github.com/example/pkg" {
		t.Errorf("expected package 'github.com/example/pkg', got %q", event.Package)
	}
	if event.Test != "TestExample" {
		t.Errorf("expected test 'TestExample', got %q", event.Test)
	}
	if event.Elapsed != 1.234 {
		t.Errorf("expected elapsed 1.234, got %f", event.Elapsed)
	}
	if event.Time.IsZero() {
		t.Error("expected non-zero time")
	}
}
