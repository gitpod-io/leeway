package leeway

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// goTestEvent represents a single event from `go test -json` output.
// See https://pkg.go.dev/cmd/test2json for the format specification.
type goTestEvent struct {
	Time        time.Time `json:"Time"`
	Action      string    `json:"Action"`
	Package     string    `json:"Package"`
	Test        string    `json:"Test"`
	Output      string    `json:"Output"`
	Elapsed     float64   `json:"Elapsed"`     // seconds
	FailedBuild string    `json:"FailedBuild"` // package that failed to build (when Action == "fail")
}

// testSpanData holds the span for an in-progress test
type testSpanData struct {
	span trace.Span
}

// GoTestTracer handles parsing Go test JSON output and creating OpenTelemetry spans
type GoTestTracer struct {
	tracer        trace.Tracer
	parentCtx     context.Context
	leewayPkgName string

	mu    sync.Mutex
	spans map[string]*testSpanData // key: "package/testname" or just "package" for package-level
}

// NewGoTestTracer creates a new GoTestTracer that will create spans as children of the given context
func NewGoTestTracer(tracer trace.Tracer, parentCtx context.Context, leewayPkgName string) *GoTestTracer {
	return &GoTestTracer{
		tracer:        tracer,
		parentCtx:     parentCtx,
		leewayPkgName: leewayPkgName,
		spans:         make(map[string]*testSpanData),
	}
}

// spanKey generates a unique key for a test span
func spanKey(pkg, test string) string {
	if test == "" {
		return pkg
	}
	return pkg + "/" + test
}

// parseJSONOutput reads JSON events from the reader and creates/ends spans accordingly
func (t *GoTestTracer) parseJSONOutput(r io.Reader, outputWriter io.Writer) error {
	scanner := bufio.NewScanner(r)
	// Increase buffer size for long output lines
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	verbose := log.IsLevelEnabled(log.DebugLevel)

	// Buffer output for each test so we can show it on failure
	testOutput := make(map[string][]string)

	for scanner.Scan() {
		line := scanner.Bytes()

		var event goTestEvent
		if err := json.Unmarshal(line, &event); err != nil {
			// Not valid JSON, write as-is (shouldn't happen with -json flag)
			_, _ = outputWriter.Write(line)
			_, _ = outputWriter.Write([]byte("\n"))
			continue
		}

		// Handle output based on verbosity
		if event.Output != "" {
			if verbose {
				// Verbose mode: show all output
				_, _ = outputWriter.Write([]byte(event.Output))
			} else if event.Test == "" {
				// Non-verbose: always show package-level output
				_, _ = outputWriter.Write([]byte(event.Output))
			} else {
				// Non-verbose: buffer test output in case of failure
				key := spanKey(event.Package, event.Test)
				testOutput[key] = append(testOutput[key], event.Output)
			}
		}

		// On test failure, flush buffered output (non-verbose mode only)
		if !verbose && event.Action == "fail" && event.Test != "" {
			key := spanKey(event.Package, event.Test)
			if output, ok := testOutput[key]; ok {
				for _, line := range output {
					_, _ = outputWriter.Write([]byte(line))
				}
				delete(testOutput, key)
			}
		}

		// Clean up buffer on test completion (pass/skip)
		if event.Action == "pass" || event.Action == "skip" {
			if event.Test != "" {
				key := spanKey(event.Package, event.Test)
				delete(testOutput, key)
			}
		}

		// Handle the event for span creation
		t.handleEvent(&event)
	}

	// End any remaining spans (in case of abnormal termination)
	t.endAllSpans()

	return scanner.Err()
}

// handleEvent processes a single go test event
func (t *GoTestTracer) handleEvent(event *goTestEvent) {
	switch event.Action {
	case "run":
		t.handleRun(event)
	case "pause":
		t.handlePause(event)
	case "cont":
		t.handleCont(event)
	case "pass", "fail", "skip":
		t.handleEnd(event)
	case "output":
		// Output is already written to outputWriter
	case "start":
		// Package test started - we could create a package-level span here
		t.handlePackageStart(event)
	}
}

// handleRun creates a new span for a test that started running
func (t *GoTestTracer) handleRun(event *goTestEvent) {
	if event.Test == "" || t.tracer == nil {
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	key := spanKey(event.Package, event.Test)

	// Create span with the test start time
	_, span := t.tracer.Start(t.parentCtx, formatTestSpanName(event.Package, event.Test),
		trace.WithTimestamp(event.Time),
		trace.WithSpanKind(trace.SpanKindInternal),
	)

	span.SetAttributes(
		attribute.String("leeway.package.name", t.leewayPkgName),
		attribute.String("test.name", event.Test),
		attribute.String("test.package", event.Package),
		attribute.String("test.framework", "go"),
	)

	t.spans[key] = &testSpanData{span: span}
}

// handlePackageStart creates a span for package-level test execution
func (t *GoTestTracer) handlePackageStart(event *goTestEvent) {
	if event.Package == "" || t.tracer == nil {
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	key := spanKey(event.Package, "")

	// Only create if not already exists
	if _, exists := t.spans[key]; exists {
		return
	}

	_, span := t.tracer.Start(t.parentCtx, fmt.Sprintf("package: %s", event.Package),
		trace.WithTimestamp(event.Time),
		trace.WithSpanKind(trace.SpanKindInternal),
	)

	span.SetAttributes(
		attribute.String("leeway.package.name", t.leewayPkgName),
		attribute.String("test.package", event.Package),
		attribute.String("test.framework", "go"),
		attribute.String("test.scope", "package"),
	)

	t.spans[key] = &testSpanData{span: span}
}

// handlePause records that a test was paused (for t.Parallel())
func (t *GoTestTracer) handlePause(event *goTestEvent) {
	if event.Test == "" {
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	key := spanKey(event.Package, event.Test)
	if data, ok := t.spans[key]; ok {
		data.span.AddEvent("test.paused", trace.WithTimestamp(event.Time))
	}
}

// handleCont records that a paused test continued
func (t *GoTestTracer) handleCont(event *goTestEvent) {
	if event.Test == "" {
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	key := spanKey(event.Package, event.Test)
	if data, ok := t.spans[key]; ok {
		data.span.AddEvent("test.continued", trace.WithTimestamp(event.Time))
	}
}

// handleEnd ends a span for a completed test
func (t *GoTestTracer) handleEnd(event *goTestEvent) {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Handle test-level completion
	if event.Test != "" {
		key := spanKey(event.Package, event.Test)
		if data, ok := t.spans[key]; ok {
			// Set status based on action
			switch event.Action {
			case "pass":
				data.span.SetStatus(codes.Ok, "")
				data.span.SetAttributes(attribute.String("test.status", "passed"))
			case "fail":
				if event.FailedBuild != "" {
					data.span.SetStatus(codes.Error, "build failed")
					data.span.SetAttributes(
						attribute.String("test.status", "build_failed"),
						attribute.String("test.failed_build", event.FailedBuild),
					)
				} else {
					data.span.SetStatus(codes.Error, "test failed")
					data.span.SetAttributes(attribute.String("test.status", "failed"))
				}
			case "skip":
				data.span.SetStatus(codes.Ok, "test skipped")
				data.span.SetAttributes(attribute.String("test.status", "skipped"))
			}

			// Add elapsed time if available
			if event.Elapsed > 0 {
				data.span.SetAttributes(attribute.Float64("test.elapsed_seconds", event.Elapsed))
			}

			data.span.End(trace.WithTimestamp(event.Time))
			delete(t.spans, key)
		}
		return
	}

	// Handle package-level completion (event.Test is empty)
	if event.Package != "" {
		key := spanKey(event.Package, "")
		if data, ok := t.spans[key]; ok {
			switch event.Action {
			case "pass":
				data.span.SetStatus(codes.Ok, "")
				data.span.SetAttributes(attribute.String("test.status", "passed"))
			case "fail":
				if event.FailedBuild != "" {
					data.span.SetStatus(codes.Error, "build failed")
					data.span.SetAttributes(
						attribute.String("test.status", "build_failed"),
						attribute.String("test.failed_build", event.FailedBuild),
					)
				} else {
					data.span.SetStatus(codes.Error, "package tests failed")
					data.span.SetAttributes(attribute.String("test.status", "failed"))
				}
			case "skip":
				data.span.SetStatus(codes.Ok, "package tests skipped")
				data.span.SetAttributes(attribute.String("test.status", "skipped"))
			}

			if event.Elapsed > 0 {
				data.span.SetAttributes(attribute.Float64("test.elapsed_seconds", event.Elapsed))
			}

			data.span.End(trace.WithTimestamp(event.Time))
			delete(t.spans, key)
		}
	}
}

// endAllSpans ends any remaining open spans (cleanup for abnormal termination)
func (t *GoTestTracer) endAllSpans() {
	t.mu.Lock()
	defer t.mu.Unlock()

	for key, data := range t.spans {
		data.span.SetStatus(codes.Error, "test did not complete")
		data.span.End()
		delete(t.spans, key)
	}
}

// formatTestSpanName creates a readable span name for a test
func formatTestSpanName(pkg, test string) string {
	// Extract just the package name without the full module path
	parts := strings.Split(pkg, "/")
	shortPkg := parts[len(parts)-1]

	return fmt.Sprintf("test: %s/%s", shortPkg, test)
}

// ensureJSONFlag ensures the -json flag is present in the test arguments
func ensureJSONFlag(args []string) []string {
	for _, arg := range args {
		if arg == "-json" {
			return args
		}
	}

	// Insert -json after "test" command
	result := make([]string, 0, len(args)+1)
	for i, arg := range args {
		result = append(result, arg)
		if arg == "test" && i < len(args)-1 {
			result = append(result, "-json")
		}
	}

	// If "test" wasn't found, just append -json
	hasJSON := false
	for _, arg := range result {
		if arg == "-json" {
			hasJSON = true
			break
		}
	}
	if !hasJSON {
		result = append(result, "-json")
	}

	return result
}
