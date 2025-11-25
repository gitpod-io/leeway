package leeway

import (
	"context"
	"fmt"
	"testing"
	"time"

	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func TestOTelReporter_PhaseSpans(t *testing.T) {
	// Create in-memory exporter for testing
	exporter := tracetest.NewInMemoryExporter()
	tp := trace.NewTracerProvider(
		trace.WithSyncer(exporter),
	)
	defer func() {
		_ = tp.Shutdown(context.Background())
	}()

	tracer := tp.Tracer("test")
	reporter := NewOTelReporter(tracer, context.Background())

	// Create test package
	pkg := &Package{
		C: &Component{
			Name: "test-component",
			W: &Workspace{
				Origin: "/workspace",
			},
		},
		PackageInternal: PackageInternal{
			Name: "test-package",
			Type: GenericPackage,
		},
	}

	// Start build and package
	status := map[*Package]PackageBuildStatus{
		pkg: PackageNotBuiltYet,
	}
	reporter.BuildStarted(pkg, status)
	reporter.PackageBuildStarted(pkg, "/tmp/build")

	// Simulate phase execution
	phases := []PackageBuildPhase{
		PackageBuildPhasePrep,
		PackageBuildPhaseBuild,
		PackageBuildPhaseTest,
	}

	for _, phase := range phases {
		reporter.PackageBuildPhaseStarted(pkg, phase)
		time.Sleep(10 * time.Millisecond) // Simulate work
		reporter.PackageBuildPhaseFinished(pkg, phase, nil)
	}

	// Finish package and build
	rep := &PackageBuildReport{
		phaseEnter: make(map[PackageBuildPhase]time.Time),
		phaseDone:  make(map[PackageBuildPhase]time.Time),
		Phases:     phases,
		Error:      nil,
	}
	reporter.PackageBuildFinished(pkg, rep)
	reporter.BuildFinished(pkg, nil)

	// Verify spans were created
	spans := exporter.GetSpans()
	if len(spans) < 5 { // build + package + 3 phases
		t.Fatalf("Expected at least 5 spans (build + package + 3 phases), got %d", len(spans))
	}

	// Count phase spans
	phaseSpanCount := 0
	for _, span := range spans {
		if span.Name == "leeway.phase" {
			phaseSpanCount++

			// Verify phase has name attribute
			hasPhaseNameAttr := false
			for _, attr := range span.Attributes {
				if string(attr.Key) == "leeway.phase.name" {
					hasPhaseNameAttr = true
					phaseName := attr.Value.AsString()
					if phaseName != string(PackageBuildPhasePrep) &&
						phaseName != string(PackageBuildPhaseBuild) &&
						phaseName != string(PackageBuildPhaseTest) {
						t.Errorf("Unexpected phase name: %s", phaseName)
					}
				}
			}
			if !hasPhaseNameAttr {
				t.Error("Expected 'leeway.phase.name' attribute in phase span")
			}

			// Verify status is OK
			if span.Status.Code != codes.Ok {
				t.Errorf("Expected phase span status OK, got %v", span.Status.Code)
			}
		}
	}

	if phaseSpanCount != 3 {
		t.Errorf("Expected 3 phase spans, got %d", phaseSpanCount)
	}
}

func TestOTelReporter_PhaseSpanWithError(t *testing.T) {
	// Create in-memory exporter for testing
	exporter := tracetest.NewInMemoryExporter()
	tp := trace.NewTracerProvider(
		trace.WithSyncer(exporter),
	)
	defer func() {
		_ = tp.Shutdown(context.Background())
	}()

	tracer := tp.Tracer("test")
	reporter := NewOTelReporter(tracer, context.Background())

	// Create test package
	pkg := &Package{
		C: &Component{
			Name: "test-component",
			W: &Workspace{
				Origin: "/workspace",
			},
		},
		PackageInternal: PackageInternal{
			Name: "test-package",
			Type: GenericPackage,
		},
	}

	// Start build and package
	status := map[*Package]PackageBuildStatus{
		pkg: PackageNotBuiltYet,
	}
	reporter.BuildStarted(pkg, status)
	reporter.PackageBuildStarted(pkg, "/tmp/build")

	// Simulate phase with error
	reporter.PackageBuildPhaseStarted(pkg, PackageBuildPhaseBuild)
	buildErr := fmt.Errorf("build failed")
	reporter.PackageBuildPhaseFinished(pkg, PackageBuildPhaseBuild, buildErr)

	// Finish package and build
	rep := &PackageBuildReport{
		phaseEnter: make(map[PackageBuildPhase]time.Time),
		phaseDone:  make(map[PackageBuildPhase]time.Time),
		Phases:     []PackageBuildPhase{PackageBuildPhaseBuild},
		Error:      buildErr,
	}
	reporter.PackageBuildFinished(pkg, rep)
	reporter.BuildFinished(pkg, buildErr)

	// Verify spans were created
	spans := exporter.GetSpans()

	// Find phase span
	var phaseSpan *tracetest.SpanStub
	for i := range spans {
		if spans[i].Name == "leeway.phase" {
			phaseSpan = &spans[i]
			break
		}
	}

	if phaseSpan == nil {
		t.Fatal("Expected to find phase span")
	}

	// Verify error status
	if phaseSpan.Status.Code != codes.Error {
		t.Errorf("Expected phase span status Error, got %v", phaseSpan.Status.Code)
	}

	// Verify error was recorded
	if len(phaseSpan.Events) == 0 {
		t.Error("Expected error event to be recorded in phase span")
	}
}

func TestOTelReporter_PhaseSpanHierarchy(t *testing.T) {
	// Create in-memory exporter for testing
	exporter := tracetest.NewInMemoryExporter()
	tp := trace.NewTracerProvider(
		trace.WithSyncer(exporter),
	)
	defer func() {
		_ = tp.Shutdown(context.Background())
	}()

	tracer := tp.Tracer("test")
	reporter := NewOTelReporter(tracer, context.Background())

	// Create test package
	pkg := &Package{
		C: &Component{
			Name: "test-component",
			W: &Workspace{
				Origin: "/workspace",
			},
		},
		PackageInternal: PackageInternal{
			Name: "test-package",
			Type: GenericPackage,
		},
	}

	// Start build and package
	status := map[*Package]PackageBuildStatus{
		pkg: PackageNotBuiltYet,
	}
	reporter.BuildStarted(pkg, status)
	reporter.PackageBuildStarted(pkg, "/tmp/build")

	// Execute phase
	reporter.PackageBuildPhaseStarted(pkg, PackageBuildPhaseBuild)
	reporter.PackageBuildPhaseFinished(pkg, PackageBuildPhaseBuild, nil)

	// Finish package and build
	rep := &PackageBuildReport{
		phaseEnter: make(map[PackageBuildPhase]time.Time),
		phaseDone:  make(map[PackageBuildPhase]time.Time),
		Phases:     []PackageBuildPhase{PackageBuildPhaseBuild},
		Error:      nil,
	}
	reporter.PackageBuildFinished(pkg, rep)
	reporter.BuildFinished(pkg, nil)

	// Verify span hierarchy
	spans := exporter.GetSpans()

	var buildSpan, packageSpan, phaseSpan *tracetest.SpanStub
	for i := range spans {
		switch spans[i].Name {
		case "leeway.build":
			buildSpan = &spans[i]
		case "leeway.package":
			packageSpan = &spans[i]
		case "leeway.phase":
			phaseSpan = &spans[i]
		}
	}

	if buildSpan == nil {
		t.Fatal("Expected to find build span")
	}
	if packageSpan == nil {
		t.Fatal("Expected to find package span")
	}
	if phaseSpan == nil {
		t.Fatal("Expected to find phase span")
	}

	// Verify parent-child relationships
	// Package span should be child of build span
	if packageSpan.Parent.TraceID() != buildSpan.SpanContext.TraceID() {
		t.Error("Package span should have same trace ID as build span")
	}
	if packageSpan.Parent.SpanID() != buildSpan.SpanContext.SpanID() {
		t.Error("Package span should be child of build span")
	}

	// Phase span should be child of package span
	if phaseSpan.Parent.TraceID() != packageSpan.SpanContext.TraceID() {
		t.Error("Phase span should have same trace ID as package span")
	}
	if phaseSpan.Parent.SpanID() != packageSpan.SpanContext.SpanID() {
		t.Error("Phase span should be child of package span")
	}
}

func TestOTelReporter_PhaseAwareInterface(t *testing.T) {
	// Verify OTelReporter implements PhaseAwareReporter
	var _ PhaseAwareReporter = (*OTelReporter)(nil)

	// Verify NoopReporter does NOT implement PhaseAwareReporter
	var noop Reporter = &NoopReporter{}
	if _, ok := noop.(PhaseAwareReporter); ok {
		t.Error("NoopReporter should not implement PhaseAwareReporter")
	}
}

func TestOTelReporter_PhaseWithoutPackageContext(t *testing.T) {
	// Create in-memory exporter for testing
	exporter := tracetest.NewInMemoryExporter()
	tp := trace.NewTracerProvider(
		trace.WithSyncer(exporter),
	)
	defer func() {
		_ = tp.Shutdown(context.Background())
	}()

	tracer := tp.Tracer("test")
	reporter := NewOTelReporter(tracer, context.Background())

	// Create test package
	pkg := &Package{
		C: &Component{
			Name: "test-component",
			W: &Workspace{
				Origin: "/workspace",
			},
		},
		PackageInternal: PackageInternal{
			Name: "test-package",
			Type: GenericPackage,
		},
	}

	// Try to start phase without starting package first
	// This should not panic and should log a warning
	reporter.PackageBuildPhaseStarted(pkg, PackageBuildPhaseBuild)
	reporter.PackageBuildPhaseFinished(pkg, PackageBuildPhaseBuild, nil)

	// Verify no phase spans were created
	spans := exporter.GetSpans()
	for _, span := range spans {
		if span.Name == "leeway.phase" {
			t.Error("Phase span should not be created without package context")
		}
	}
}
