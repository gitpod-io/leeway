package leeway

import (
	"context"
	"testing"
	"time"

	"go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func TestOTelReporter_BuildLifecycle(t *testing.T) {
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

	// Test build lifecycle
	status := map[*Package]PackageBuildStatus{
		pkg: PackageNotBuiltYet,
	}

	reporter.BuildStarted(pkg, status)
	reporter.BuildFinished(pkg, nil)

	// Verify spans were created
	spans := exporter.GetSpans()
	if len(spans) == 0 {
		t.Fatal("Expected at least one span to be created")
	}

	// Verify root span
	rootSpan := spans[len(spans)-1]
	if rootSpan.Name != "leeway.build" {
		t.Errorf("Expected root span name 'leeway.build', got '%s'", rootSpan.Name)
	}

	// Verify attributes
	attrs := rootSpan.Attributes
	hasTargetPackage := false
	for _, attr := range attrs {
		if string(attr.Key) == "leeway.target.package" {
			hasTargetPackage = true
			if attr.Value.AsString() != "test-component:test-package" {
				t.Errorf("Expected target package 'test-component:test-package', got '%s'", attr.Value.AsString())
			}
		}
	}
	if !hasTargetPackage {
		t.Error("Expected 'leeway.target.package' attribute in root span")
	}
}

func TestOTelReporter_PackageLifecycle(t *testing.T) {
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

	// Start build first
	status := map[*Package]PackageBuildStatus{
		pkg: PackageNotBuiltYet,
	}
	reporter.BuildStarted(pkg, status)

	// Test package lifecycle
	reporter.PackageBuildStarted(pkg, "/tmp/build")

	rep := &PackageBuildReport{
		phaseEnter: make(map[PackageBuildPhase]time.Time),
		phaseDone:  make(map[PackageBuildPhase]time.Time),
		Phases:     []PackageBuildPhase{PackageBuildPhasePrep, PackageBuildPhaseBuild},
		Error:      nil,
	}
	reporter.PackageBuildFinished(pkg, rep)

	reporter.BuildFinished(pkg, nil)

	// Verify spans were created
	spans := exporter.GetSpans()
	if len(spans) < 2 {
		t.Fatalf("Expected at least 2 spans (build + package), got %d", len(spans))
	}

	// Find package span
	var packageSpan *tracetest.SpanStub
	for i := range spans {
		if spans[i].Name == "leeway.package" {
			packageSpan = &spans[i]
			break
		}
	}

	if packageSpan == nil {
		t.Fatal("Expected to find package span")
	}

	// Verify package attributes
	hasPackageName := false
	hasPackageType := false
	for _, attr := range packageSpan.Attributes {
		switch string(attr.Key) {
		case "leeway.package.name":
			hasPackageName = true
			if attr.Value.AsString() != "test-component:test-package" {
				t.Errorf("Expected package name 'test-component:test-package', got '%s'", attr.Value.AsString())
			}
		case "leeway.package.type":
			hasPackageType = true
			if attr.Value.AsString() != string(GenericPackage) {
				t.Errorf("Expected package type '%s', got '%s'", GenericPackage, attr.Value.AsString())
			}
		}
	}

	if !hasPackageName {
		t.Error("Expected 'leeway.package.name' attribute in package span")
	}
	if !hasPackageType {
		t.Error("Expected 'leeway.package.type' attribute in package span")
	}
}

func TestOTelReporter_NilTracer(t *testing.T) {
	// Reporter with nil tracer should not panic
	reporter := NewOTelReporter(nil, context.Background())

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

	status := map[*Package]PackageBuildStatus{
		pkg: PackageNotBuiltYet,
	}

	// These should not panic
	reporter.BuildStarted(pkg, status)
	reporter.PackageBuildStarted(pkg, "/tmp/build")
	reporter.PackageBuildFinished(pkg, &PackageBuildReport{})
	reporter.BuildFinished(pkg, nil)
}

func TestOTelReporter_ConcurrentPackages(t *testing.T) {
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

	// Create test packages
	pkg1 := &Package{
		C: &Component{
			Name: "component1",
			W: &Workspace{
				Origin: "/workspace",
			},
		},
		PackageInternal: PackageInternal{
			Name: "package1",
			Type: GenericPackage,
		},
	}

	pkg2 := &Package{
		C: &Component{
			Name: "component2",
			W: &Workspace{
				Origin: "/workspace",
			},
		},
		PackageInternal: PackageInternal{
			Name: "package2",
			Type: GenericPackage,
		},
	}

	// Start build
	status := map[*Package]PackageBuildStatus{
		pkg1: PackageNotBuiltYet,
		pkg2: PackageNotBuiltYet,
	}
	reporter.BuildStarted(pkg1, status)

	// Build packages concurrently
	done := make(chan bool, 2)

	go func() {
		reporter.PackageBuildStarted(pkg1, "/tmp/build1")
		reporter.PackageBuildFinished(pkg1, &PackageBuildReport{
			phaseEnter: make(map[PackageBuildPhase]time.Time),
			phaseDone:  make(map[PackageBuildPhase]time.Time),
			Phases:     []PackageBuildPhase{PackageBuildPhasePrep},
		})
		done <- true
	}()

	go func() {
		reporter.PackageBuildStarted(pkg2, "/tmp/build2")
		reporter.PackageBuildFinished(pkg2, &PackageBuildReport{
			phaseEnter: make(map[PackageBuildPhase]time.Time),
			phaseDone:  make(map[PackageBuildPhase]time.Time),
			Phases:     []PackageBuildPhase{PackageBuildPhasePrep},
		})
		done <- true
	}()

	// Wait for both to complete
	<-done
	<-done

	reporter.BuildFinished(pkg1, nil)

	// Verify we got spans for both packages
	spans := exporter.GetSpans()
	packageSpanCount := 0
	for _, span := range spans {
		if span.Name == "leeway.package" {
			packageSpanCount++
		}
	}

	if packageSpanCount != 2 {
		t.Errorf("Expected 2 package spans, got %d", packageSpanCount)
	}
}

func TestOTelReporter_WithParentContext(t *testing.T) {
	// Create in-memory exporter for testing
	exporter := tracetest.NewInMemoryExporter()
	tp := trace.NewTracerProvider(
		trace.WithSyncer(exporter),
	)
	defer func() {
		_ = tp.Shutdown(context.Background())
	}()

	// Create parent span
	tracer := tp.Tracer("test")
	parentCtx, parentSpan := tracer.Start(context.Background(), "parent-span")
	parentSpanID := parentSpan.SpanContext().SpanID()

	// Create reporter with parent context
	reporter := NewOTelReporter(tracer, parentCtx)

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

	status := map[*Package]PackageBuildStatus{
		pkg: PackageNotBuiltYet,
	}

	reporter.BuildStarted(pkg, status)
	reporter.BuildFinished(pkg, nil)

	// End parent span so it appears in exporter
	parentSpan.End()

	// Verify spans were created and have parent relationship
	spans := exporter.GetSpans()
	if len(spans) < 2 {
		t.Fatalf("Expected at least 2 spans (parent + build), got %d", len(spans))
	}

	// Find build span
	var buildSpan *tracetest.SpanStub
	for i := range spans {
		if spans[i].Name == "leeway.build" {
			buildSpan = &spans[i]
			break
		}
	}

	if buildSpan == nil {
		t.Fatal("Expected to find build span")
	}

	// Verify parent relationship
	if buildSpan.Parent.SpanID() != parentSpanID {
		t.Error("Build span should have parent span as parent")
	}
}
