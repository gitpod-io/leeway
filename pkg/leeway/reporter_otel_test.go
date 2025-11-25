package leeway

import (
	"context"
	"fmt"
	"os"
	"strings"
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

func TestOTelReporter_GitHubAttributes(t *testing.T) {
	// Save and restore environment
	githubVars := []string{
		"GITHUB_ACTIONS",
		"GITHUB_WORKFLOW",
		"GITHUB_RUN_ID",
		"GITHUB_RUN_NUMBER",
		"GITHUB_JOB",
		"GITHUB_ACTOR",
		"GITHUB_REPOSITORY",
		"GITHUB_REF",
		"GITHUB_SHA",
		"GITHUB_SERVER_URL",
		"GITHUB_WORKFLOW_REF",
	}

	oldVars := make(map[string]string)
	for _, key := range githubVars {
		oldVars[key] = os.Getenv(key)
	}

	defer func() {
		for key, val := range oldVars {
			if val == "" {
				_ = os.Unsetenv(key)
			} else {
				_ = os.Setenv(key, val)
			}
		}
	}()

	// Set GitHub environment variables
	_ = os.Setenv("GITHUB_ACTIONS", "true")
	_ = os.Setenv("GITHUB_WORKFLOW", "test-workflow")
	_ = os.Setenv("GITHUB_RUN_ID", "123456789")
	_ = os.Setenv("GITHUB_RUN_NUMBER", "42")
	_ = os.Setenv("GITHUB_JOB", "test-job")
	_ = os.Setenv("GITHUB_ACTOR", "test-user")
	_ = os.Setenv("GITHUB_REPOSITORY", "test-org/test-repo")
	_ = os.Setenv("GITHUB_REF", "refs/pull/123/merge")
	_ = os.Setenv("GITHUB_HEAD_REF", "feature-branch")
	_ = os.Setenv("GITHUB_SHA", "abc123def456")
	_ = os.Setenv("GITHUB_SERVER_URL", "https://github.com")
	_ = os.Setenv("GITHUB_WORKFLOW_REF", "test-org/test-repo/.github/workflows/test.yml@refs/heads/main")

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

	// Verify spans were created
	spans := exporter.GetSpans()
	if len(spans) == 0 {
		t.Fatal("Expected at least one span to be created")
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

	// Verify GitHub attributes are present
	expectedAttrs := map[string]string{
		"github.workflow":     "test-workflow",
		"github.run_id":       "123456789",
		"github.run_number":   "42",
		"github.job":          "test-job",
		"github.actor":        "test-user",
		"github.repository":   "test-org/test-repo",
		"github.ref":          "refs/pull/123/merge",
		"github.head_ref":     "feature-branch",
		"github.sha":          "abc123def456",
		"github.server_url":   "https://github.com",
		"github.workflow_ref": "test-org/test-repo/.github/workflows/test.yml@refs/heads/main",
	}

	foundAttrs := make(map[string]string)
	for _, attr := range buildSpan.Attributes {
		key := string(attr.Key)
		if strings.HasPrefix(key, "github.") {
			foundAttrs[key] = attr.Value.AsString()
		}
	}

	// Check all expected attributes are present with correct values
	for key, expectedValue := range expectedAttrs {
		actualValue, found := foundAttrs[key]
		if !found {
			t.Errorf("Expected GitHub attribute '%s' not found in span", key)
		} else if actualValue != expectedValue {
			t.Errorf("GitHub attribute '%s': expected '%s', got '%s'", key, expectedValue, actualValue)
		}
	}

	// Verify we found all expected attributes
	if len(foundAttrs) != len(expectedAttrs) {
		t.Errorf("Expected %d GitHub attributes, found %d", len(expectedAttrs), len(foundAttrs))
	}
}

func TestOTelReporter_NoGitHubAttributes(t *testing.T) {
	// Save and restore GITHUB_ACTIONS
	oldValue := os.Getenv("GITHUB_ACTIONS")
	defer func() {
		if oldValue == "" {
			_ = os.Unsetenv("GITHUB_ACTIONS")
		} else {
			_ = os.Setenv("GITHUB_ACTIONS", oldValue)
		}
	}()

	// Ensure GITHUB_ACTIONS is not set
	_ = os.Unsetenv("GITHUB_ACTIONS")

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

	// Verify spans were created
	spans := exporter.GetSpans()
	if len(spans) == 0 {
		t.Fatal("Expected at least one span to be created")
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

	// Verify NO GitHub attributes are present
	for _, attr := range buildSpan.Attributes {
		key := string(attr.Key)
		if strings.HasPrefix(key, "github.") {
			t.Errorf("Unexpected GitHub attribute '%s' found when GITHUB_ACTIONS is not set", key)
		}
	}
}

func TestOTelReporter_BuildError(t *testing.T) {
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

	// Simulate build error
	buildErr := fmt.Errorf("build failed: compilation error")
	reporter.BuildFinished(pkg, buildErr)

	// Verify spans were created
	spans := exporter.GetSpans()
	if len(spans) == 0 {
		t.Fatal("Expected at least one span to be created")
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

	// Verify error status
	if buildSpan.Status.Code != 1 { // codes.Error = 1
		t.Errorf("Expected error status code 1, got %d", buildSpan.Status.Code)
	}

	if buildSpan.Status.Description != "build failed: compilation error" {
		t.Errorf("Expected error description 'build failed: compilation error', got '%s'", buildSpan.Status.Description)
	}
}

func TestOTelReporter_PackageBuildError(t *testing.T) {
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
	reporter.PackageBuildStarted(pkg, "/tmp/build")

	// Simulate package build error
	pkgErr := fmt.Errorf("package build failed: test failure")
	rep := &PackageBuildReport{
		phaseEnter: make(map[PackageBuildPhase]time.Time),
		phaseDone:  make(map[PackageBuildPhase]time.Time),
		Phases:     []PackageBuildPhase{PackageBuildPhasePrep, PackageBuildPhaseTest},
		Error:      pkgErr,
	}
	reporter.PackageBuildFinished(pkg, rep)
	reporter.BuildFinished(pkg, nil)

	// Verify spans were created
	spans := exporter.GetSpans()
	if len(spans) < 2 {
		t.Fatalf("Expected at least 2 spans, got %d", len(spans))
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

	// Verify error status
	if packageSpan.Status.Code != 1 { // codes.Error = 1
		t.Errorf("Expected error status code 1, got %d", packageSpan.Status.Code)
	}

	if packageSpan.Status.Description != "package build failed: test failure" {
		t.Errorf("Expected error description 'package build failed: test failure', got '%s'", packageSpan.Status.Description)
	}
}

func TestOTelReporter_TestCoverageAttributes(t *testing.T) {
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
	reporter.PackageBuildStarted(pkg, "/tmp/build")

	// Report with test coverage
	rep := &PackageBuildReport{
		phaseEnter:             make(map[PackageBuildPhase]time.Time),
		phaseDone:              make(map[PackageBuildPhase]time.Time),
		Phases:                 []PackageBuildPhase{PackageBuildPhasePrep, PackageBuildPhaseTest},
		TestCoverageAvailable:  true,
		TestCoveragePercentage: 85,
		FunctionsWithTest:      42,
		FunctionsWithoutTest:   8,
	}
	reporter.PackageBuildFinished(pkg, rep)
	reporter.BuildFinished(pkg, nil)

	// Verify spans were created
	spans := exporter.GetSpans()
	if len(spans) < 2 {
		t.Fatalf("Expected at least 2 spans, got %d", len(spans))
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

	// Verify test coverage attributes
	expectedAttrs := map[string]int64{
		"leeway.package.test.coverage_percentage":    85,
		"leeway.package.test.functions_with_test":    42,
		"leeway.package.test.functions_without_test": 8,
	}

	foundAttrs := make(map[string]int64)
	for _, attr := range packageSpan.Attributes {
		key := string(attr.Key)
		if strings.HasPrefix(key, "leeway.package.test.") {
			foundAttrs[key] = attr.Value.AsInt64()
		}
	}

	for key, expectedValue := range expectedAttrs {
		actualValue, found := foundAttrs[key]
		if !found {
			t.Errorf("Expected test coverage attribute '%s' not found", key)
		} else if actualValue != expectedValue {
			t.Errorf("Test coverage attribute '%s': expected %d, got %d", key, expectedValue, actualValue)
		}
	}
}

func TestOTelReporter_PhaseDurations(t *testing.T) {
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
	reporter.PackageBuildStarted(pkg, "/tmp/build")

	// Simulate phase execution with actual phase spans
	phases := []PackageBuildPhase{PackageBuildPhasePrep, PackageBuildPhaseBuild, PackageBuildPhaseTest}
	for _, phase := range phases {
		reporter.PackageBuildPhaseStarted(pkg, phase)
		time.Sleep(10 * time.Millisecond) // Simulate work
		reporter.PackageBuildPhaseFinished(pkg, phase, nil)
	}

	// Create report with phase durations
	now := time.Now()
	rep := &PackageBuildReport{
		phaseEnter: map[PackageBuildPhase]time.Time{
			PackageBuildPhasePrep:  now,
			PackageBuildPhaseBuild: now.Add(100 * time.Millisecond),
			PackageBuildPhaseTest:  now.Add(300 * time.Millisecond),
		},
		phaseDone: map[PackageBuildPhase]time.Time{
			PackageBuildPhasePrep:  now.Add(100 * time.Millisecond),
			PackageBuildPhaseBuild: now.Add(300 * time.Millisecond),
			PackageBuildPhaseTest:  now.Add(500 * time.Millisecond),
		},
		Phases: phases,
	}
	reporter.PackageBuildFinished(pkg, rep)
	reporter.BuildFinished(pkg, nil)

	// Verify spans were created
	spans := exporter.GetSpans()
	if len(spans) < 5 { // build + package + 3 phases
		t.Fatalf("Expected at least 5 spans, got %d", len(spans))
	}

	// Verify phase spans exist (durations are now in nested spans, not attributes)
	expectedPhases := []string{"prep", "build", "test"}
	foundPhases := make(map[string]bool)

	for _, span := range spans {
		if span.Name == "leeway.phase" {
			for _, attr := range span.Attributes {
				if string(attr.Key) == "leeway.phase.name" {
					phaseName := attr.Value.AsString()
					foundPhases[phaseName] = true

					// Verify span has reasonable duration
					duration := span.EndTime.Sub(span.StartTime)
					if duration < 5*time.Millisecond || duration > 100*time.Millisecond {
						t.Errorf("Phase '%s' duration %v seems unreasonable", phaseName, duration)
					}
				}
			}
		}
	}

	for _, phase := range expectedPhases {
		if !foundPhases[phase] {
			t.Errorf("Expected phase span for '%s' not found", phase)
		}
	}
}

func TestOTelReporter_PackageBuildStatusCounts(t *testing.T) {
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

	// Create multiple packages with different statuses
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

	pkg3 := &Package{
		C: &Component{
			Name: "component3",
			W: &Workspace{
				Origin: "/workspace",
			},
		},
		PackageInternal: PackageInternal{
			Name: "package3",
			Type: GenericPackage,
		},
	}

	status := map[*Package]PackageBuildStatus{
		pkg1: PackageBuilt,
		pkg2: PackageInRemoteCache,
		pkg3: PackageNotBuiltYet,
	}

	reporter.BuildStarted(pkg1, status)
	reporter.BuildFinished(pkg1, nil)

	// Verify spans were created
	spans := exporter.GetSpans()
	if len(spans) == 0 {
		t.Fatal("Expected at least one span to be created")
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

	// Verify package status counts
	expectedCounts := map[string]int64{
		"leeway.packages.total":      3,
		"leeway.packages.cached":     1,
		"leeway.packages.remote":     1,
		"leeway.packages.to_build":   1,
		"leeway.packages.downloaded": 0,
	}

	foundCounts := make(map[string]int64)
	for _, attr := range buildSpan.Attributes {
		key := string(attr.Key)
		if strings.HasPrefix(key, "leeway.packages.") {
			foundCounts[key] = attr.Value.AsInt64()
		}
	}

	for key, expectedValue := range expectedCounts {
		actualValue, found := foundCounts[key]
		if !found {
			t.Errorf("Expected package count attribute '%s' not found", key)
		} else if actualValue != expectedValue {
			t.Errorf("Package count attribute '%s': expected %d, got %d", key, expectedValue, actualValue)
		}
	}
}

func TestOTelReporter_MemoryCleanup(t *testing.T) {
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
	reporter.PackageBuildStarted(pkg, "/tmp/build")

	// Verify maps are populated
	reporter.mu.RLock()
	if len(reporter.packageSpans) != 1 {
		t.Errorf("Expected 1 package span in map, got %d", len(reporter.packageSpans))
	}
	if len(reporter.packageCtxs) != 1 {
		t.Errorf("Expected 1 package context in map, got %d", len(reporter.packageCtxs))
	}
	reporter.mu.RUnlock()

	// Finish package build
	rep := &PackageBuildReport{
		phaseEnter: make(map[PackageBuildPhase]time.Time),
		phaseDone:  make(map[PackageBuildPhase]time.Time),
		Phases:     []PackageBuildPhase{PackageBuildPhasePrep},
	}
	reporter.PackageBuildFinished(pkg, rep)

	// Verify maps are cleaned up
	reporter.mu.RLock()
	if len(reporter.packageSpans) != 0 {
		t.Errorf("Expected package spans map to be empty after PackageBuildFinished, got %d entries", len(reporter.packageSpans))
	}
	if len(reporter.packageCtxs) != 0 {
		t.Errorf("Expected package contexts map to be empty after PackageBuildFinished, got %d entries", len(reporter.packageCtxs))
	}
	reporter.mu.RUnlock()

	reporter.BuildFinished(pkg, nil)
}
