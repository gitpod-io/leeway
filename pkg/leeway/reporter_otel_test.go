package leeway

import (
	"context"
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
	_ = os.Setenv("GITHUB_REF", "refs/heads/main")
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
		"github.ref":          "refs/heads/main",
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
