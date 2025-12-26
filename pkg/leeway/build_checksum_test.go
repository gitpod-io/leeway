package leeway

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRecordArtifactChecksum(t *testing.T) {
	// Test checksum recording works correctly
	tmpDir := t.TempDir()
	testArtifact := filepath.Join(tmpDir, "test.tar.gz")
	err := os.WriteFile(testArtifact, []byte("test content"), 0644)
	if err != nil {
		t.Fatal(err)
	}

	ctx := &buildContext{
		InFlightChecksums: true,
		artifactChecksums: make(map[string]string),
	}

	err = ctx.recordArtifactChecksum(testArtifact)
	if err != nil {
		t.Errorf("recordArtifactChecksum failed: %v", err)
	}

	if len(ctx.artifactChecksums) != 1 {
		t.Errorf("Expected 1 checksum, got %d", len(ctx.artifactChecksums))
	}
}

func TestVerifyArtifactChecksum(t *testing.T) {
	tmpDir := t.TempDir()
	testArtifact := filepath.Join(tmpDir, "test.tar.gz")
	err := os.WriteFile(testArtifact, []byte("test content"), 0644)
	if err != nil {
		t.Fatal(err)
	}

	ctx := &buildContext{
		InFlightChecksums: true,
		artifactChecksums: make(map[string]string),
	}

	// Record initial checksum
	err = ctx.recordArtifactChecksum(testArtifact)
	if err != nil {
		t.Fatal(err)
	}

	// Verify unmodified file passes
	err = ctx.verifyArtifactChecksum(testArtifact)
	if err != nil {
		t.Errorf("Verification should pass for unmodified file: %v", err)
	}

	// Modify file to simulate TOCTU attack
	err = os.WriteFile(testArtifact, []byte("tampered content"), 0644)
	if err != nil {
		t.Fatal(err)
	}

	// Verify modified file fails with TOCTU message
	err = ctx.verifyArtifactChecksum(testArtifact)
	if err == nil {
		t.Error("Verification should fail for tampered file")
	}
	if !strings.Contains(err.Error(), "cache artifact") || !strings.Contains(err.Error(), "modified") {
		t.Errorf("Expected cache artifact modified error, got: %v", err)
	}
}

func TestInFlightChecksumsDisabled(t *testing.T) {
	ctx := &buildContext{
		InFlightChecksums: false,
		artifactChecksums: nil,
	}

	// Both operations should be no-op
	err := ctx.recordArtifactChecksum("nonexistent")
	if err != nil {
		t.Errorf("Disabled checksumming should be no-op: %v", err)
	}

	err = ctx.verifyArtifactChecksum("nonexistent")
	if err != nil {
		t.Errorf("Disabled checksumming should be no-op: %v", err)
	}
}

func TestVerifyAllArtifactChecksums(t *testing.T) {
	tmpDir := t.TempDir()

	// Create multiple test artifacts
	artifacts := []string{
		filepath.Join(tmpDir, "pkg1.tar.gz"),
		filepath.Join(tmpDir, "pkg2.tar.gz"),
	}

	ctx := &buildContext{
		InFlightChecksums: true,
		artifactChecksums: make(map[string]string),
	}

	// Record checksums for all artifacts
	for i, artifact := range artifacts {
		content := fmt.Sprintf("package %d content", i)
		err := os.WriteFile(artifact, []byte(content), 0644)
		if err != nil {
			t.Fatal(err)
		}

		err = ctx.recordArtifactChecksum(artifact)
		if err != nil {
			t.Fatal(err)
		}
	}

	// Verify all pass initially
	err := verifyAllArtifactChecksums(ctx)
	if err != nil {
		t.Errorf("All checksums should verify: %v", err)
	}

	// Tamper with one artifact
	err = os.WriteFile(artifacts[0], []byte("tampered!"), 0644)
	if err != nil {
		t.Fatal(err)
	}

	// Verification should fail
	err = verifyAllArtifactChecksums(ctx)
	if err == nil {
		t.Error("Verification should fail when artifact is tampered")
	}
	if !strings.Contains(err.Error(), "checksum verification failures") {
		t.Errorf("Expected verification failure message, got: %v", err)
	}
}
