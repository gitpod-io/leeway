package slsa

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewVerifier(t *testing.T) {
	sourceURI := "github.com/gitpod-io/gitpod-next"
	trustedRoots := []string{"https://fulcio.sigstore.dev"}

	verifier := NewVerifier(sourceURI, trustedRoots)

	if verifier.sourceURI != sourceURI {
		t.Errorf("Expected sourceURI %s, got %s", sourceURI, verifier.sourceURI)
	}

	if len(verifier.trustedRoots) != len(trustedRoots) {
		t.Errorf("Expected %d trusted roots, got %d", len(trustedRoots), len(verifier.trustedRoots))
	}

	if verifier.trustedRoots[0] != trustedRoots[0] {
		t.Errorf("Expected trusted root %s, got %s", trustedRoots[0], verifier.trustedRoots[0])
	}
}

func TestAttestationKey(t *testing.T) {
	tests := []struct {
		name        string
		artifactKey string
		expected    string
	}{
		{
			name:        "tar.gz artifact",
			artifactKey: "v1.2.3.tar.gz",
			expected:    "v1.2.3.tar.gz.att",
		},
		{
			name:        "tar artifact",
			artifactKey: "v1.2.3.tar",
			expected:    "v1.2.3.tar.att",
		},
		{
			name:        "simple version",
			artifactKey: "v1.0.0",
			expected:    "v1.0.0.att",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := AttestationKey(tt.artifactKey)
			if result != tt.expected {
				t.Errorf("AttestationKey(%s) = %s, expected %s", tt.artifactKey, result, tt.expected)
			}
		})
	}
}

func TestVerifier_calculateSHA256(t *testing.T) {
	// Create a temporary file with known content
	// We test the exact hash to ensure our SHA256 calculation is correct
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.txt")
	testContent := "Hello, SLSA verification!"

	err := os.WriteFile(testFile, []byte(testContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	verifier := NewVerifier("test-uri", []string{})
	hash, err := verifier.calculateSHA256(testFile)
	if err != nil {
		t.Fatalf("calculateSHA256 failed: %v", err)
	}

	// Verify the exact SHA256 hash - this is deterministic and should always match
	expected := "ee65dc2d86a19ac262729eb6ebd30b7c8b61b459aa68d84704cb824e929b8d84"
	if hash != expected {
		t.Errorf("Expected hash %s, got %s", expected, hash)
	}

	// Also verify it's the correct length (redundant but good for clarity)
	if len(hash) != 64 {
		t.Errorf("Expected hash length 64, got %d", len(hash))
	}
}

func TestVerifier_calculateSHA256_NonExistentFile(t *testing.T) {
	verifier := NewVerifier("test-uri", []string{})
	_, err := verifier.calculateSHA256("/non/existent/file")
	if err == nil {
		t.Error("Expected error for non-existent file, got nil")
	}
}

func TestVerifier_VerifyArtifact_MissingFiles(t *testing.T) {
	verifier := NewVerifier("github.com/gitpod-io/gitpod-next", []string{"https://fulcio.sigstore.dev"})
	ctx := context.Background()

	// Test with missing attestation file
	err := verifier.VerifyArtifact(ctx, "/non/existent/artifact", "/non/existent/attestation")
	if err == nil {
		t.Error("Expected error for missing attestation file, got nil")
	}
	if err != nil && !strings.Contains(err.Error(), "failed to read attestation file") {
		t.Errorf("Expected 'failed to read attestation file' error, got: %v", err)
	}
}

func TestVerifier_VerifyArtifact_MissingArtifact(t *testing.T) {
	verifier := NewVerifier("github.com/gitpod-io/gitpod-next", []string{"https://fulcio.sigstore.dev"})
	ctx := context.Background()

	// Create a temporary attestation file
	tmpDir := t.TempDir()
	attestationFile := filepath.Join(tmpDir, "test.att")
	err := os.WriteFile(attestationFile, []byte("fake attestation"), 0644)
	if err != nil {
		t.Fatalf("Failed to create test attestation file: %v", err)
	}

	// Test with missing artifact file
	err = verifier.VerifyArtifact(ctx, "/non/existent/artifact", attestationFile)
	if err == nil {
		t.Error("Expected error for missing artifact file, got nil")
	}
	if err != nil && !strings.Contains(err.Error(), "failed to calculate artifact hash") {
		t.Errorf("Expected 'failed to calculate artifact hash' error, got: %v", err)
	}
}

// Note: We cannot easily test successful SLSA verification without valid attestations
// and artifacts, which would require complex setup. In integration tests, we would
// use mock attestations or test fixtures.