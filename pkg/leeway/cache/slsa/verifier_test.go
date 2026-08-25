package slsa

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
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

func TestNewVerifierForRef(t *testing.T) {
	verifier := NewVerifierForRef("github.com/gitpod-io/gitpod-next", "refs/heads/main", nil)

	if verifier.sourceRef != "refs/heads/main" {
		t.Errorf("expected source ref refs/heads/main, got %q", verifier.sourceRef)
	}
}

func TestNormalizeGitHubRepositoryURI(t *testing.T) {
	tests := []struct {
		name      string
		sourceURI string
		want      string
		wantError bool
	}{
		{name: "HTTPS", sourceURI: "https://github.com/gitpod-io/gitpod-next", want: "https://github.com/gitpod-io/gitpod-next"},
		{name: "HTTPS Git suffix", sourceURI: "https://github.com/gitpod-io/gitpod-next.git", want: "https://github.com/gitpod-io/gitpod-next"},
		{name: "HTTPS Git suffix and slash", sourceURI: "https://github.com/gitpod-io/gitpod-next.git/", want: "https://github.com/gitpod-io/gitpod-next"},
		{name: "host and path", sourceURI: "github.com/gitpod-io/gitpod-next", want: "https://github.com/gitpod-io/gitpod-next"},
		{name: "SSH", sourceURI: "git@github.com:gitpod-io/gitpod-next.git", want: "https://github.com/gitpod-io/gitpod-next"},
		{name: "empty", wantError: true},
		{name: "wrong host", sourceURI: "https://example.com/gitpod-io/gitpod-next", wantError: true},
		{name: "missing repository", sourceURI: "https://github.com/gitpod-io", wantError: true},
		{name: "extra path", sourceURI: "https://github.com/gitpod-io/gitpod-next/actions", wantError: true},
		{name: "query", sourceURI: "https://github.com/gitpod-io/gitpod-next?ref=main", wantError: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizeGitHubRepositoryURI(tt.sourceURI)
			if tt.wantError {
				if err == nil {
					t.Fatalf("expected an error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("normalizeGitHubRepositoryURI failed: %v", err)
			}
			if got != tt.want {
				t.Errorf("expected %q, got %q", tt.want, got)
			}
		})
	}
}

func TestGitHubCertificateIdentity(t *testing.T) {
	identity, err := newGitHubCertificateIdentity("git@github.com:gitpod-io/gitpod-next.git", "refs/heads/main")
	if err != nil {
		t.Fatalf("newGitHubCertificateIdentity failed: %v", err)
	}

	valid := certificate.Summary{
		SubjectAlternativeName: "https://github.com/gitpod-io/gitpod-next/.github/workflows/build-main.yml@refs/heads/main",
		Extensions: certificate.Extensions{
			Issuer:              githubActionsOIDCIssuer,
			SourceRepositoryURI: "https://github.com/gitpod-io/gitpod-next",
			SourceRepositoryRef: "refs/heads/main",
		},
	}

	tests := []struct {
		name    string
		mutate  func(*certificate.Summary)
		wantErr bool
	}{
		{name: "trusted main signer"},
		{
			name: "wrong issuer",
			mutate: func(summary *certificate.Summary) {
				summary.Issuer = "https://issuer.example.com"
			},
			wantErr: true,
		},
		{
			name: "wrong repository",
			mutate: func(summary *certificate.Summary) {
				summary.SubjectAlternativeName = "https://github.com/attacker/repo/.github/workflows/build.yml@refs/heads/main"
				summary.SourceRepositoryURI = "https://github.com/attacker/repo"
			},
			wantErr: true,
		},
		{
			name: "wrong ref",
			mutate: func(summary *certificate.Summary) {
				summary.SubjectAlternativeName = "https://github.com/gitpod-io/gitpod-next/.github/workflows/build-branch.yml@refs/pull/123/merge"
				summary.SourceRepositoryRef = "refs/pull/123/merge"
			},
			wantErr: true,
		},
		{
			name: "missing repository claim",
			mutate: func(summary *certificate.Summary) {
				summary.SourceRepositoryURI = ""
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			summary := valid
			if tt.mutate != nil {
				tt.mutate(&summary)
			}
			err := identity.Verify(summary)
			if tt.wantErr && err == nil {
				t.Fatal("expected identity verification to fail")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("expected identity verification to succeed: %v", err)
			}
		})
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
	if err != nil && !strings.Contains(err.Error(), "failed to load attestation bundle") {
		t.Errorf("Expected 'failed to load attestation bundle' error, got: %v", err)
	}
}

func TestVerifier_VerifyArtifact_InvalidAttestation(t *testing.T) {
	verifier := NewVerifier("github.com/gitpod-io/gitpod-next", []string{"https://fulcio.sigstore.dev"})
	ctx := context.Background()

	// Create a temporary attestation file with invalid content
	tmpDir := t.TempDir()
	attestationFile := filepath.Join(tmpDir, "test.att")
	err := os.WriteFile(attestationFile, []byte("fake attestation"), 0644)
	if err != nil {
		t.Fatalf("Failed to create test attestation file: %v", err)
	}

	// Create a temporary artifact file
	artifactFile := filepath.Join(tmpDir, "test.tar.gz")
	err = os.WriteFile(artifactFile, []byte("fake artifact"), 0644)
	if err != nil {
		t.Fatalf("Failed to create test artifact file: %v", err)
	}

	// Test with invalid attestation
	err = verifier.VerifyArtifact(ctx, artifactFile, attestationFile)
	if err == nil {
		t.Error("Expected error for invalid attestation, got nil")
	}
	// The error should be about loading the bundle (invalid JSON)
	if err != nil && !strings.Contains(err.Error(), "failed to load attestation bundle") {
		t.Errorf("Expected 'failed to load attestation bundle' error, got: %v", err)
	}
}

// Note: Testing empty subject hash requires a valid Sigstore Bundle with proper
// signature verification, which is complex to set up in unit tests. The validation
// is in place (lines 125-127 in verifier.go) and will catch this case in production.
// Integration tests with real attestations would verify this behavior.

// Note: We cannot easily test successful SLSA verification without valid attestations
// and artifacts, which would require complex setup. In integration tests, we would
// use mock attestations or test fixtures.
