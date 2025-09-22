package slsa

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"

	slsav1 "github.com/slsa-framework/slsa-verifier/v2/verifiers"
	"github.com/slsa-framework/slsa-verifier/v2/options"
)

// Verifier handles SLSA attestation verification using Go API
type Verifier struct {
	sourceURI    string
	trustedRoots []string
}

// NewVerifier creates a new SLSA verifier instance
func NewVerifier(sourceURI string, trustedRoots []string) *Verifier {
	return &Verifier{
		sourceURI:    sourceURI,
		trustedRoots: trustedRoots,
	}
}

// VerifyArtifact verifies an artifact against its SLSA attestation using Go API
// This follows the same pattern as the official slsa-verifier CLI implementation
func (v *Verifier) VerifyArtifact(ctx context.Context, artifactPath, attestationPath string) error {
	// Read attestation file
	attestationBytes, err := os.ReadFile(attestationPath)
	if err != nil {
		return fmt.Errorf("failed to read attestation file: %w", err)
	}

	// Calculate artifact hash (required by slsa-verifier API)
	artifactHash, err := v.calculateSHA256(artifactPath)
	if err != nil {
		return fmt.Errorf("failed to calculate artifact hash: %w", err)
	}

	// Configure provenance verification options
	provenanceOpts := &options.ProvenanceOpts{
		ExpectedSourceURI: v.sourceURI,
		ExpectedDigest:    artifactHash,
	}
	
	// TODO: Integrate TrustedRoots when slsa-verifier v2 supports custom trust stores
	// Currently uses Sigstore's default trusted roots

	// Configure builder options (can be nil for basic verification)
	builderOpts := &options.BuilderOpts{}

	// Use slsa-verifier Go API directly
	_, _, err = slsav1.VerifyArtifact(ctx, attestationBytes, artifactHash, provenanceOpts, builderOpts)
	if err != nil {
		return fmt.Errorf("SLSA verification failed: %w", err)
	}

	return nil
}

// calculateSHA256 calculates the SHA256 hash of a file
func (v *Verifier) calculateSHA256(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}

// AttestationKey returns the attestation key for an artifact key
func AttestationKey(artifactKey string) string {
	return artifactKey + ".att"
}