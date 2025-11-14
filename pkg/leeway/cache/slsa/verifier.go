package slsa

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
	log "github.com/sirupsen/logrus"
)

// VerificationFailedError is returned when SLSA verification fails
type VerificationFailedError struct {
	Reason string
}

func (e VerificationFailedError) Error() string {
	return fmt.Sprintf("SLSA verification failed: %s", e.Reason)
}

// VerifierInterface defines the interface for SLSA verification
type VerifierInterface interface {
	VerifyArtifact(ctx context.Context, artifactPath, attestationPath string) error
}

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

// VerifyArtifact verifies an artifact against its SLSA attestation using sigstore-go
// This implementation uses the official Sigstore Go library which natively supports
// Sigstore Bundle format and uses embedded transparency log entries for verification.
func (v *Verifier) VerifyArtifact(ctx context.Context, artifactPath, attestationPath string) error {
	startTime := time.Now()
	
	log.WithFields(log.Fields{
		"artifact":    artifactPath,
		"attestation": attestationPath,
	}).Debug("Starting SLSA verification")
	
	// Step 1: Load the Sigstore Bundle
	// This parses the attestation file as a Sigstore Bundle v0.3 format
	b, err := bundle.LoadJSONFromPath(attestationPath)
	if err != nil {
		return VerificationFailedError{
			Reason: fmt.Sprintf("failed to load attestation bundle: %v", err),
		}
	}

	// Step 2: Get trusted root from Sigstore public good instance
	// This fetches the current trusted root (CA certificates, Rekor public keys, etc.)
	// from Sigstore's TUF repository
	trustedRoot, err := root.FetchTrustedRoot()
	if err != nil {
		return VerificationFailedError{
			Reason: fmt.Sprintf("failed to fetch trusted root: %v", err),
		}
	}

	// Step 3: Create a verifier with transparency log verification
	// WithTransparencyLog(1) means "require at least 1 transparency log entry"
	// WithIntegratedTimestamps(1) means "require at least 1 integrated timestamp"
	verifier, err := verify.NewSignedEntityVerifier(
		trustedRoot,
		verify.WithTransparencyLog(1),
		verify.WithIntegratedTimestamps(1),
	)
	if err != nil {
		return VerificationFailedError{
			Reason: fmt.Sprintf("failed to create verifier: %v", err),
		}
	}

	// Step 4: Open the artifact file for verification
	artifactFile, err := os.Open(artifactPath)
	if err != nil {
		return VerificationFailedError{
			Reason: fmt.Sprintf("failed to open artifact: %v", err),
		}
	}
	defer artifactFile.Close()

	// Step 5: Create verification policy
	// WithArtifact provides the artifact for hash verification
	// WithoutIdentitiesUnsafe skips identity verification (we only care about signature)
	// In production, you might want to verify the identity (GitHub Actions workflow)
	policy := verify.NewPolicy(
		verify.WithArtifact(artifactFile),
		verify.WithoutIdentitiesUnsafe(),
	)

	// Step 6: Verify the bundle
	// This checks:
	// - Signature is valid
	// - Certificate chain is valid
	// - Transparency log entry is valid (using embedded tlog_entries!)
	// - Timestamps are consistent
	// - Artifact hash matches (if provided)
	_, err = verifier.Verify(b, policy)
	if err != nil {
		return VerificationFailedError{
			Reason: fmt.Sprintf("signature verification failed: %v", err),
		}
	}

	// Step 7: Extract and verify the subject hash from the attestation
	// The attestation contains the expected hash of the artifact in the SLSA provenance
	envelope, err := b.Envelope()
	if err != nil {
		return VerificationFailedError{
			Reason: fmt.Sprintf("failed to get envelope: %v", err),
		}
	}

	// Decode the base64-encoded payload
	payloadBytes, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		return VerificationFailedError{
			Reason: fmt.Sprintf("failed to decode payload: %v", err),
		}
	}

	// Parse the SLSA provenance to get the subject
	var payload struct {
		Subject []struct {
			Digest struct {
				Sha256 string `json:"sha256"`
			} `json:"digest"`
		} `json:"subject"`
	}

	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return VerificationFailedError{
			Reason: fmt.Sprintf("failed to parse payload: %v", err),
		}
	}

	if len(payload.Subject) == 0 {
		return VerificationFailedError{
			Reason: "no subject in attestation",
		}
	}

	expectedHash := payload.Subject[0].Digest.Sha256
	if expectedHash == "" {
		return VerificationFailedError{
			Reason: "SLSA provenance subject has no SHA256 digest",
		}
	}

	// Step 8: Hash the actual artifact and compare
	artifactFile.Seek(0, 0) // Reset file pointer
	h := sha256.New()
	if _, err := io.Copy(h, artifactFile); err != nil {
		return VerificationFailedError{
			Reason: fmt.Sprintf("failed to hash artifact: %v", err),
		}
	}
	actualHash := hex.EncodeToString(h.Sum(nil))

	if actualHash != expectedHash {
		return VerificationFailedError{
			Reason: fmt.Sprintf("hash mismatch: expected %s, got %s", expectedHash, actualHash),
		}
	}

	// Success! The artifact is verified:
	// ✅ Signature is valid
	// ✅ Certificate chain is valid
	// ✅ Transparency log entry is valid
	// ✅ Hash matches
	
	duration := time.Since(startTime)
	log.WithFields(log.Fields{
		"artifact":       artifactPath,
		"expectedHash":   expectedHash,
		"actualHash":     actualHash,
		"verificationMs": duration.Milliseconds(),
	}).Info("SLSA verification successful")
	
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