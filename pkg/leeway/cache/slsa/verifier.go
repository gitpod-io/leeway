package slsa

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
	log "github.com/sirupsen/logrus"
)

const githubActionsOIDCIssuer = "https://token.actions.githubusercontent.com"

var validGitHubRepositoryComponent = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

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
	sourceRef    string
	trustedRoots []string
}

// NewVerifier creates a new SLSA verifier instance
func NewVerifier(sourceURI string, trustedRoots []string) *Verifier {
	return NewVerifierForRef(sourceURI, "", trustedRoots)
}

// NewVerifierForRef creates a verifier restricted to an optional source ref.
func NewVerifierForRef(sourceURI, sourceRef string, trustedRoots []string) *Verifier {
	return &Verifier{
		sourceURI:    sourceURI,
		sourceRef:    sourceRef,
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
	verifier, err := verify.NewVerifier(
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
	defer func() {
		if closeErr := artifactFile.Close(); closeErr != nil {
			log.WithError(closeErr).Warn("Failed to close artifact file")
		}
	}()

	// Step 5: Create verification policy. The certificate identity binds the
	// signature to the configured GitHub repository and optional source ref.
	identity, err := newGitHubCertificateIdentity(v.sourceURI, v.sourceRef)
	if err != nil {
		return VerificationFailedError{
			Reason: fmt.Sprintf("invalid certificate identity policy: %v", err),
		}
	}

	policy := verify.NewPolicy(
		verify.WithArtifact(artifactFile),
		verify.WithCertificateIdentity(identity),
	)

	// Step 6: Verify the bundle
	// This checks:
	// - Signature is valid
	// - Certificate chain is valid
	// - Transparency log entry is valid (using embedded tlog_entries!)
	// - Timestamps are consistent
	// - Artifact hash matches (if provided)
	// - Certificate identity matches the configured repository and source ref
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
	// Reset file pointer to beginning for hashing
	if _, err := artifactFile.Seek(0, 0); err != nil {
		return VerificationFailedError{
			Reason: fmt.Sprintf("failed to reset artifact file pointer: %v", err),
		}
	}

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

func newGitHubCertificateIdentity(sourceURI, sourceRef string) (verify.CertificateIdentity, error) {
	repositoryURI, err := normalizeGitHubRepositoryURI(sourceURI)
	if err != nil {
		return verify.CertificateIdentity{}, err
	}

	if sourceRef != "" && !strings.HasPrefix(sourceRef, "refs/") {
		return verify.CertificateIdentity{}, fmt.Errorf("source ref must start with refs/")
	}

	refPattern := `[^@]+`
	if sourceRef != "" {
		refPattern = regexp.QuoteMeta(sourceRef)
	}
	sanPattern := fmt.Sprintf(`^%s/\.github/workflows/[^/@]+@%s$`, regexp.QuoteMeta(repositoryURI), refPattern)

	sanMatcher, err := verify.NewSANMatcher("", sanPattern)
	if err != nil {
		return verify.CertificateIdentity{}, fmt.Errorf("cannot create certificate SAN matcher: %w", err)
	}
	issuerMatcher, err := verify.NewIssuerMatcher(githubActionsOIDCIssuer, "")
	if err != nil {
		return verify.CertificateIdentity{}, fmt.Errorf("cannot create certificate issuer matcher: %w", err)
	}

	return verify.NewCertificateIdentity(sanMatcher, issuerMatcher, certificate.Extensions{
		SourceRepositoryURI: repositoryURI,
		SourceRepositoryRef: sourceRef,
	})
}

func normalizeGitHubRepositoryURI(sourceURI string) (string, error) {
	raw := strings.TrimSpace(sourceURI)
	if raw == "" {
		return "", fmt.Errorf("source URI is empty")
	}

	if strings.HasPrefix(raw, "git@github.com:") {
		raw = "https://github.com/" + strings.TrimPrefix(raw, "git@github.com:")
	} else if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}

	parsed, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("cannot parse source URI: %w", err)
	}
	if !strings.EqualFold(parsed.Hostname(), "github.com") {
		return "", fmt.Errorf("source URI must identify a github.com repository")
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("source URI must not contain a query or fragment")
	}

	repositoryPath := strings.TrimSuffix(strings.Trim(parsed.Path, "/"), ".git")
	parts := strings.Split(repositoryPath, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", fmt.Errorf("source URI must contain an owner and repository")
	}
	if !validGitHubRepositoryComponent.MatchString(parts[0]) || !validGitHubRepositoryComponent.MatchString(parts[1]) {
		return "", fmt.Errorf("source URI contains an invalid owner or repository")
	}

	return "https://github.com/" + strings.Join(parts, "/"), nil
}

// calculateSHA256 calculates the SHA256 hash of a file
func (v *Verifier) calculateSHA256(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			log.WithError(closeErr).Warn("Failed to close file")
		}
	}()

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
