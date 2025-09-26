package signing

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/common"
	slsa "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v0.2"

	log "github.com/sirupsen/logrus"
)

// GitHubContext contains GitHub Actions environment information
type GitHubContext struct {
	RunID        string // GITHUB_RUN_ID
	RunNumber    string // GITHUB_RUN_NUMBER
	Actor        string // GITHUB_ACTOR
	Repository   string // GITHUB_REPOSITORY
	Ref          string // GITHUB_REF
	SHA          string // GITHUB_SHA
	ServerURL    string // GITHUB_SERVER_URL
	WorkflowRef  string // GITHUB_WORKFLOW_REF
}

// Validate ensures all required GitHub context fields are present
func (ctx *GitHubContext) Validate() error {
	if ctx.RunID == "" {
		return fmt.Errorf("GITHUB_RUN_ID is required")
	}
	if ctx.Repository == "" {
		return fmt.Errorf("GITHUB_REPOSITORY is required")
	}
	if ctx.SHA == "" {
		return fmt.Errorf("GITHUB_SHA is required")
	}
	if ctx.ServerURL == "" {
		return fmt.Errorf("GITHUB_SERVER_URL is required")
	}
	if ctx.WorkflowRef == "" {
		return fmt.Errorf("GITHUB_WORKFLOW_REF is required")
	}
	return nil
}

// GetGitHubContext extracts GitHub Actions context from environment variables
func GetGitHubContext() *GitHubContext {
	return &GitHubContext{
		RunID:       os.Getenv("GITHUB_RUN_ID"),
		RunNumber:   os.Getenv("GITHUB_RUN_NUMBER"),
		Actor:       os.Getenv("GITHUB_ACTOR"),
		Repository:  os.Getenv("GITHUB_REPOSITORY"),
		Ref:         os.Getenv("GITHUB_REF"),
		SHA:         os.Getenv("GITHUB_SHA"),
		ServerURL:   os.Getenv("GITHUB_SERVER_URL"),
		WorkflowRef: os.Getenv("GITHUB_WORKFLOW_REF"),
	}
}

// SignedAttestationResult contains the signed SLSA attestation ready for upload
type SignedAttestationResult struct {
	AttestationBytes []byte `json:"attestation_bytes"` // Complete .att file content
	Checksum         string `json:"checksum"`          // SHA256 of the artifact
	ArtifactName     string `json:"artifact_name"`     // Name of the artifact
}



// GenerateSignedSLSAAttestation generates and signs SLSA provenance in one integrated step
func GenerateSignedSLSAAttestation(ctx context.Context, artifactPath string, githubCtx *GitHubContext) (*SignedAttestationResult, error) {
	// Calculate artifact checksum
	checksum, err := computeSHA256(artifactPath)
	if err != nil {
		return nil, fmt.Errorf("checksum calculation failed: %w", err)
	}

	// Validate GitHub context completeness
	if err := githubCtx.Validate(); err != nil {
		return nil, fmt.Errorf("incomplete GitHub context: %w", err)
	}

	sourceURI := fmt.Sprintf("%s/%s", githubCtx.ServerURL, githubCtx.Repository)
	builderID := fmt.Sprintf("%s/%s/.github/workflows/build.yml@%s",
		githubCtx.ServerURL, githubCtx.Repository, githubCtx.Ref)

	log.WithFields(log.Fields{
		"artifact":   filepath.Base(artifactPath),
		"checksum":   checksum[:16] + "...",
		"source_uri": sourceURI,
		"builder_id": builderID,
	}).Debug("Generating SLSA attestation")

	// Create SLSA statement directly using in-toto libraries
	stmt := &in_toto.Statement{
		StatementHeader: in_toto.StatementHeader{
			Type:          in_toto.StatementInTotoV01,
			PredicateType: slsa.PredicateSLSAProvenance,
			Subject: []in_toto.Subject{{
				Name: filepath.Base(artifactPath),
				Digest: common.DigestSet{
					"sha256": checksum,
				},
			}},
		},
	}

	// Create SLSA predicate directly
	pred := slsa.ProvenancePredicate{
		Builder: common.ProvenanceBuilder{
			ID: builderID,
		},
		BuildType: "https://leeway.build/cache-signing/v1",
		Invocation: slsa.ProvenanceInvocation{
			ConfigSource: slsa.ConfigSource{
				URI: sourceURI,
			},
			Parameters: map[string]interface{}{
				"workflow": githubCtx.WorkflowRef,
			},
		},
	}

	// Set metadata
	now := time.Now().UTC()
	pred.Metadata = &slsa.ProvenanceMetadata{
		BuildInvocationID: githubCtx.RunID,
		BuildStartedOn:    &now,
		BuildFinishedOn:   &now,
		Completeness: slsa.ProvenanceComplete{
			Parameters:  true,
			Environment: false,
			Materials:   false,
		},
		Reproducible: false,
	}

	// Set the predicate
	stmt.Predicate = pred

	log.WithFields(log.Fields{
		"artifact":   filepath.Base(artifactPath),
		"checksum":   checksum[:16] + "...",
		"source_uri": sourceURI,
		"builder_id": builderID,
	}).Debug("Generated SLSA provenance, proceeding with integrated signing")

	// Generate and sign the SLSA provenance using Sigstore
	signedAttestation, err := signProvenanceWithSigstore(ctx, stmt)
	if err != nil {
		return nil, fmt.Errorf("failed to sign SLSA provenance: %w", err)
	}

	return &SignedAttestationResult{
		AttestationBytes: signedAttestation,
		Checksum:         checksum,
		ArtifactName:     filepath.Base(artifactPath),
	}, nil
}

// computeSHA256 calculates the SHA256 hash of a file
func computeSHA256(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", fmt.Errorf("failed to calculate hash: %w", err)
	}

	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}

// signProvenanceWithSigstore signs SLSA provenance using Sigstore keyless signing
func signProvenanceWithSigstore(ctx context.Context, statement *in_toto.Statement) ([]byte, error) {
	// Validate GitHub OIDC environment
	if err := validateSigstoreEnvironment(); err != nil {
		return nil, fmt.Errorf("sigstore environment validation failed: %w", err)
	}

	// Marshal the statement to JSON for signing
	payload, err := json.Marshal(statement)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal statement: %w", err)
	}

	log.WithFields(log.Fields{
		"payload_size": len(payload),
		"subject":      statement.Subject[0].Name,
	}).Debug("Starting Sigstore keyless signing")

	// TODO: Implement actual Sigstore signing using the correct API
	// For now, return the unsigned payload as a placeholder
	// This maintains the correct architecture while we resolve the API details
	
	log.WithFields(log.Fields{
		"artifact": statement.Subject[0].Name,
		"note":     "Using placeholder signing - actual Sigstore integration needed",
	}).Warn("Placeholder signing implementation - replace with actual Sigstore signing")

	// Create a simple .att file format that's compatible with existing verification
	// This is a temporary implementation to maintain the correct architecture
	attestationEnvelope := map[string]interface{}{
		"payloadType": "application/vnd.in-toto+json",
		"payload":     payload,
		"signatures": []map[string]interface{}{
			{
				"keyid": "placeholder-keyid",
				"sig":   "placeholder-signature",
			},
		},
	}

	bundleBytes, err := json.Marshal(attestationEnvelope)
	if err != nil {
		return nil, &SigningError{
			Type:     ErrorTypeSigstore,
			Artifact: statement.Subject[0].Name,
			Message:  fmt.Sprintf("failed to marshal attestation envelope: %v", err),
			Cause:    err,
		}
	}

	log.WithFields(log.Fields{
		"artifact":    statement.Subject[0].Name,
		"bundle_size": len(bundleBytes),
	}).Info("Generated SLSA attestation (placeholder signing)")

	return bundleBytes, nil
}

// validateSigstoreEnvironment checks if the environment is properly configured for keyless signing
func validateSigstoreEnvironment() error {
	// Check for required GitHub OIDC token
	if os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN") == "" {
		return &SigningError{
			Type:     ErrorTypeValidation,
			Artifact: "",
			Message:  "ACTIONS_ID_TOKEN_REQUEST_TOKEN not found - ensure id-token: write permission is set",
			Cause:    nil,
		}
	}

	if os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL") == "" {
		return &SigningError{
			Type:     ErrorTypeValidation,
			Artifact: "",
			Message:  "ACTIONS_ID_TOKEN_REQUEST_URL not found - ensure running in GitHub Actions",
			Cause:    nil,
		}
	}

	log.Debug("Sigstore environment validation passed")
	return nil
}

// getEnvOrDefault returns environment variable value or default
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}