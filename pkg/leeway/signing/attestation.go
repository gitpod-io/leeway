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
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/sign"

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
	builderID := fmt.Sprintf("%s/%s", githubCtx.ServerURL, githubCtx.WorkflowRef)

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
	// Note: BuildStartedOn and BuildFinishedOn are set to nil because sign-cache runs
	// in a separate job after the build completes, and we don't have access to the
	// actual build times. Using signing time or artifact mtime would be misleading.
	pred.Metadata = &slsa.ProvenanceMetadata{
		BuildInvocationID: githubCtx.RunID,
		BuildStartedOn:    nil,
		BuildFinishedOn:   nil,
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

	// Create ephemeral keypair for signing
	keypair, err := sign.NewEphemeralKeypair(nil)
	if err != nil {
		return nil, &SigningError{
			Type:     ErrorTypeSigstore,
			Artifact: statement.Subject[0].Name,
			Message:  fmt.Sprintf("failed to create ephemeral keypair: %v", err),
			Cause:    err,
		}
	}

	// Create DSSE content for SLSA attestation (in-toto format)
	content := &sign.DSSEData{
		Data:        payload,
		PayloadType: "application/vnd.in-toto+json",
	}

	// Get trusted root from Sigstore TUF
	trustedRoot, err := root.FetchTrustedRoot()
	if err != nil {
		return nil, &SigningError{
			Type:     ErrorTypeSigstore,
			Artifact: statement.Subject[0].Name,
			Message:  fmt.Sprintf("failed to fetch trusted root: %v", err),
			Cause:    err,
		}
	}

	// Get signing config from Sigstore TUF
	signingConfig, err := root.FetchSigningConfig()
	if err != nil {
		return nil, &SigningError{
			Type:     ErrorTypeSigstore,
			Artifact: statement.Subject[0].Name,
			Message:  fmt.Sprintf("failed to fetch signing config: %v", err),
			Cause:    err,
		}
	}

	// Create bundle options
	bundleOpts := sign.BundleOptions{
		TrustedRoot: trustedRoot,
		Context:     ctx,
	}

	// Configure Fulcio for GitHub OIDC if we have a token
	if os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN") != "" {
		// Select Fulcio service from signing config
		fulcioService, err := root.SelectService(signingConfig.FulcioCertificateAuthorityURLs(), sign.FulcioAPIVersions, time.Now())
		if err != nil {
			return nil, &SigningError{
				Type:     ErrorTypeSigstore,
				Artifact: statement.Subject[0].Name,
				Message:  fmt.Sprintf("failed to select Fulcio service: %v", err),
				Cause:    err,
			}
		}

		fulcioOpts := &sign.FulcioOptions{
			BaseURL: fulcioService.URL,
			Timeout: 30 * time.Second,
			Retries: 1,
		}
		bundleOpts.CertificateProvider = sign.NewFulcio(fulcioOpts)
		bundleOpts.CertificateProviderOptions = &sign.CertificateProviderOptions{
			// Let sigstore-go automatically handle GitHub OIDC
			// It will use ACTIONS_ID_TOKEN_REQUEST_TOKEN/URL automatically
		}

		// Configure Rekor transparency log
		rekorServices, err := root.SelectServices(signingConfig.RekorLogURLs(),
			signingConfig.RekorLogURLsConfig(), sign.RekorAPIVersions, time.Now())
		if err != nil {
			return nil, &SigningError{
				Type:     ErrorTypeSigstore,
				Artifact: statement.Subject[0].Name,
				Message:  fmt.Sprintf("failed to select Rekor services: %v", err),
				Cause:    err,
			}
		}

		for _, rekorService := range rekorServices {
			rekorOpts := &sign.RekorOptions{
				BaseURL: rekorService.URL,
				Timeout: 90 * time.Second,
				Retries: 1,
				Version: rekorService.MajorAPIVersion,
			}
			bundleOpts.TransparencyLogs = append(bundleOpts.TransparencyLogs, sign.NewRekor(rekorOpts))
		}
	}

	// Sign and create bundle
	signedBundle, err := sign.Bundle(content, keypair, bundleOpts)
	if err != nil {
		return nil, &SigningError{
			Type:     ErrorTypeSigstore,
			Artifact: statement.Subject[0].Name,
			Message:  fmt.Sprintf("failed to sign with Sigstore: %v", err),
			Cause:    err,
		}
	}

	// Convert to bytes for .att file format
	bundleBytes, err := json.Marshal(signedBundle)
	if err != nil {
		return nil, &SigningError{
			Type:     ErrorTypeSigstore,
			Artifact: statement.Subject[0].Name,
			Message:  fmt.Sprintf("failed to marshal signed bundle: %v", err),
			Cause:    err,
		}
	}

	log.WithFields(log.Fields{
		"artifact":    statement.Subject[0].Name,
		"bundle_size": len(bundleBytes),
	}).Info("Successfully signed SLSA attestation with Sigstore")

	return bundleBytes, nil
}

// validateSigstoreEnvironment checks if the environment is properly configured for keyless signing
func validateSigstoreEnvironment() error {
	// Check for GitHub OIDC token (this is the key requirement)
	if os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN") == "" {
		return &SigningError{
			Type:     ErrorTypeValidation,
			Artifact: "",
			Message:  "ACTIONS_ID_TOKEN_REQUEST_TOKEN not found - ensure 'permissions: id-token: write' is set in GitHub Actions",
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

	// Verify we're in GitHub Actions environment
	if os.Getenv("GITHUB_ACTIONS") != "true" {
		return &SigningError{
			Type:     ErrorTypeValidation,
			Artifact: "",
			Message:  "not running in GitHub Actions environment",
			Cause:    nil,
		}
	}

	log.Debug("Sigstore environment validation passed")
	return nil
}