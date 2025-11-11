package signing

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
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
	RunID       string // GITHUB_RUN_ID
	RunNumber   string // GITHUB_RUN_NUMBER
	Actor       string // GITHUB_ACTOR
	Repository  string // GITHUB_REPOSITORY
	Ref         string // GITHUB_REF
	SHA         string // GITHUB_SHA
	ServerURL   string // GITHUB_SERVER_URL
	WorkflowRef string // GITHUB_WORKFLOW_REF
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
	
	// Extract builder ID from OIDC token to match certificate identity
	// This is critical for compatibility with reusable workflows
	builderID, err := extractBuilderIDFromOIDC(ctx, githubCtx)
	if err != nil {
		return nil, fmt.Errorf("failed to extract builder ID from OIDC token: %w", err)
	}

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
	defer func() { _ = file.Close() }()

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
		// Fetch the GitHub OIDC token for Sigstore
		idToken, err := fetchGitHubOIDCToken(ctx, "sigstore")
		if err != nil {
			return nil, &SigningError{
				Type:     ErrorTypeSigstore,
				Artifact: statement.Subject[0].Name,
				Message:  fmt.Sprintf("failed to fetch GitHub OIDC token: %v", err),
				Cause:    err,
			}
		}

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
			IDToken: idToken,
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

// extractBuilderIDFromOIDC extracts the builder ID from the GitHub OIDC token.
// This ensures the builder ID matches the certificate identity issued by Fulcio, which is
// critical for slsa-verifier compatibility, especially with reusable workflows.
//
// For reusable workflows, the OIDC token contains:
// - job_workflow_ref claim: Points to the actual executing workflow (e.g., _build.yml)
// - sub claim: May contain job_workflow_ref embedded in colon-separated format
// - workflow_ref env var: Points to the calling workflow (e.g., build-main.yml)
//
// Fulcio uses the sub claim for the certificate identity. For reusable workflows,
// the sub claim includes job_workflow_ref in the format:
// repo:OWNER/REPO:ref:REF:job_workflow_ref:OWNER/REPO/.github/workflows/WORKFLOW@REF
func extractBuilderIDFromOIDC(ctx context.Context, githubCtx *GitHubContext) (string, error) {
	// Fetch the OIDC token with sigstore audience
	idToken, err := fetchGitHubOIDCToken(ctx, "sigstore")
	if err != nil {
		return "", fmt.Errorf("failed to fetch OIDC token: %w", err)
	}

	// Parse the JWT token to extract claims
	// JWT format: header.payload.signature
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid JWT token format: expected 3 parts, got %d", len(parts))
	}

	// Decode the payload (second part)
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("failed to decode JWT payload: %w", err)
	}

	// Parse the payload JSON
	var claims map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return "", fmt.Errorf("failed to parse JWT claims: %w", err)
	}

	// Extract the sub claim (required for Fulcio certificate identity)
	sub, ok := claims["sub"].(string)
	if !ok || strings.TrimSpace(sub) == "" {
		return "", fmt.Errorf("sub claim not found or empty in OIDC token")
	}

	// Try to extract job_workflow_ref from the sub claim first
	// 
	// Context:
	// When we call sign.Bundle() with the OIDC token, the Sigstore library sends it to Fulcio (Sigstore's CA).
	// Fulcio extracts claims from the OIDC token and issues a short-lived certificate with the builder identity in the Subject Alternative Name (SAN).
	// For verification to succeed, our attestation's builder ID must match what Fulcio puts in the certificate SAN.
	//
	// TODO: Verify if GitHub embeds job_workflow_ref in the sub claim or only provides it as top-level.
	// GitHub docs show it as top-level, but we need to confirm what Fulcio actually uses. The current
	// implementation tries both approaches to ensure we match Fulcio's extraction logic.
	jobWorkflowRef := extractJobWorkflowRef(sub)
	
	// If not found in sub, try the top-level job_workflow_ref claim
	if jobWorkflowRef == "" {
		if jwfRef, ok := claims["job_workflow_ref"].(string); ok && jwfRef != "" {
			jobWorkflowRef = jwfRef
			log.WithField("job_workflow_ref", jobWorkflowRef).Debug("Using top-level job_workflow_ref claim (not found in sub)")
		}
	}
	
	if jobWorkflowRef == "" {
		return "", fmt.Errorf("job_workflow_ref not found in sub claim or top-level claims: %s", sub)
	}

	// Construct the builder ID URL
	builderID := fmt.Sprintf("%s/%s", githubCtx.ServerURL, jobWorkflowRef)
	
	log.WithFields(log.Fields{
		"sub_claim":        sub,
		"job_workflow_ref": jobWorkflowRef,
		"builder_id":       builderID,
	}).Debug("Extracted builder ID from OIDC token")

	return builderID, nil
}

// extractJobWorkflowRef extracts the job_workflow_ref from a GitHub OIDC sub claim.
// The sub claim format for reusable workflows is:
// repo:OWNER/REPO:ref:REF:job_workflow_ref:OWNER/REPO/.github/workflows/WORKFLOW@REF
//
// For direct workflows (non-reusable), the format is similar but job_workflow_ref
// points to the same workflow as workflow_ref.
func extractJobWorkflowRef(sub string) string {
	// Split by colon to parse the structured claim
	parts := strings.Split(sub, ":")
	
	// Find the job_workflow_ref field
	for i, part := range parts {
		if part == "job_workflow_ref" && i+1 < len(parts) {
			// Return everything after "job_workflow_ref:"
			// This handles the case where the workflow path contains colons
			return strings.Join(parts[i+1:], ":")
		}
	}
	
	// If no job_workflow_ref found, return empty string
	return ""
}

// fetchGitHubOIDCToken fetches an OIDC token from GitHub Actions for Sigstore.
// It uses the ACTIONS_ID_TOKEN_REQUEST_TOKEN and ACTIONS_ID_TOKEN_REQUEST_URL
// environment variables to authenticate and retrieve a JWT token with the specified audience.
func fetchGitHubOIDCToken(ctx context.Context, audience string) (string, error) {
	requestURL := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL")
	requestToken := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")

	if requestURL == "" || requestToken == "" {
		return "", fmt.Errorf("GitHub OIDC environment not configured")
	}

	// Parse the request URL
	u, err := url.Parse(requestURL)
	if err != nil {
		return "", fmt.Errorf("failed to parse ACTIONS_ID_TOKEN_REQUEST_URL: %w", err)
	}

	// Add the audience parameter
	q := u.Query()
	q.Set("audience", audience)
	u.RawQuery = q.Encode()

	// Create HTTP request with context
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", requestToken))

	// Execute request with timeout
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to fetch token: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Check response status
	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("failed to get OIDC token, status: %d, body: %s",
			resp.StatusCode, string(bodyBytes))
	}

	// Parse response
	var payload struct {
		Value string `json:"value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}

	if payload.Value == "" {
		return "", fmt.Errorf("received empty token from GitHub OIDC")
	}

	return payload.Value, nil
}
