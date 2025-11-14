package cmd

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/gitpod-io/leeway/pkg/leeway/cache"
	"github.com/gitpod-io/leeway/pkg/leeway/signing"
)

// signCacheCmd represents the sign-cache command
var signCacheCmd = &cobra.Command{
	Use:   "sign-cache --from-manifest <path>",
	Short: "Signs and uploads cache artifacts using manifest (CI use only)",
	Long: `Reads artifact paths from manifest file, generates SLSA attestations,
and uploads to remote cache with write-only credentials.

This command is designed for CI environments where build and signing are
separated for security. The build job creates a manifest of artifacts to sign,
and this command consumes that manifest to generate cryptographic attestations.

Concurrency:
  Default: 20 concurrent signing operations
  Configure via --max-signing-concurrency flag or LEEWAY_MAX_SIGNING_CONCURRENCY env var
  Valid range: 1-100 (automatically capped)

Example:
  leeway plumbing sign-cache --from-manifest artifacts-to-sign.txt
  leeway plumbing sign-cache --from-manifest artifacts.txt --dry-run
  leeway plumbing sign-cache --from-manifest artifacts.txt --max-signing-concurrency 30
  LEEWAY_MAX_SIGNING_CONCURRENCY=30 leeway plumbing sign-cache --from-manifest artifacts.txt`,
	RunE: func(cmd *cobra.Command, args []string) error {
		manifestPath, _ := cmd.Flags().GetString("from-manifest")
		dryRun, _ := cmd.Flags().GetBool("dry-run")
		
		// Get max concurrency setting (env var as default, CLI flag overrides)
		maxConcurrency, _ := cmd.Flags().GetInt("max-signing-concurrency")
		if !cmd.Flags().Changed("max-signing-concurrency") {
			if envVal := os.Getenv(EnvvarMaxSigningConcurrency); envVal != "" {
				if parsed, err := strconv.Atoi(envVal); err == nil && parsed > 0 {
					maxConcurrency = parsed
				}
			}
		}

		if manifestPath == "" {
			return fmt.Errorf("--from-manifest flag is required")
		}

		// Validate manifest file exists
		if _, err := os.Stat(manifestPath); os.IsNotExist(err) {
			return fmt.Errorf("manifest file does not exist: %s", manifestPath)
		}

		return runSignCache(cmd.Context(), manifestPath, dryRun, maxConcurrency)
	},
}

func init() {
	plumbingCmd.AddCommand(signCacheCmd)
	signCacheCmd.Flags().String("from-manifest", "", "Path to newline-separated artifact paths file")
	signCacheCmd.Flags().Bool("dry-run", false, "Log actions without signing or uploading")
	signCacheCmd.Flags().Int("max-signing-concurrency", 20, "Maximum concurrent signing operations (env: LEEWAY_MAX_SIGNING_CONCURRENCY)")
	_ = signCacheCmd.MarkFlagRequired("from-manifest")
}

// runSignCache implements the main signing logic
func runSignCache(ctx context.Context, manifestPath string, dryRun bool, maxConcurrency int) error {
	log.WithFields(log.Fields{
		"manifest": manifestPath,
		"dry_run":  dryRun,
	}).Info("Starting cache artifact signing process")

	if dryRun {
		log.Info("DRY-RUN MODE: No actual signing or uploading will occur")
	}

	// Get workspace configuration using existing Leeway patterns
	ws, err := getWorkspace()
	if err != nil {
		return fmt.Errorf("failed to get workspace: %w", err)
	}

	// Get remote cache using existing Leeway patterns
	remoteCache := getRemoteCacheFromEnv()
	if remoteCache == nil {
		return fmt.Errorf("remote cache not configured - set LEEWAY_REMOTE_CACHE_BUCKET and LEEWAY_REMOTE_CACHE_STORAGE")
	}

	log.WithFields(log.Fields{
		"workspace":  ws.Origin,
		"cache_type": fmt.Sprintf("%T", remoteCache),
	}).Info("Initialized workspace and remote cache")

	// Validate GitHub context for CI environment
	githubCtx := signing.GetGitHubContext()
	if err := githubCtx.Validate(); err != nil {
		return fmt.Errorf("invalid GitHub context - this command must run in GitHub Actions: %w", err)
	}

	shaDisplay := githubCtx.SHA
	if len(shaDisplay) > 8 {
		shaDisplay = shaDisplay[:8] + "..."
	}

	log.WithFields(log.Fields{
		"repository": githubCtx.Repository,
		"run_id":     githubCtx.RunID,
		"sha":        shaDisplay,
	}).Info("Validated GitHub Actions context")

	// Parse and validate manifest
	artifacts, err := parseManifest(manifestPath)
	if err != nil {
		return fmt.Errorf("failed to parse manifest: %w", err)
	}

	if len(artifacts) == 0 {
		log.Warn("No artifacts found in manifest")
		return nil
	}

	log.WithField("artifacts", len(artifacts)).Info("Found artifacts to sign")

	// Process artifacts with bounded concurrency to avoid overwhelming Sigstore
	// Validate and apply reasonable bounds
	if maxConcurrency < 1 {
		log.WithField("provided", maxConcurrency).Warn("maxConcurrency must be at least 1, using 1")
		maxConcurrency = 1
	} else if maxConcurrency > 100 {
		log.WithField("provided", maxConcurrency).Warn("maxConcurrency exceeds maximum, capping at 100")
		maxConcurrency = 100
	}

	log.WithField("maxConcurrency", maxConcurrency).Info("Configured signing concurrency")

	const maxAcceptableFailureRate = 0.5 // Fail command if more than 50% of artifacts fail
	semaphore := make(chan struct{}, maxConcurrency)

	var successful []string
	var failed []*signing.SigningError
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Track temporary files for cleanup
	var tempFiles []string
	defer func() {
		// Clean up all temporary files
		for _, tempFile := range tempFiles {
			if err := os.Remove(tempFile); err != nil && !os.IsNotExist(err) {
				log.WithError(err).WithField("file", tempFile).Warn("Failed to clean up temporary file")
			}
		}
	}()

	for _, artifact := range artifacts {
		wg.Add(1)
		go func(artifactPath string) {
			defer wg.Done()

			// Acquire semaphore
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			log.WithField("artifact", artifactPath).Debug("Starting artifact processing")

			if err := processArtifact(ctx, artifactPath, githubCtx, remoteCache, dryRun); err != nil {
				signingErr := signing.CategorizeError(artifactPath, err)

				mu.Lock()
				failed = append(failed, signingErr)
				mu.Unlock()

				log.WithFields(log.Fields{
					"artifact":   artifactPath,
					"error_type": signingErr.Type,
				}).WithError(err).Error("Failed to process artifact")
			} else {
				mu.Lock()
				successful = append(successful, artifactPath)
				mu.Unlock()

				log.WithField("artifact", artifactPath).Debug("Successfully processed artifact")
			}
		}(artifact)
	}

	// Wait for all goroutines to complete
	wg.Wait()

	// Report final results
	log.WithFields(log.Fields{
		"successful": len(successful),
		"failed":     len(failed),
		"total":      len(artifacts),
	}).Info("Artifact signing process completed")

	// Determine exit strategy based on failure ratio
	if len(failed) > 0 {
		failureRate := float64(len(failed)) / float64(len(artifacts))

		// Log detailed failure information
		for _, failure := range failed {
			log.WithFields(log.Fields{
				"type":     failure.Type,
				"artifact": failure.Artifact,
			}).Error(failure.Message)
		}

		if failureRate > maxAcceptableFailureRate {
			return fmt.Errorf("signing failed for %d/%d artifacts (%.1f%% failure rate)",
				len(failed), len(artifacts), failureRate*100)
		} else {
			log.WithField("failure_rate", fmt.Sprintf("%.1f%%", failureRate*100)).
				Warn("Partial signing failure - continuing with available artifacts")
		}
	}

	log.Info("Cache artifact signing process completed")
	return nil
}

// processArtifact handles signing and uploading of a single artifact using integrated SLSA signing
func processArtifact(ctx context.Context, artifactPath string, githubCtx *signing.GitHubContext, remoteCache cache.RemoteCache, dryRun bool) error {
	log.WithFields(log.Fields{
		"artifact": artifactPath,
		"dry_run":  dryRun,
	}).Debug("Processing artifact with integrated SLSA signing")

	if dryRun {
		log.WithField("artifact", artifactPath).Info("DRY-RUN: Would generate signed SLSA attestation and upload")
		return nil
	}

	// Single step: generate and sign SLSA attestation using integrated approach
	signedAttestation, err := signing.GenerateSignedSLSAAttestation(ctx, artifactPath, githubCtx)
	if err != nil {
		return fmt.Errorf("failed to generate signed attestation: %w", err)
	}

	log.WithFields(log.Fields{
		"artifact":         artifactPath,
		"artifact_name":    signedAttestation.ArtifactName,
		"checksum":         signedAttestation.Checksum[:16] + "...",
		"attestation_size": len(signedAttestation.AttestationBytes),
	}).Info("Successfully generated signed SLSA attestation")

	// Upload artifact + .att file using existing RemoteCache patterns
	uploader := signing.NewArtifactUploader(remoteCache)
	if err := uploader.UploadArtifactWithAttestation(ctx, artifactPath, signedAttestation.AttestationBytes); err != nil {
		return fmt.Errorf("failed to upload to remote cache: %w", err)
	}

	log.WithField("artifact", artifactPath).Info("Successfully uploaded signed artifact and attestation to remote cache")
	return nil
}

// parseManifest reads and validates the manifest file
func parseManifest(manifestPath string) ([]string, error) {
	log.WithField("manifest", manifestPath).Debug("Parsing manifest file")

	content, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read manifest file: %w", err)
	}

	if len(content) == 0 {
		return nil, fmt.Errorf("manifest file is empty")
	}

	// Split by newlines and filter empty lines
	lines := strings.Split(string(content), "\n")
	var artifacts []string
	var validationErrors []string

	for i, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue // Skip empty lines
		}

		// Validate artifact path exists and is readable
		if stat, err := os.Stat(line); os.IsNotExist(err) {
			validationErrors = append(validationErrors, fmt.Sprintf("line %d: artifact not found: %s", i+1, line))
			continue
		} else if err != nil {
			validationErrors = append(validationErrors, fmt.Sprintf("line %d: cannot access artifact: %s (%v)", i+1, line, err))
			continue
		} else if stat.IsDir() {
			validationErrors = append(validationErrors, fmt.Sprintf("line %d: path is a directory, not a file: %s", i+1, line))
			continue
		}

		// Validate it looks like a cache artifact (basic heuristic)
		if !strings.HasSuffix(line, ".tar.gz") && !strings.HasSuffix(line, ".tar") {
			log.WithField("artifact", line).Warn("Artifact does not have expected extension (.tar.gz or .tar)")
		}

		artifacts = append(artifacts, line)
	}

	// Report validation errors if any
	if len(validationErrors) > 0 {
		return nil, fmt.Errorf("manifest validation failed:\n%s", strings.Join(validationErrors, "\n"))
	}

	log.WithFields(log.Fields{
		"total_lines": len(lines),
		"artifacts":   len(artifacts),
	}).Debug("Successfully parsed manifest")

	return artifacts, nil
}
