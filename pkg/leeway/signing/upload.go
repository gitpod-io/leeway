package signing

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/gitpod-io/leeway/pkg/leeway/cache"
	log "github.com/sirupsen/logrus"
)

// ArtifactUploader handles uploading signed artifacts and attestations to remote cache
type ArtifactUploader struct {
	remoteCache cache.RemoteCache
}

// NewArtifactUploader creates a new artifact uploader
func NewArtifactUploader(remoteCache cache.RemoteCache) *ArtifactUploader {
	return &ArtifactUploader{
		remoteCache: remoteCache,
	}
}

// UploadArtifactWithAttestation uploads both the artifact and its .att file to remote cache
func (u *ArtifactUploader) UploadArtifactWithAttestation(ctx context.Context, artifactPath string, attestationBytes []byte) error {
	// Validate inputs
	if artifactPath == "" {
		return &SigningError{
			Type:    ErrorTypeValidation,
			Message: "artifact path cannot be empty",
		}
	}
	if len(attestationBytes) == 0 {
		return &SigningError{
			Type:    ErrorTypeValidation,
			Message: "attestation bytes cannot be empty",
		}
	}

	// Check artifact exists before creating temp file (fail fast)
	if _, err := os.Stat(artifactPath); err != nil {
		return &SigningError{
			Type:     ErrorTypeFileSystem,
			Artifact: artifactPath,
			Message:  fmt.Sprintf("artifact file not accessible: %v", err),
			Cause:    err,
		}
	}

	// Extract artifact name for key generation
	artifactName := filepath.Base(artifactPath)

	// Generate cache keys following existing patterns
	artifactKey := artifactName
	attestationKey := artifactName + ".att"

	log.WithFields(log.Fields{
		"artifact":     artifactPath,
		"artifact_key": artifactKey,
		"att_key":      attestationKey,
	}).Debug("Preparing to upload signed artifact and attestation")

	// Create temporary file for the .att file
	tmpDir := os.TempDir()
	attestationPath := filepath.Join(tmpDir, fmt.Sprintf("attestation-%d.att", time.Now().UnixNano()))
	defer func() {
		if err := os.Remove(attestationPath); err != nil && !os.IsNotExist(err) {
			log.WithError(err).WithField("file", attestationPath).Warn("Failed to clean up temporary attestation file")
		}
	}()

	// Write .att file to temporary location
	if err := os.WriteFile(attestationPath, attestationBytes, 0644); err != nil {
		return &SigningError{
			Type:     ErrorTypeFileSystem,
			Artifact: artifactPath,
			Message:  fmt.Sprintf("failed to write .att file: %v", err),
			Cause:    err,
		}
	}

	// Check context before upload
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("context cancelled before upload: %w", err)
	}

	// Check if artifact already exists in remote cache
	// Only upload if it doesn't exist (avoid re-uploading downloaded artifacts)
	artifactExists, err := u.remoteCache.HasFile(ctx, artifactKey)
	if err != nil {
		log.WithError(err).WithField("key", artifactKey).Warn("Failed to check if artifact exists, will attempt upload")
		artifactExists = false // Assume it doesn't exist and try to upload
	}

	if artifactExists {
		log.WithFields(log.Fields{
			"artifact":     artifactPath,
			"artifact_key": artifactKey,
		}).Info("Artifact already exists in remote cache, skipping upload")

		// Also skip attestation upload - the existing artifact already has an attestation
		// Uploading a new attestation for a different local artifact would cause verification failures
		log.WithFields(log.Fields{
			"artifact":     artifactPath,
			"artifact_key": artifactKey,
			"att_key":      attestationKey,
		}).Info("Skipping attestation upload (artifact already exists with attestation)")
		return nil
	}

	// Upload artifact (only if it doesn't exist)
	if err := u.remoteCache.UploadFile(ctx, artifactPath, artifactKey); err != nil {
		return fmt.Errorf("failed to upload artifact: %w", err)
	}
	log.WithFields(log.Fields{
		"artifact":     artifactPath,
		"artifact_key": artifactKey,
	}).Info("Successfully uploaded artifact to remote cache")

	// Check context between uploads
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("context cancelled between uploads: %w", err)
	}

	// Upload attestation file (only if artifact was also uploaded)
	if err := u.remoteCache.UploadFile(ctx, attestationPath, attestationKey); err != nil {
		return fmt.Errorf("failed to upload .att file: %w", err)
	}

	log.WithFields(log.Fields{
		"artifact":     artifactPath,
		"artifact_key": artifactKey,
		"att_key":      attestationKey,
	}).Info("Successfully uploaded attestation file")

	return nil
}
