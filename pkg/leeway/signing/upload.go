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

		// Check if attestation also exists
		attestationExists, err := u.remoteCache.HasFile(ctx, attestationKey)
		if err != nil {
			log.WithError(err).WithField("key", attestationKey).Warn("Failed to check if attestation exists, will attempt upload")
			attestationExists = false // Assume it doesn't exist and try to upload
		}

		if attestationExists {
			// Both artifact and attestation exist, but still check SBOM files
			log.WithFields(log.Fields{
				"artifact":     artifactPath,
				"artifact_key": artifactKey,
				"att_key":      attestationKey,
			}).Info("Skipping artifact and attestation upload (already exist)")

			// Still upload SBOM files if missing
			u.uploadSBOMFiles(ctx, artifactPath, artifactKey)
			return nil
		}

		// Artifact exists but attestation missing, upload attestation only
		log.WithFields(log.Fields{
			"artifact":     artifactPath,
			"artifact_key": artifactKey,
			"att_key":      attestationKey,
		}).Info("Artifact exists but attestation missing, uploading attestation only")

		if err := u.remoteCache.UploadFile(ctx, attestationPath, attestationKey); err != nil {
			return fmt.Errorf("failed to upload attestation: %w", err)
		}

		log.WithFields(log.Fields{
			"artifact":     artifactPath,
			"artifact_key": artifactKey,
			"att_key":      attestationKey,
		}).Info("Successfully uploaded attestation")

		// Also upload SBOM files if missing
		u.uploadSBOMFiles(ctx, artifactPath, artifactKey)
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

	// Upload SBOM files if they exist (non-blocking - failures are logged but don't fail the upload)
	u.uploadSBOMFiles(ctx, artifactPath, artifactKey)

	return nil
}

// uploadSBOMFiles uploads SBOM sidecar files alongside the artifact.
// This is a non-blocking operation - failures are logged but don't fail the upload.
func (u *ArtifactUploader) uploadSBOMFiles(ctx context.Context, artifactPath, artifactKey string) {
	// SBOM file extensions - must match pkg/leeway/sbom.go constants
	sbomExtensions := []string{
		".sbom.cdx.json",  // CycloneDX format
		".sbom.spdx.json", // SPDX format
		".sbom.json",      // Syft native format
	}

	for _, ext := range sbomExtensions {
		sbomPath := artifactPath + ext
		sbomKey := artifactKey + ext

		// Check if SBOM file exists locally
		if _, err := os.Stat(sbomPath); os.IsNotExist(err) {
			log.WithFields(log.Fields{
				"path": sbomPath,
			}).Debug("SBOM file not found locally, skipping upload")
			continue
		}

		// Check if SBOM already exists in remote cache
		exists, err := u.remoteCache.HasFile(ctx, sbomKey)
		if err != nil {
			log.WithError(err).WithField("key", sbomKey).Warn("Failed to check if SBOM exists, will attempt upload")
			exists = false
		}

		if exists {
			log.WithFields(log.Fields{
				"key": sbomKey,
			}).Debug("SBOM file already exists in remote cache, skipping upload")
			continue
		}

		// Upload SBOM file
		if err := u.remoteCache.UploadFile(ctx, sbomPath, sbomKey); err != nil {
			log.WithError(err).WithFields(log.Fields{
				"key":  sbomKey,
				"path": sbomPath,
			}).Warn("Failed to upload SBOM file to remote cache")
			continue
		}

		log.WithFields(log.Fields{
			"key": sbomKey,
		}).Info("Successfully uploaded SBOM file to remote cache")
	}
}
