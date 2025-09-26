package signing

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gitpod-io/leeway/pkg/leeway/cache"
	"github.com/gitpod-io/leeway/pkg/leeway/cache/remote"
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

	// Check if we have an S3 cache (most common case)
	if s3Cache, ok := u.remoteCache.(*remote.S3Cache); ok {
		return u.uploadToS3Cache(ctx, s3Cache, artifactPath, attestationBytes, artifactKey, attestationKey)
	}

	// For other cache types, we'll need to implement alternative approaches
	return fmt.Errorf("unsupported remote cache type: %T", u.remoteCache)
}

// uploadToS3Cache handles uploading to S3 cache specifically
func (u *ArtifactUploader) uploadToS3Cache(ctx context.Context, s3Cache *remote.S3Cache, artifactPath string, attestationBytes []byte, artifactKey, attestationKey string) error {
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

	// Upload artifact first
	if err := u.uploadFileToS3(ctx, s3Cache, artifactPath, artifactKey); err != nil {
		return fmt.Errorf("failed to upload artifact: %w", err)
	}

	// Upload .att file
	if err := u.uploadFileToS3(ctx, s3Cache, attestationPath, attestationKey); err != nil {
		return fmt.Errorf("failed to upload .att file: %w", err)
	}

	log.WithFields(log.Fields{
		"artifact":     artifactPath,
		"artifact_key": artifactKey,
		"att_key":      attestationKey,
	}).Info("Successfully uploaded artifact and .att file")

	return nil
}

// uploadFileToS3 uploads a single file to S3 cache
func (u *ArtifactUploader) uploadFileToS3(ctx context.Context, s3Cache *remote.S3Cache, filePath, key string) error {
	// We need to access the underlying S3Storage, but it's not exported
	// For now, we'll use a workaround by creating a mock package and using the existing Upload method
	
	// Create a mock package that represents our file
	mockPkg := &mockCachePackage{
		version:  key,
		fullName: strings.TrimSuffix(key, filepath.Ext(key)),
		filePath: filePath,
	}

	// Create a mock local cache that returns our file path
	mockLocalCache := &mockLocalCache{
		packages: map[string]string{
			mockPkg.FullName(): filePath,
		},
	}

	// Use the existing Upload method
	return s3Cache.Upload(ctx, mockLocalCache, []cache.Package{mockPkg})
}

// mockCachePackage implements cache.Package for individual file uploads
type mockCachePackage struct {
	version  string
	fullName string
	filePath string
}

func (m *mockCachePackage) Version() (string, error) {
	return m.version, nil
}

func (m *mockCachePackage) FullName() string {
	return m.fullName
}

// mockLocalCache implements cache.LocalCache for individual file uploads
type mockLocalCache struct {
	packages map[string]string
}

func (m *mockLocalCache) Location(pkg cache.Package) (path string, exists bool) {
	path, exists = m.packages[pkg.FullName()]
	return path, exists
}