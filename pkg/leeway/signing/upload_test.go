package signing

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/gitpod-io/leeway/pkg/leeway/cache"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Mock remote cache for testing
type mockRemoteCacheUpload struct {
	uploadedFiles map[string][]byte
	uploadErrors  map[string]error
	mu            sync.Mutex
}

func (m *mockRemoteCacheUpload) Upload(ctx context.Context, src cache.LocalCache, pkgs []cache.Package) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, pkg := range pkgs {
		// Check if this package should fail
		if err, exists := m.uploadErrors[pkg.FullName()]; exists {
			return err
		}

		// Simulate successful upload by storing the package name
		if m.uploadedFiles == nil {
			m.uploadedFiles = make(map[string][]byte)
		}

		// Get the file content from local cache
		if path, exists := src.Location(pkg); exists {
			if content, err := os.ReadFile(path); err == nil {
				m.uploadedFiles[pkg.FullName()] = content
			}
		} else {
			// For testing, just store a placeholder
			m.uploadedFiles[pkg.FullName()] = []byte("mock content for " + pkg.FullName())
		}
	}

	return nil
}

func (m *mockRemoteCacheUpload) Download(ctx context.Context, dst cache.LocalCache, pkgs []cache.Package) error {
	return nil
}

func (m *mockRemoteCacheUpload) ExistingPackages(ctx context.Context, pkgs []cache.Package) (map[cache.Package]struct{}, error) {
	return make(map[cache.Package]struct{}), nil
}

func (m *mockRemoteCacheUpload) UploadFile(ctx context.Context, filePath string, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if this key should fail
	if err, exists := m.uploadErrors[key]; exists {
		return err
	}

	// Simulate successful upload by storing the file content
	if m.uploadedFiles == nil {
		m.uploadedFiles = make(map[string][]byte)
	}

	// Read the file content
	if content, err := os.ReadFile(filePath); err == nil {
		m.uploadedFiles[key] = content
	} else {
		// For testing, just store a placeholder
		m.uploadedFiles[key] = []byte("mock content for " + key)
	}

	return nil
}

func (m *mockRemoteCacheUpload) HasFile(ctx context.Context, key string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.uploadedFiles == nil {
		return false, nil
	}

	_, exists := m.uploadedFiles[key]
	return exists, nil
}

// Test helper to create a test artifact file
func createTestArtifactFile(t *testing.T, dir, name, content string) string {
	path := filepath.Join(dir, name)
	err := os.WriteFile(path, []byte(content), 0644)
	require.NoError(t, err)
	return path
}

// TestArtifactUploader_SuccessfulUpload tests normal upload flow
func TestArtifactUploader_SuccessfulUpload(t *testing.T) {
	tmpDir := t.TempDir()

	// Create test artifact
	artifactPath := filepath.Join(tmpDir, "test-artifact.tar.gz")
	artifactContent := []byte("test artifact content")
	err := os.WriteFile(artifactPath, artifactContent, 0644)
	require.NoError(t, err)

	// Create attestation
	attestationBytes := []byte(`{"_type":"https://in-toto.io/Statement/v0.1"}`)

	// Setup mock cache
	mockCache := &mockRemoteCacheUpload{
		uploadedFiles: make(map[string][]byte),
	}

	// Create uploader
	uploader := NewArtifactUploader(mockCache)

	// Upload
	ctx := context.Background()
	err = uploader.UploadArtifactWithAttestation(ctx, artifactPath, attestationBytes)
	assert.NoError(t, err)
}

// TestArtifactUploader_MultipleArtifacts tests batch upload concept
func TestArtifactUploader_MultipleArtifacts(t *testing.T) {
	tmpDir := t.TempDir()

	artifacts := []string{"artifact1.tar.gz", "artifact2.tar.gz", "artifact3.tar"}

	mockCache := &mockRemoteCacheUpload{
		uploadedFiles: make(map[string][]byte),
	}
	uploader := NewArtifactUploader(mockCache)
	ctx := context.Background()

	// Upload multiple artifacts
	for _, name := range artifacts {
		artifactPath := filepath.Join(tmpDir, name)
		err := os.WriteFile(artifactPath, []byte("content "+name), 0644)
		require.NoError(t, err)

		attestation := []byte(`{"artifact":"` + name + `"}`)

		err = uploader.UploadArtifactWithAttestation(ctx, artifactPath, attestation)
		assert.NoError(t, err)
	}
}

// TestArtifactUploader_ValidatesInputs tests input validation
func TestArtifactUploader_ValidatesInputs(t *testing.T) {
	mockCache := &mockRemoteCacheUpload{
		uploadedFiles: make(map[string][]byte),
	}
	uploader := NewArtifactUploader(mockCache)
	ctx := context.Background()

	t.Run("empty artifact path", func(t *testing.T) {
		err := uploader.UploadArtifactWithAttestation(ctx, "", []byte("attestation"))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "artifact path cannot be empty")
	})

	t.Run("empty attestation bytes", func(t *testing.T) {
		tmpDir := t.TempDir()
		artifactPath := filepath.Join(tmpDir, "test.tar.gz")
		_ = os.WriteFile(artifactPath, []byte("test"), 0644)

		err := uploader.UploadArtifactWithAttestation(ctx, artifactPath, []byte{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "attestation bytes cannot be empty")
	})

	t.Run("nil attestation bytes", func(t *testing.T) {
		tmpDir := t.TempDir()
		artifactPath := filepath.Join(tmpDir, "test.tar.gz")
		_ = os.WriteFile(artifactPath, []byte("test"), 0644)

		err := uploader.UploadArtifactWithAttestation(ctx, artifactPath, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "attestation bytes cannot be empty")
	})

	t.Run("non-existent artifact file", func(t *testing.T) {
		err := uploader.UploadArtifactWithAttestation(ctx, "/nonexistent/file.tar.gz", []byte("attestation"))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "artifact file not accessible")
	})

	t.Run("directory instead of file", func(t *testing.T) {
		tmpDir := t.TempDir()
		err := uploader.UploadArtifactWithAttestation(ctx, tmpDir, []byte("attestation"))
		// os.Stat succeeds for directories, but upload will fail later
		// This is acceptable - the backend will catch it
		assert.NoError(t, err)
	})
}

// TestArtifactUploader_HandlesLargeFiles tests large file handling
func TestArtifactUploader_HandlesLargeFiles(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a larger test artifact (1MB)
	artifactPath := filepath.Join(tmpDir, "large-artifact.tar.gz")
	largeContent := make([]byte, 1024*1024) // 1MB
	for i := range largeContent {
		largeContent[i] = byte(i % 256)
	}
	err := os.WriteFile(artifactPath, largeContent, 0644)
	require.NoError(t, err)

	// Create attestation
	attestationBytes := []byte(`{"_type":"https://in-toto.io/Statement/v0.1","large":true}`)

	// Setup mock cache
	mockCache := &mockRemoteCacheUpload{
		uploadedFiles: make(map[string][]byte),
	}

	uploader := NewArtifactUploader(mockCache)

	// Upload
	ctx := context.Background()
	err = uploader.UploadArtifactWithAttestation(ctx, artifactPath, attestationBytes)
	assert.NoError(t, err)
}

// TestArtifactUploader_NetworkFailure tests network error handling
func TestArtifactUploader_NetworkFailure(t *testing.T) {
	tmpDir := t.TempDir()
	artifactPath := filepath.Join(tmpDir, "test.tar.gz")
	err := os.WriteFile(artifactPath, []byte("test"), 0644)
	require.NoError(t, err)

	// Configure mock to simulate network failure
	mockCache := &mockRemoteCacheUpload{
		uploadedFiles: make(map[string][]byte),
		uploadErrors: map[string]error{
			"test.tar.gz": fmt.Errorf("network timeout"),
		},
	}

	uploader := NewArtifactUploader(mockCache)
	attestation := []byte(`{"test":"attestation"}`)

	err = uploader.UploadArtifactWithAttestation(context.Background(), artifactPath, attestation)

	// Should return network error from mock
	assert.Error(t, err)
}

// TestArtifactUploader_PartialUploadFailure tests partial failure scenarios
func TestArtifactUploader_PartialUploadFailure(t *testing.T) {
	tmpDir := t.TempDir()
	artifactPath := filepath.Join(tmpDir, "test.tar.gz")
	err := os.WriteFile(artifactPath, []byte("test"), 0644)
	require.NoError(t, err)

	// Simulate: artifact upload succeeds, attestation upload fails
	mockCache := &mockRemoteCacheUpload{
		uploadedFiles: make(map[string][]byte),
		uploadErrors: map[string]error{
			"test.tar.gz.att": fmt.Errorf("attestation upload failed"),
		},
	}

	uploader := NewArtifactUploader(mockCache)
	attestation := []byte(`{"test":"attestation"}`)

	err = uploader.UploadArtifactWithAttestation(context.Background(), artifactPath, attestation)

	// Should return error
	assert.Error(t, err)
}

// TestArtifactUploader_PermissionDenied tests access control
func TestArtifactUploader_PermissionDenied(t *testing.T) {
	tmpDir := t.TempDir()
	artifactPath := filepath.Join(tmpDir, "test.tar.gz")
	err := os.WriteFile(artifactPath, []byte("test"), 0644)
	require.NoError(t, err)

	// Simulate permission error
	mockCache := &mockRemoteCacheUpload{
		uploadedFiles: make(map[string][]byte),
		uploadErrors: map[string]error{
			"test.tar.gz": fmt.Errorf("access denied: insufficient permissions"),
		},
	}

	uploader := NewArtifactUploader(mockCache)
	attestation := []byte(`{"test":"attestation"}`)

	err = uploader.UploadArtifactWithAttestation(context.Background(), artifactPath, attestation)

	assert.Error(t, err)
}

// TestArtifactUploader_ContextCancellation tests context handling
func TestArtifactUploader_ContextCancellation(t *testing.T) {
	tmpDir := t.TempDir()
	artifactPath := filepath.Join(tmpDir, "test.tar.gz")
	_ = os.WriteFile(artifactPath, []byte("test"), 0644)

	mockCache := &mockRemoteCacheUpload{
		uploadedFiles: make(map[string][]byte),
	}
	uploader := NewArtifactUploader(mockCache)
	attestation := []byte(`{"test":"attestation"}`)

	t.Run("context cancelled before upload", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		err := uploader.UploadArtifactWithAttestation(ctx, artifactPath, attestation)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "context cancelled")
	})

	t.Run("context timeout", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
		defer cancel()
		time.Sleep(10 * time.Millisecond) // Ensure timeout

		err := uploader.UploadArtifactWithAttestation(ctx, artifactPath, attestation)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "context")
	})
}

// TestArtifactUploader_ConcurrentUploads tests concurrent upload handling
func TestArtifactUploader_ConcurrentUploads(t *testing.T) {
	tmpDir := t.TempDir()

	mockCache := &mockRemoteCacheUpload{
		uploadedFiles: make(map[string][]byte),
	}

	uploader := NewArtifactUploader(mockCache)

	// Create multiple artifacts
	const numArtifacts = 5
	artifacts := make([]string, numArtifacts)

	for i := 0; i < numArtifacts; i++ {
		name := fmt.Sprintf("artifact%d.tar.gz", i)
		artifacts[i] = createTestArtifactFile(t, tmpDir, name, fmt.Sprintf("content %d", i))
	}

	// Upload concurrently
	errChan := make(chan error, numArtifacts)

	for _, artifactPath := range artifacts {
		go func(path string) {
			attestation := []byte(fmt.Sprintf(`{"artifact":"%s"}`, filepath.Base(path)))
			err := uploader.UploadArtifactWithAttestation(context.Background(), path, attestation)
			errChan <- err
		}(artifactPath)
	}

	// Collect results
	for i := 0; i < numArtifacts; i++ {
		err := <-errChan

		assert.NoError(t, err)
	}
}

// TestArtifactUploader_SkipsExistingArtifacts tests that existing artifacts are not re-uploaded
func TestArtifactUploader_SkipsExistingArtifacts(t *testing.T) {
	tmpDir := t.TempDir()
	artifactPath := filepath.Join(tmpDir, "existing.tar.gz")
	artifactContent := []byte("existing artifact content")
	err := os.WriteFile(artifactPath, artifactContent, 0644)
	require.NoError(t, err)

	mockCache := &mockRemoteCacheUpload{
		uploadedFiles: make(map[string][]byte),
	}

	// Pre-populate the cache with the artifact (simulating it already exists)
	mockCache.uploadedFiles["existing.tar.gz"] = artifactContent

	uploader := NewArtifactUploader(mockCache)
	attestation := []byte(`{"test":"attestation"}`)

	err = uploader.UploadArtifactWithAttestation(context.Background(), artifactPath, attestation)
	require.NoError(t, err)

	// Verify that the artifact was NOT re-uploaded (content should be unchanged)
	assert.Equal(t, artifactContent, mockCache.uploadedFiles["existing.tar.gz"], "Artifact should not be re-uploaded")

	// Verify that the attestation WAS uploaded
	assert.Contains(t, mockCache.uploadedFiles, "existing.tar.gz.att", "Attestation should be uploaded")
	assert.Equal(t, attestation, mockCache.uploadedFiles["existing.tar.gz.att"], "Attestation content should match")
}

// TestArtifactUploader_UploadsNewArtifacts tests that new artifacts are uploaded
func TestArtifactUploader_UploadsNewArtifacts(t *testing.T) {
	tmpDir := t.TempDir()
	artifactPath := filepath.Join(tmpDir, "new.tar.gz")
	artifactContent := []byte("new artifact content")
	err := os.WriteFile(artifactPath, artifactContent, 0644)
	require.NoError(t, err)

	mockCache := &mockRemoteCacheUpload{
		uploadedFiles: make(map[string][]byte),
	}

	uploader := NewArtifactUploader(mockCache)
	attestation := []byte(`{"test":"attestation"}`)

	err = uploader.UploadArtifactWithAttestation(context.Background(), artifactPath, attestation)
	require.NoError(t, err)

	// Verify that the artifact WAS uploaded
	assert.Contains(t, mockCache.uploadedFiles, "new.tar.gz", "New artifact should be uploaded")
	assert.Equal(t, artifactContent, mockCache.uploadedFiles["new.tar.gz"], "Artifact content should match")

	// Verify that the attestation WAS uploaded
	assert.Contains(t, mockCache.uploadedFiles, "new.tar.gz.att", "Attestation should be uploaded")
	assert.Equal(t, attestation, mockCache.uploadedFiles["new.tar.gz.att"], "Attestation content should match")
}
