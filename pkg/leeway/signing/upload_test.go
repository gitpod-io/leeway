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
	uploadCalls   map[string]int // Track number of times each key was uploaded
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

func (m *mockRemoteCacheUpload) Download(ctx context.Context, dst cache.LocalCache, pkgs []cache.Package) map[string]cache.DownloadResult {
	results := make(map[string]cache.DownloadResult)
	for _, pkg := range pkgs {
		results[pkg.FullName()] = cache.DownloadResult{Status: cache.DownloadStatusNotFound}
	}
	return results
}

func (m *mockRemoteCacheUpload) ExistingPackages(ctx context.Context, pkgs []cache.Package) (map[cache.Package]struct{}, error) {
	return make(map[cache.Package]struct{}), nil
}

func (m *mockRemoteCacheUpload) UploadFile(ctx context.Context, filePath string, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Track upload calls
	if m.uploadCalls == nil {
		m.uploadCalls = make(map[string]int)
	}
	m.uploadCalls[key]++

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
// and attestation upload is also skipped when both artifact and attestation exist
func TestArtifactUploader_SkipsExistingArtifacts(t *testing.T) {
	tmpDir := t.TempDir()
	artifactPath := filepath.Join(tmpDir, "existing.tar.gz")
	artifactContent := []byte("existing artifact content")
	err := os.WriteFile(artifactPath, artifactContent, 0644)
	require.NoError(t, err)

	mockCache := &mockRemoteCacheUpload{
		uploadedFiles: make(map[string][]byte),
		uploadCalls:   make(map[string]int),
	}

	// Pre-populate the cache with both artifact and attestation (simulating they already exist)
	existingAttestation := []byte(`{"existing":"attestation"}`)
	mockCache.uploadedFiles["existing.tar.gz"] = artifactContent
	mockCache.uploadedFiles["existing.tar.gz.att"] = existingAttestation

	uploader := NewArtifactUploader(mockCache)
	attestation := []byte(`{"test":"attestation"}`)

	err = uploader.UploadArtifactWithAttestation(context.Background(), artifactPath, attestation)
	require.NoError(t, err)

	// CRITICAL: Verify that UploadFile was NOT called for the artifact
	assert.Equal(t, 0, mockCache.uploadCalls["existing.tar.gz"], "Artifact should not be uploaded when it already exists")

	// CRITICAL: Verify that the attestation was NOT uploaded when both exist
	assert.Equal(t, 0, mockCache.uploadCalls["existing.tar.gz.att"], "Attestation should NOT be uploaded when both artifact and attestation exist")

	// Verify existing attestation is preserved
	assert.Equal(t, existingAttestation, mockCache.uploadedFiles["existing.tar.gz.att"], "Existing attestation should be preserved")
}

// TestArtifactUploader_UploadsAttestationWhenMissing tests that attestation is uploaded
// when artifact exists but attestation is missing (e.g., old build before SLSA)
func TestArtifactUploader_UploadsAttestationWhenMissing(t *testing.T) {
	tmpDir := t.TempDir()
	artifactPath := filepath.Join(tmpDir, "existing.tar.gz")
	artifactContent := []byte("existing artifact content")
	err := os.WriteFile(artifactPath, artifactContent, 0644)
	require.NoError(t, err)

	mockCache := &mockRemoteCacheUpload{
		uploadedFiles: make(map[string][]byte),
		uploadCalls:   make(map[string]int),
	}

	// Pre-populate the cache with artifact only (no attestation - simulating old build)
	mockCache.uploadedFiles["existing.tar.gz"] = artifactContent

	uploader := NewArtifactUploader(mockCache)
	attestation := []byte(`{"test":"attestation"}`)

	err = uploader.UploadArtifactWithAttestation(context.Background(), artifactPath, attestation)
	require.NoError(t, err)

	// Verify that artifact was NOT re-uploaded
	assert.Equal(t, 0, mockCache.uploadCalls["existing.tar.gz"], "Artifact should not be re-uploaded when it already exists")

	// CRITICAL: Verify that attestation WAS uploaded (missing attestation case)
	assert.Equal(t, 1, mockCache.uploadCalls["existing.tar.gz.att"], "Attestation should be uploaded when missing")
	assert.Contains(t, mockCache.uploadedFiles, "existing.tar.gz.att", "Attestation should be in cache")
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
		uploadCalls:   make(map[string]int),
	}

	uploader := NewArtifactUploader(mockCache)
	attestation := []byte(`{"test":"attestation"}`)

	err = uploader.UploadArtifactWithAttestation(context.Background(), artifactPath, attestation)
	require.NoError(t, err)

	// Verify that UploadFile was called for the artifact
	assert.Equal(t, 1, mockCache.uploadCalls["new.tar.gz"], "New artifact should be uploaded exactly once")
	assert.Contains(t, mockCache.uploadedFiles, "new.tar.gz", "New artifact should be in cache")
	assert.Equal(t, artifactContent, mockCache.uploadedFiles["new.tar.gz"], "Artifact content should match")

	// Verify that the attestation WAS uploaded
	assert.Equal(t, 1, mockCache.uploadCalls["new.tar.gz.att"], "Attestation should be uploaded exactly once")
	assert.Contains(t, mockCache.uploadedFiles, "new.tar.gz.att", "Attestation should be in cache")
	assert.Equal(t, attestation, mockCache.uploadedFiles["new.tar.gz.att"], "Attestation content should match")
}

// TestArtifactUploader_SimulatesDownloadedArtifactWorkflow tests the complete workflow
// where an artifact is downloaded from remote cache and then signed
func TestArtifactUploader_SimulatesDownloadedArtifactWorkflow(t *testing.T) {
	tmpDir := t.TempDir()

	// Simulate the workflow:
	// 1. Build job uploads artifact to S3
	// 2. Sign job downloads artifact from S3
	// 3. Sign job creates attestation
	// 4. Sign job should NOT re-upload artifact OR attestation

	mockCache := &mockRemoteCacheUpload{
		uploadedFiles: make(map[string][]byte),
		uploadCalls:   make(map[string]int),
	}

	// Step 1: Simulate build job uploading artifact and attestation
	buildArtifactContent := []byte("artifact built by build job")
	buildAttestation := []byte(`{"build":"attestation"}`)
	mockCache.uploadedFiles["downloaded.tar.gz"] = buildArtifactContent
	mockCache.uploadedFiles["downloaded.tar.gz.att"] = buildAttestation
	mockCache.uploadCalls["downloaded.tar.gz"] = 1 // Track that build job uploaded it
	mockCache.uploadCalls["downloaded.tar.gz.att"] = 1

	// Step 2: Simulate sign job downloading artifact (creates local file)
	downloadedArtifactPath := filepath.Join(tmpDir, "downloaded.tar.gz")
	err := os.WriteFile(downloadedArtifactPath, buildArtifactContent, 0644)
	require.NoError(t, err)

	// Step 3 & 4: Sign job creates attestation and uploads
	uploader := NewArtifactUploader(mockCache)
	attestation := []byte(`{"test":"attestation for downloaded artifact"}`)

	err = uploader.UploadArtifactWithAttestation(context.Background(), downloadedArtifactPath, attestation)
	require.NoError(t, err)

	// CRITICAL: Artifact should NOT be re-uploaded
	// uploadCalls should still be 1 (from build job), not 2
	assert.Equal(t, 1, mockCache.uploadCalls["downloaded.tar.gz"],
		"Downloaded artifact should NOT be re-uploaded by sign job")

	// CRITICAL: Attestation should NOT be uploaded when both exist
	assert.Equal(t, 1, mockCache.uploadCalls["downloaded.tar.gz.att"],
		"Attestation should NOT be uploaded when both artifact and attestation exist")

	// Verify existing attestation is preserved
	assert.Equal(t, buildAttestation, mockCache.uploadedFiles["downloaded.tar.gz.att"],
		"Existing attestation should be preserved")

	// Artifact content should remain unchanged (not overwritten)
	assert.Equal(t, buildArtifactContent, mockCache.uploadedFiles["downloaded.tar.gz"],
		"Artifact content should remain unchanged from build job")
}

// TestArtifactUploader_SimulatesLocallyBuiltArtifactWorkflow tests the workflow
// where an artifact is built locally and needs to be uploaded
func TestArtifactUploader_SimulatesLocallyBuiltArtifactWorkflow(t *testing.T) {
	tmpDir := t.TempDir()

	// Simulate the workflow:
	// 1. Build job builds artifact locally (not in remote cache)
	// 2. Sign job creates attestation
	// 3. Sign job should upload BOTH artifact and attestation

	mockCache := &mockRemoteCacheUpload{
		uploadedFiles: make(map[string][]byte),
		uploadCalls:   make(map[string]int),
	}

	// Step 1: Simulate locally built artifact (not in remote cache yet)
	localArtifactPath := filepath.Join(tmpDir, "local.tar.gz")
	localArtifactContent := []byte("artifact built locally")
	err := os.WriteFile(localArtifactPath, localArtifactContent, 0644)
	require.NoError(t, err)

	// Step 2 & 3: Sign job creates attestation and uploads
	uploader := NewArtifactUploader(mockCache)
	attestation := []byte(`{"test":"attestation for local artifact"}`)

	err = uploader.UploadArtifactWithAttestation(context.Background(), localArtifactPath, attestation)
	require.NoError(t, err)

	// VERIFICATION: Both artifact and attestation should be uploaded
	assert.Equal(t, 1, mockCache.uploadCalls["local.tar.gz"],
		"Locally built artifact should be uploaded")
	assert.Equal(t, localArtifactContent, mockCache.uploadedFiles["local.tar.gz"],
		"Artifact content should match")

	assert.Equal(t, 1, mockCache.uploadCalls["local.tar.gz.att"],
		"Attestation should be uploaded")
	assert.Equal(t, attestation, mockCache.uploadedFiles["local.tar.gz.att"],
		"Attestation content should match")
}

// TestArtifactUploader_PreventsAttestationOverwrite tests the race condition fix
// where multiple workflows building the same artifact would overwrite each other's attestations
func TestArtifactUploader_PreventsAttestationOverwrite(t *testing.T) {
	tmpDir := t.TempDir()

	// Simulate the race condition scenario:
	// 1. Workflow A builds artifact (checksum A), uploads to S3, signs it, uploads attestation A
	// 2. Workflow B builds artifact (checksum B), finds artifact exists, signs LOCAL artifact B
	// 3. WITHOUT THIS: Workflow B would upload attestation B, overwriting attestation A
	// 4. WITH THIS: Workflow B skips attestation upload, preserving attestation A

	mockCache := &mockRemoteCacheUpload{
		uploadedFiles: make(map[string][]byte),
		uploadCalls:   make(map[string]int),
	}

	// Step 1: Workflow A uploads artifact and attestation
	artifactAContent := []byte("artifact with checksum A")
	attestationA := []byte(`{"checksum":"A","workflow":"build-main"}`)

	mockCache.uploadedFiles["shared-artifact.tar.gz"] = artifactAContent
	mockCache.uploadedFiles["shared-artifact.tar.gz.att"] = attestationA
	mockCache.uploadCalls["shared-artifact.tar.gz"] = 1
	mockCache.uploadCalls["shared-artifact.tar.gz.att"] = 1

	// Step 2: Workflow B builds a different version locally
	artifactBPath := filepath.Join(tmpDir, "shared-artifact.tar.gz")
	artifactBContent := []byte("artifact with checksum B")
	err := os.WriteFile(artifactBPath, artifactBContent, 0644)
	require.NoError(t, err)

	// Step 3: Workflow B tries to upload (should skip both)
	uploader := NewArtifactUploader(mockCache)
	attestationB := []byte(`{"checksum":"B","workflow":"build-cli"}`)

	err = uploader.UploadArtifactWithAttestation(context.Background(), artifactBPath, attestationB)
	require.NoError(t, err)

	// Step 4: Verify the fix
	// Artifact upload count should still be 1 (only workflow A uploaded)
	assert.Equal(t, 1, mockCache.uploadCalls["shared-artifact.tar.gz"],
		"Artifact should not be re-uploaded by workflow B")

	// CRITICAL: Attestation upload count should still be 1 (only workflow A uploaded)
	assert.Equal(t, 1, mockCache.uploadCalls["shared-artifact.tar.gz.att"],
		"Attestation should not be overwritten by workflow B")

	// Verify original attestation A is preserved (not overwritten by attestation B)
	assert.Equal(t, attestationA, mockCache.uploadedFiles["shared-artifact.tar.gz.att"],
		"Original attestation A should be preserved, not overwritten by attestation B")

	// Verify original artifact A is preserved
	assert.Equal(t, artifactAContent, mockCache.uploadedFiles["shared-artifact.tar.gz"],
		"Original artifact A should be preserved")
}

// TestArtifactUploader_HasFileError tests fallback behavior when HasFile check fails
func TestArtifactUploader_HasFileError(t *testing.T) {
	tmpDir := t.TempDir()
	artifactPath := filepath.Join(tmpDir, "test.tar.gz")
	artifactContent := []byte("test content")
	err := os.WriteFile(artifactPath, artifactContent, 0644)
	require.NoError(t, err)

	// Create a mock that returns an error for HasFile
	mockCache := &mockRemoteCacheUploadWithHasFileError{
		mockRemoteCacheUpload: mockRemoteCacheUpload{
			uploadedFiles: make(map[string][]byte),
			uploadCalls:   make(map[string]int),
		},
		hasFileError: fmt.Errorf("S3 connection failed"),
	}

	uploader := NewArtifactUploader(mockCache)
	attestation := []byte(`{"test":"attestation"}`)

	// Should proceed with upload despite HasFile error (safe fallback)
	err = uploader.UploadArtifactWithAttestation(context.Background(), artifactPath, attestation)
	require.NoError(t, err)

	// Verify both were uploaded (fallback behavior assumes artifact doesn't exist)
	assert.Equal(t, 1, mockCache.uploadCalls["test.tar.gz"],
		"Artifact should be uploaded when HasFile fails")
	assert.Equal(t, 1, mockCache.uploadCalls["test.tar.gz.att"],
		"Attestation should be uploaded when HasFile fails")
}

// mockRemoteCacheUploadWithHasFileError extends mockRemoteCacheUpload to simulate HasFile errors
type mockRemoteCacheUploadWithHasFileError struct {
	mockRemoteCacheUpload
	hasFileError error
}

func (m *mockRemoteCacheUploadWithHasFileError) HasFile(ctx context.Context, key string) (bool, error) {
	if m.hasFileError != nil {
		return false, m.hasFileError
	}
	return m.mockRemoteCacheUpload.HasFile(ctx, key)
}

// TestArtifactUploader_AttestationCheckError tests fallback behavior when attestation HasFile check fails
func TestArtifactUploader_AttestationCheckError(t *testing.T) {
	tmpDir := t.TempDir()
	artifactPath := filepath.Join(tmpDir, "test.tar.gz")
	artifactContent := []byte("test content")
	err := os.WriteFile(artifactPath, artifactContent, 0644)
	require.NoError(t, err)

	// Create a mock where artifact exists but attestation check fails
	mockCache := &mockRemoteCacheUploadWithSelectiveError{
		mockRemoteCacheUpload: mockRemoteCacheUpload{
			uploadedFiles: map[string][]byte{
				"test.tar.gz": artifactContent, // Artifact exists
			},
			uploadCalls: make(map[string]int),
		},
		errorKeys: map[string]error{
			"test.tar.gz.att": fmt.Errorf("S3 connection failed for attestation check"),
		},
	}

	uploader := NewArtifactUploader(mockCache)
	attestation := []byte(`{"test":"attestation"}`)

	// Should proceed with attestation upload despite HasFile error (safe fallback)
	err = uploader.UploadArtifactWithAttestation(context.Background(), artifactPath, attestation)
	require.NoError(t, err)

	// Artifact should not be re-uploaded
	assert.Equal(t, 0, mockCache.uploadCalls["test.tar.gz"],
		"Artifact should not be uploaded when it exists")

	// Attestation should be uploaded (fallback behavior assumes it doesn't exist)
	assert.Equal(t, 1, mockCache.uploadCalls["test.tar.gz.att"],
		"Attestation should be uploaded when HasFile check fails")
}

// mockRemoteCacheUploadWithSelectiveError allows different errors for different keys
type mockRemoteCacheUploadWithSelectiveError struct {
	mockRemoteCacheUpload
	errorKeys map[string]error
}

func (m *mockRemoteCacheUploadWithSelectiveError) HasFile(ctx context.Context, key string) (bool, error) {
	if err, exists := m.errorKeys[key]; exists {
		return false, err
	}
	return m.mockRemoteCacheUpload.HasFile(ctx, key)
}
