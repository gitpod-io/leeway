package remote

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/gitpod-io/leeway/pkg/leeway/cache"
	"golang.org/x/time/rate"
)

// TestS3Cache_ProvenanceUpload tests provenance bundle upload functionality
func TestS3Cache_ProvenanceUpload(t *testing.T) {
	tests := []struct {
		name                 string
		createProvenanceFile bool
		provenanceContent    string
		expectUpload         bool
		expectedLogContains  string
	}{
		{
			name:                 "successful provenance upload",
			createProvenanceFile: true,
			provenanceContent:    `{"predicate":{"buildType":"test"}}`,
			expectUpload:         true,
			expectedLogContains:  "Successfully uploaded provenance bundle",
		},
		{
			name:                 "missing provenance file (skip upload)",
			createProvenanceFile: false,
			expectUpload:         false,
			expectedLogContains:  "Provenance bundle not found locally",
		},
		{
			name:                 "empty provenance file",
			createProvenanceFile: true,
			provenanceContent:    "",
			expectUpload:         true,
			expectedLogContains:  "Successfully uploaded provenance bundle",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary directory for test
			tmpDir := t.TempDir()

			// Create mock package
			pkg := &mockPackage{
				version: "v1.0.0",
			}

			// Create artifact file
			artifactPath := filepath.Join(tmpDir, "v1.0.0.tar.gz")
			if err := os.WriteFile(artifactPath, []byte("test artifact"), 0644); err != nil {
				t.Fatalf("Failed to create artifact: %v", err)
			}

			// Create provenance file if needed
			if tt.createProvenanceFile {
				provenancePath := artifactPath + ".provenance.jsonl"
				if err := os.WriteFile(provenancePath, []byte(tt.provenanceContent), 0644); err != nil {
					t.Fatalf("Failed to create provenance file: %v", err)
				}
			}

			// Create mock S3 storage
			mockStorage := &mockS3StorageForProvenance{
				objects: make(map[string][]byte),
			}

			// Create S3 cache
			s3Cache := &S3Cache{
				storage:     mockStorage,
				rateLimiter: rate.NewLimiter(rate.Limit(100), 200),
				cfg: &cache.RemoteConfig{
					BucketName: "test-bucket",
				},
			}

			// Test upload
			ctx := context.Background()
			s3Cache.uploadProvenanceBundle(ctx, pkg.FullName(), "v1.0.0.tar.gz", artifactPath)

			// Verify upload
			provenanceKey := "v1.0.0.tar.gz.provenance.jsonl"
			if tt.expectUpload {
				if _, exists := mockStorage.objects[provenanceKey]; !exists {
					t.Errorf("Expected provenance to be uploaded but it wasn't")
				}
				if tt.provenanceContent != "" {
					if string(mockStorage.objects[provenanceKey]) != tt.provenanceContent {
						t.Errorf("Provenance content mismatch: got %q, want %q",
							string(mockStorage.objects[provenanceKey]), tt.provenanceContent)
					}
				}
			} else {
				if _, exists := mockStorage.objects[provenanceKey]; exists {
					t.Errorf("Expected provenance not to be uploaded but it was")
				}
			}
		})
	}
}

// TestS3Cache_ProvenanceDownload tests provenance bundle download functionality
func TestS3Cache_ProvenanceDownload(t *testing.T) {
	tests := []struct {
		name                string
		provenanceExists    bool
		provenanceContent   string
		expectDownload      bool
		expectFileCreated   bool
		expectedLogContains string
	}{
		{
			name:              "successful provenance download",
			provenanceExists:  true,
			provenanceContent: `{"predicate":{"buildType":"test"}}`,
			expectDownload:    true,
			expectFileCreated: true,
		},
		{
			name:              "missing provenance (backward compatibility)",
			provenanceExists:  false,
			expectDownload:    false,
			expectFileCreated: false,
		},
		{
			name:              "empty provenance file",
			provenanceExists:  true,
			provenanceContent: "",
			expectDownload:    false, // Should fail verification (empty file)
			expectFileCreated: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary directory for test
			tmpDir := t.TempDir()

			// Create mock package
			pkg := &mockPackage{

				version: "v1.0.0",
			}

			// Create artifact file
			artifactPath := filepath.Join(tmpDir, "v1.0.0.tar.gz")
			if err := os.WriteFile(artifactPath, []byte("test artifact"), 0644); err != nil {
				t.Fatalf("Failed to create artifact: %v", err)
			}

			// Create mock S3 storage
			mockStorage := &mockS3StorageForProvenance{
				objects: make(map[string][]byte),
			}

			// Add provenance to mock storage if it should exist
			if tt.provenanceExists {
				provenanceKey := "v1.0.0.tar.gz.provenance.jsonl"
				mockStorage.objects[provenanceKey] = []byte(tt.provenanceContent)
			}

			// Create S3 cache
			s3Cache := &S3Cache{
				storage:     mockStorage,
				rateLimiter: rate.NewLimiter(rate.Limit(100), 200),
				cfg: &cache.RemoteConfig{
					BucketName: "test-bucket",
				},
			}

			// Test download
			ctx := context.Background()
			success := s3Cache.downloadProvenanceBundle(ctx, pkg.FullName(), "v1.0.0.tar.gz", artifactPath)

			// Verify download result
			if success != tt.expectDownload {
				t.Errorf("Download success mismatch: got %v, want %v", success, tt.expectDownload)
			}

			// Verify file creation
			provenancePath := artifactPath + ".provenance.jsonl"
			fileExists := fileExists(provenancePath)
			if fileExists != tt.expectFileCreated {
				t.Errorf("File creation mismatch: got %v, want %v", fileExists, tt.expectFileCreated)
			}

			// Verify content if file should exist
			if tt.expectFileCreated && tt.provenanceContent != "" {
				content, err := os.ReadFile(provenancePath)
				if err != nil {
					t.Fatalf("Failed to read provenance file: %v", err)
				}
				if string(content) != tt.provenanceContent {
					t.Errorf("Provenance content mismatch: got %q, want %q",
						string(content), tt.provenanceContent)
				}
			}
		})
	}
}

// TestS3Cache_ProvenanceRoundTrip tests upload and download together
func TestS3Cache_ProvenanceRoundTrip(t *testing.T) {
	// Create temporary directories
	uploadDir := t.TempDir()
	downloadDir := t.TempDir()

	// Create mock package
	pkg := &mockPackage{

		version: "v1.0.0",
	}

	// Create artifact and provenance in upload directory
	uploadArtifactPath := filepath.Join(uploadDir, "v1.0.0.tar.gz")
	if err := os.WriteFile(uploadArtifactPath, []byte("test artifact"), 0644); err != nil {
		t.Fatalf("Failed to create artifact: %v", err)
	}

	provenanceContent := `{"predicate":{"buildType":"test","materials":[{"uri":"git+https://github.com/test/repo"}]}}`
	uploadProvenancePath := uploadArtifactPath + ".provenance.jsonl"
	if err := os.WriteFile(uploadProvenancePath, []byte(provenanceContent), 0644); err != nil {
		t.Fatalf("Failed to create provenance file: %v", err)
	}

	// Create mock S3 storage (shared between upload and download)
	mockStorage := &mockS3StorageForProvenance{
		objects: make(map[string][]byte),
	}

	// Create S3 cache
	s3Cache := &S3Cache{
		storage:     mockStorage,
		rateLimiter: rate.NewLimiter(rate.Limit(100), 200),
		cfg: &cache.RemoteConfig{
			BucketName: "test-bucket",
		},
	}

	// Upload
	ctx := context.Background()
	s3Cache.uploadProvenanceBundle(ctx, pkg.FullName(), "v1.0.0.tar.gz", uploadArtifactPath)

	// Verify upload
	provenanceKey := "v1.0.0.tar.gz.provenance.jsonl"
	if _, exists := mockStorage.objects[provenanceKey]; !exists {
		t.Fatal("Provenance was not uploaded")
	}

	// Download to different directory
	downloadArtifactPath := filepath.Join(downloadDir, "v1.0.0.tar.gz")
	if err := os.WriteFile(downloadArtifactPath, []byte("test artifact"), 0644); err != nil {
		t.Fatalf("Failed to create download artifact: %v", err)
	}

	success := s3Cache.downloadProvenanceBundle(ctx, pkg.FullName(), "v1.0.0.tar.gz", downloadArtifactPath)
	if !success {
		t.Fatal("Provenance download failed")
	}

	// Verify downloaded content matches uploaded content
	downloadProvenancePath := downloadArtifactPath + ".provenance.jsonl"
	downloadedContent, err := os.ReadFile(downloadProvenancePath)
	if err != nil {
		t.Fatalf("Failed to read downloaded provenance: %v", err)
	}

	if string(downloadedContent) != provenanceContent {
		t.Errorf("Downloaded content mismatch:\ngot:  %q\nwant: %q",
			string(downloadedContent), provenanceContent)
	}
}

// TestS3Cache_ProvenanceAtomicMove tests atomic move behavior
func TestS3Cache_ProvenanceAtomicMove(t *testing.T) {
	tmpDir := t.TempDir()

	pkg := &mockPackage{

		version: "v1.0.0",
	}

	artifactPath := filepath.Join(tmpDir, "v1.0.0.tar.gz")
	if err := os.WriteFile(artifactPath, []byte("test artifact"), 0644); err != nil {
		t.Fatalf("Failed to create artifact: %v", err)
	}

	// Create mock S3 storage with provenance
	provenanceContent := `{"predicate":{"buildType":"test"}}`
	mockStorage := &mockS3StorageForProvenance{
		objects: map[string][]byte{
			"v1.0.0.tar.gz.provenance.jsonl": []byte(provenanceContent),
		},
	}

	s3Cache := &S3Cache{
		storage:     mockStorage,
		rateLimiter: rate.NewLimiter(rate.Limit(100), 200),
		cfg: &cache.RemoteConfig{
			BucketName: "test-bucket",
		},
	}

	// Download provenance
	ctx := context.Background()
	success := s3Cache.downloadProvenanceBundle(ctx, pkg.FullName(), "v1.0.0.tar.gz", artifactPath)
	if !success {
		t.Fatal("Provenance download failed")
	}

	// Verify no .tmp file left behind
	tmpFiles, err := filepath.Glob(filepath.Join(tmpDir, "*.tmp"))
	if err != nil {
		t.Fatalf("Failed to check for tmp files: %v", err)
	}
	if len(tmpFiles) > 0 {
		t.Errorf("Found temporary files that should have been cleaned up: %v", tmpFiles)
	}

	// Verify final file exists
	provenancePath := artifactPath + ".provenance.jsonl"
	if !fileExists(provenancePath) {
		t.Error("Final provenance file does not exist")
	}
}

// mockS3StorageForProvenance is a mock implementation for provenance testing
type mockS3StorageForProvenance struct {
	objects map[string][]byte
}

func (m *mockS3StorageForProvenance) HasObject(ctx context.Context, key string) (bool, error) {
	_, exists := m.objects[key]
	return exists, nil
}

func (m *mockS3StorageForProvenance) GetObject(ctx context.Context, key string, dest string) (int64, error) {
	data, exists := m.objects[key]
	if !exists {
		return 0, &mockNotFoundError{key: key}
	}

	if err := os.WriteFile(dest, data, 0644); err != nil {
		return 0, err
	}

	return int64(len(data)), nil
}

func (m *mockS3StorageForProvenance) UploadObject(ctx context.Context, key string, src string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	m.objects[key] = data
	return nil
}


