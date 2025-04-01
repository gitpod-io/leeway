package remote

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gitpod-io/leeway/pkg/leeway/cache"
	"github.com/gitpod-io/leeway/pkg/leeway/cache/local"
	"github.com/google/go-cmp/cmp"
)

// s3TestPackage for testing S3 download functionality
type s3TestPackage struct {
	versionStr string
	fullName   string
	versionErr error
}

func (m s3TestPackage) Version() (string, error) {
	return m.versionStr, m.versionErr
}

func (m s3TestPackage) FullName() string {
	return m.fullName
}

// mockS3Storage implements a simple ObjectStorage for testing
type mockS3Storage struct {
	objects       map[string][]byte
	failDownload  bool
	downloadDelay time.Duration
}

func (m *mockS3Storage) HasObject(ctx context.Context, key string) (bool, error) {
	_, exists := m.objects[key]
	return exists, nil
}

func (m *mockS3Storage) GetObject(ctx context.Context, key string, dest string) (int64, error) {
	if m.failDownload {
		return 0, errors.New("simulated download failure")
	}

	if m.downloadDelay > 0 {
		time.Sleep(m.downloadDelay)
	}

	data, exists := m.objects[key]
	if !exists {
		return 0, errors.New("NotFound: object does not exist")
	}

	if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
		return 0, err
	}

	if err := os.WriteFile(dest, data, 0644); err != nil {
		return 0, err
	}

	return int64(len(data)), nil
}

func (m *mockS3Storage) UploadObject(ctx context.Context, key string, src string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}

	m.objects[key] = data
	return nil
}

func (m *mockS3Storage) ListObjects(ctx context.Context, prefix string) ([]string, error) {
	var result []string
	for key := range m.objects {
		if len(prefix) == 0 || key[:len(prefix)] == prefix {
			result = append(result, key)
		}
	}
	return result, nil
}

func TestS3CacheDownload(t *testing.T) {
	tmpDir := t.TempDir()

	localCache, err := local.NewFilesystemCache(tmpDir)
	if err != nil {
		t.Fatalf("failed to create local cache: %v", err)
	}

	tests := []struct {
		name           string
		packages       []cache.Package
		mockObjects    map[string][]byte
		failDownload   bool
		downloadDelay  time.Duration
		wantDownloaded map[string]bool
		wantErrorCount int
	}{
		{
			name: "successful download",
			packages: []cache.Package{
				s3TestPackage{versionStr: "v1", fullName: "pkg1"},
			},
			mockObjects: map[string][]byte{
				"v1.tar.gz": []byte("test data"),
			},
			wantDownloaded: map[string]bool{
				"v1.tar.gz": true,
			},
		},
		{
			name: "fallback to tar",
			packages: []cache.Package{
				s3TestPackage{versionStr: "v2", fullName: "pkg2"},
			},
			mockObjects: map[string][]byte{
				"v2.tar": []byte("test data for tar"),
			},
			wantDownloaded: map[string]bool{
				"v2.tar": true,
			},
		},
		{
			name: "package not found",
			packages: []cache.Package{
				s3TestPackage{versionStr: "v3", fullName: "pkg3"},
			},
			mockObjects:    map[string][]byte{},
			wantDownloaded: map[string]bool{},
		},
		{
			name: "download failure with retry success",
			packages: []cache.Package{
				s3TestPackage{versionStr: "v4", fullName: "pkg4"},
			},
			mockObjects: map[string][]byte{
				"v4.tar.gz": []byte("test data"),
			},
			downloadDelay: 10 * time.Millisecond, // Simulate network latency
			wantDownloaded: map[string]bool{
				"v4.tar.gz": true,
			},
		},
		{
			name: "package version error",
			packages: []cache.Package{
				s3TestPackage{versionStr: "", fullName: "pkg5", versionErr: errors.New("version error")},
			},
			mockObjects:    map[string][]byte{},
			wantDownloaded: map[string]bool{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clean up the temp directory
			files, _ := filepath.Glob(filepath.Join(tmpDir, "*"))
			for _, f := range files {
				if err := os.Remove(f); err != nil {
					t.Logf("Failed to remove test file %s: %v", f, err)
				}
			}

			mockStorage := &mockS3Storage{
				objects:       tt.mockObjects,
				failDownload:  tt.failDownload,
				downloadDelay: tt.downloadDelay,
			}

			s3Cache := &S3Cache{
				storage:     mockStorage,
				workerCount: 1,
			}

			err := s3Cache.Download(context.Background(), localCache, tt.packages)

			// We always return nil from Download now to continue with local builds
			if err != nil {
				t.Errorf("expected no error but got %v", err)
			}

			// Check if expected files were downloaded
			for pkg, expectedDownload := range tt.wantDownloaded {
				// We need to look for the file based on the version as that's how the local cache stores it
				// Extract the version from the package name (v1, v2, etc.)
				version := strings.TrimSuffix(strings.TrimSuffix(pkg, ".tar.gz"), ".tar")
				path := filepath.Join(tmpDir, pkg)
				_, err := os.Stat(path)
				fileExists := err == nil

				if expectedDownload && !fileExists {
					// Check if any file with the version prefix exists
					matches, _ := filepath.Glob(filepath.Join(tmpDir, version+"*"))
					if len(matches) == 0 {
						t.Errorf("expected a file for package %s to be downloaded but none was found", pkg)
					}
				} else if !expectedDownload && fileExists {
					t.Errorf("didn't expect file %s to be downloaded but it was", pkg)
				}

				if fileExists {
					data, _ := os.ReadFile(path)
					if !cmp.Equal(data, mockStorage.objects[pkg]) {
						t.Errorf("file contents mismatch for %s", pkg)
					}
				}
			}
		})
	}
}
