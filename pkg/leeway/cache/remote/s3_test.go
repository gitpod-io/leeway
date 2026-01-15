package remote

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"github.com/gitpod-io/leeway/pkg/leeway/cache"
	"github.com/google/go-cmp/cmp"
	"golang.org/x/time/rate"
)

// mockS3Client implements a mock S3 client for testing
type mockS3Client struct {
	headObjectFunc func(ctx context.Context, params *s3.HeadObjectInput, optFns ...func(*s3.Options)) (*s3.HeadObjectOutput, error)
	getObjectFunc  func(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error)
	putObjectFunc  func(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error)
}

func (m *mockS3Client) HeadObject(ctx context.Context, params *s3.HeadObjectInput, optFns ...func(*s3.Options)) (*s3.HeadObjectOutput, error) {
	if m.headObjectFunc != nil {
		return m.headObjectFunc(ctx, params, optFns...)
	}
	return nil, fmt.Errorf("HeadObject not implemented")
}

func (m *mockS3Client) GetObject(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	if m.getObjectFunc != nil {
		return m.getObjectFunc(ctx, params, optFns...)
	}
	return nil, fmt.Errorf("GetObject not implemented")
}

func (m *mockS3Client) PutObject(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	if m.putObjectFunc != nil {
		return m.putObjectFunc(ctx, params, optFns...)
	}
	return nil, fmt.Errorf("PutObject not implemented")
}

func (m *mockS3Client) AbortMultipartUpload(ctx context.Context, params *s3.AbortMultipartUploadInput, optFns ...func(*s3.Options)) (*s3.AbortMultipartUploadOutput, error) {
	return &s3.AbortMultipartUploadOutput{}, nil
}

func (m *mockS3Client) CompleteMultipartUpload(ctx context.Context, params *s3.CompleteMultipartUploadInput, optFns ...func(*s3.Options)) (*s3.CompleteMultipartUploadOutput, error) {
	return &s3.CompleteMultipartUploadOutput{}, nil
}

func (m *mockS3Client) CreateMultipartUpload(ctx context.Context, params *s3.CreateMultipartUploadInput, optFns ...func(*s3.Options)) (*s3.CreateMultipartUploadOutput, error) {
	return &s3.CreateMultipartUploadOutput{}, nil
}

func (m *mockS3Client) UploadPart(ctx context.Context, params *s3.UploadPartInput, optFns ...func(*s3.Options)) (*s3.UploadPartOutput, error) {
	return &s3.UploadPartOutput{}, nil
}

func TestS3Cache_ExistingPackages(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tests := []struct {
		name            string
		packages        []cache.Package
		mockHeadObject  func(key string) (*s3.HeadObjectOutput, error)
		expectedResults map[string]struct{}
		expectError     bool
	}{
		{
			name: "finds tar.gz package",
			packages: []cache.Package{
				&mockPackage{version: "v1"},
			},
			mockHeadObject: func(key string) (*s3.HeadObjectOutput, error) {
				if key == "v1.tar.gz" {
					return &s3.HeadObjectOutput{}, nil
				}
				return nil, &types.NoSuchKey{}
			},
			expectedResults: map[string]struct{}{
				"v1": {},
			},
		},
		{
			name: "finds tar package when tar.gz not found",
			packages: []cache.Package{
				&mockPackage{version: "v1"},
			},
			mockHeadObject: func(key string) (*s3.HeadObjectOutput, error) {
				if key == "v1.tar.gz" {
					return nil, &types.NoSuchKey{}
				}
				if key == "v1.tar" {
					return &s3.HeadObjectOutput{}, nil
				}
				return nil, &types.NoSuchKey{}
			},
			expectedResults: map[string]struct{}{
				"v1": {},
			},
		},
		{
			name: "package not found",
			packages: []cache.Package{
				&mockPackage{version: "v1"},
			},
			mockHeadObject: func(key string) (*s3.HeadObjectOutput, error) {
				return nil, &types.NoSuchKey{}
			},
			expectedResults: map[string]struct{}{},
		},
		{
			name: "version error",
			packages: []cache.Package{
				&mockPackage{version: "v1", err: errors.New("version error")},
			},
			mockHeadObject: func(key string) (*s3.HeadObjectOutput, error) {
				return &s3.HeadObjectOutput{}, nil
			},
			expectedResults: map[string]struct{}{},
			expectError:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &mockS3Client{
				headObjectFunc: func(ctx context.Context, params *s3.HeadObjectInput, optFns ...func(*s3.Options)) (*s3.HeadObjectOutput, error) {
					return tt.mockHeadObject(*params.Key)
				},
			}

			s3Cache := &S3Cache{
				storage: &S3Storage{
					client:     mockClient,
					bucketName: "test-bucket",
				},
				workerCount:         1,
				downloadWorkerCount: defaultDownloadWorkerCount,
				rateLimiter:         rate.NewLimiter(rate.Limit(defaultRateLimit), defaultBurstLimit),
				semaphore:           make(chan struct{}, maxConcurrentOperations),
			}

			results, err := s3Cache.ExistingPackages(ctx, tt.packages)
			if tt.expectError {
				if err == nil {
					t.Error("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			resultVersions := make(map[string]struct{})
			for pkg := range results {
				version, err := pkg.Version()
				if err != nil {
					t.Errorf("unexpected error getting version: %v", err)
					continue
				}
				resultVersions[version] = struct{}{}
			}
			if !cmp.Equal(tt.expectedResults, resultVersions) {
				t.Errorf("expected results %v, got %v", tt.expectedResults, resultVersions)
			}
		})
	}
}

func TestS3Cache_Download(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tmpDir, err := os.MkdirTemp("", "s3cache-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create test directories
	if err := os.MkdirAll(tmpDir, 0755); err != nil {
		t.Fatalf("failed to create test directories: %v", err)
	}

	// Mock local cache that will return paths in tmpDir
	mockLocalCache := &struct{ cache.LocalCache }{
		LocalCache: &testLocalCache{
			baseDir: tmpDir,
		},
	}

	tests := []struct {
		name          string
		packages      []cache.Package
		mockGetObject func(key string) (*s3.GetObjectOutput, error)
		localCache    cache.LocalCache
		expectedFiles []string
		expectError   bool
	}{
		{
			name: "downloads tar.gz package",
			packages: []cache.Package{
				s3TestPackage{versionStr: "v1", fullName: "pkg1"},
			},
			mockGetObject: func(key string) (*s3.GetObjectOutput, error) {
				if key == "v1.tar.gz" {
					// Return success and actually write the file
					path := filepath.Join(tmpDir, "v1.tar.gz")
					if err := os.WriteFile(path, []byte("test data"), 0644); err != nil {
						return nil, err
					}
					return &s3.GetObjectOutput{
						Body:          io.NopCloser(bytes.NewReader([]byte("test data"))),
						ContentLength: aws.Int64(9), // length of "test data"
					}, nil
				}
				return nil, &types.NoSuchKey{}
			},
			localCache:    mockLocalCache,
			expectedFiles: []string{"v1.tar.gz"},
		},
		{
			name: "downloads tar package when tar.gz fails",
			packages: []cache.Package{
				s3TestPackage{versionStr: "v2", fullName: "pkg2"},
			},
			mockGetObject: func(key string) (*s3.GetObjectOutput, error) {
				if key == "v2.tar.gz" {
					return nil, &types.NoSuchKey{}
				}
				if key == "v2.tar" {
					// Return success and actually write the file
					path := filepath.Join(tmpDir, "v2.tar")
					if err := os.WriteFile(path, []byte("test data for tar"), 0644); err != nil {
						return nil, err
					}
					return &s3.GetObjectOutput{
						Body:          io.NopCloser(bytes.NewReader([]byte("test data for tar"))),
						ContentLength: aws.Int64(16), // length of "test data for tar"
					}, nil
				}
				return nil, &types.NoSuchKey{}
			},
			localCache:    mockLocalCache,
			expectedFiles: []string{"v2.tar"},
		},
		{
			name: "fails when package not found",
			packages: []cache.Package{
				s3TestPackage{versionStr: "v3", fullName: "pkg3"},
			},
			mockGetObject: func(key string) (*s3.GetObjectOutput, error) {
				return nil, &types.NoSuchKey{}
			},
			localCache:    mockLocalCache,
			expectedFiles: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clean up any existing files
			files, _ := filepath.Glob(filepath.Join(tmpDir, "*"))
			for _, f := range files {
				os.Remove(f)
			}

			mockClient := &mockS3Client{
				getObjectFunc: func(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
					output, err := tt.mockGetObject(*params.Key)
					return output, err
				},
			}

			s3Cache := &S3Cache{
				storage: &S3Storage{
					client:     mockClient,
					bucketName: "test-bucket",
				},
				workerCount:         1,
				downloadWorkerCount: defaultDownloadWorkerCount,
				rateLimiter:         rate.NewLimiter(rate.Limit(defaultRateLimit), defaultBurstLimit),
				semaphore:           make(chan struct{}, maxConcurrentOperations),
			}

			results := s3Cache.Download(ctx, tt.localCache, tt.packages)
			if tt.expectError {
				// Check if any result has a failure status
				hasFailure := false
				for _, result := range results {
					if result.Status == cache.DownloadStatusFailed || result.Status == cache.DownloadStatusVerificationFailed {
						hasFailure = true
						break
					}
				}
				if !hasFailure {
					t.Error("expected error but got none")
				}
				return
			}

			// Check that we got results for all packages
			if len(results) != len(tt.packages) {
				t.Errorf("expected %d results, got %d", len(tt.packages), len(results))
				return
			}

			for _, expectedFile := range tt.expectedFiles {
				path := filepath.Join(tmpDir, expectedFile)
				if _, err := os.Stat(path); err != nil {
					// Try to list all files in the directory to help debugging
					files, _ := filepath.Glob(filepath.Join(tmpDir, "*"))
					t.Errorf("expected file %s to exist: %v. Directory contents: %v", path, err, files)
					continue
				}
				// Verify file contents
				data, err := os.ReadFile(path)
				if err != nil {
					t.Errorf("failed to read file %s: %v", path, err)
					continue
				}
				expectedContent := "test data"
				if strings.HasSuffix(expectedFile, ".tar") {
					expectedContent = "test data for tar"
				}
				if string(data) != expectedContent {
					t.Errorf("expected file %s to contain %q, got %q", path, expectedContent, string(data))
				}
			}
		})
	}
}

func TestS3Cache_Upload(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tmpDir, err := os.MkdirTemp("", "s3cache-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create test directories
	if err := os.MkdirAll(tmpDir, 0755); err != nil {
		t.Fatalf("failed to create test directories: %v", err)
	}

	tests := []struct {
		name          string
		packages      []cache.Package
		mockPutObject func(key string) error
		localCache    *mockLocalCache
		expectError   bool
	}{
		{
			name: "successful upload",
			packages: []cache.Package{
				&mockPackage{version: "v1"},
			},
			mockPutObject: func(key string) error {
				return nil
			},
			localCache: &mockLocalCache{
				locations: map[string]string{
					"v1": filepath.Join(tmpDir, "pkg1.tar.gz"),
				},
			},
		},
		{
			name: "403 forbidden error should not fail",
			packages: []cache.Package{
				&mockPackage{version: "v1"},
			},
			mockPutObject: func(key string) error {
				return &smithy.GenericAPIError{
					Code:    "Forbidden",
					Message: "Access Denied",
				}
			},
			localCache: &mockLocalCache{
				locations: map[string]string{
					"v1": filepath.Join(tmpDir, "pkg1.tar.gz"),
				},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test directories and files for each test case
			if !tt.expectError {
				for _, path := range tt.localCache.locations {
					dir := filepath.Dir(path)
					if err := os.MkdirAll(dir, 0755); err != nil {
						t.Fatalf("failed to create directory %s: %v", dir, err)
					}
					if err := os.WriteFile(path, []byte("test"), 0644); err != nil {
						t.Fatalf("failed to write test file %s: %v", path, err)
					}
				}
			}

			mockClient := &mockS3Client{
				putObjectFunc: func(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
					if tt.mockPutObject != nil {
						if err := tt.mockPutObject(*params.Key); err != nil {
							return nil, err
						}
					}
					return &s3.PutObjectOutput{}, nil
				},
			}

			s3Cache := &S3Cache{
				storage: &S3Storage{
					client:     mockClient,
					bucketName: "test-bucket",
				},
				workerCount:         1,
				downloadWorkerCount: defaultDownloadWorkerCount,
				rateLimiter:         rate.NewLimiter(rate.Limit(defaultRateLimit), defaultBurstLimit),
				semaphore:           make(chan struct{}, maxConcurrentOperations),
			}

			err := s3Cache.Upload(ctx, tt.localCache, tt.packages)
			if tt.expectError {
				if err == nil {
					t.Error("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

// testLocalCache is a simplified local cache implementation for testing
type testLocalCache struct {
	baseDir string
}

func (c *testLocalCache) Location(pkg cache.Package) (path string, exists bool) {
	version, err := pkg.Version()
	if err != nil {
		return "", false
	}

	// Check for .tar.gz file first
	gzPath := filepath.Join(c.baseDir, fmt.Sprintf("%s.tar.gz", version))
	if _, err := os.Stat(gzPath); err == nil {
		return gzPath, true
	}

	// Fall back to .tar file
	tarPath := filepath.Join(c.baseDir, fmt.Sprintf("%s.tar", version))
	if _, err := os.Stat(tarPath); err == nil {
		return tarPath, true
	}

	// Neither exists - return the tar.gz path for future creation
	return gzPath, false
}
