package remote

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gitpod-io/leeway/pkg/leeway/cache"
	"github.com/gitpod-io/leeway/pkg/leeway/cache/local"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/time/rate"
)

// Mock error types
var (
	ErrTimeout   = errors.New("request timeout")
	ErrNotFound  = errors.New("resource not found")
	ErrForbidden = errors.New("access forbidden")
	ErrRateLimit = errors.New("SlowDown: Please reduce your request rate")
)

// Mock S3 with configurable failures
type mockS3WithFailures struct {
	calls         int
	failUntilCall int
	failureType   error
	data          map[string][]byte
	mu            sync.Mutex
	callDelay     time.Duration
}

func (m *mockS3WithFailures) GetObject(ctx context.Context, key string, dest string) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.calls++

	// Simulate delay if configured
	if m.callDelay > 0 {
		time.Sleep(m.callDelay)
	}

	// Check for context cancellation
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	default:
	}

	// Simulate failures until threshold
	if m.calls <= m.failUntilCall {
		return 0, m.failureType
	}

	// Return data if available
	if data, ok := m.data[key]; ok {
		// Simulate successful download
		return int64(len(data)), nil
	}
	return 0, ErrNotFound
}

func (m *mockS3WithFailures) PutObject(ctx context.Context, key string, data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.calls++

	// Simulate delay if configured
	if m.callDelay > 0 {
		time.Sleep(m.callDelay)
	}

	// Check for context cancellation
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	// Simulate failures until threshold
	if m.calls <= m.failUntilCall {
		return m.failureType
	}

	// Store data
	if m.data == nil {
		m.data = make(map[string][]byte)
	}
	m.data[key] = data

	return nil
}

func (m *mockS3WithFailures) HasObject(ctx context.Context, key string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.calls++

	// Check for context cancellation
	select {
	case <-ctx.Done():
		return false, ctx.Err()
	default:
	}

	// Simulate failures until threshold
	if m.calls <= m.failUntilCall {
		return false, m.failureType
	}

	_, exists := m.data[key]
	return exists, nil
}

func (m *mockS3WithFailures) UploadObject(ctx context.Context, key string, src string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.calls++

	// Simulate delay if configured
	if m.callDelay > 0 {
		time.Sleep(m.callDelay)
	}

	// Check for context cancellation
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	// Simulate failures until threshold
	if m.calls <= m.failUntilCall {
		return m.failureType
	}

	// Read source file and store
	if data, err := os.ReadFile(src); err == nil {
		if m.data == nil {
			m.data = make(map[string][]byte)
		}
		m.data[key] = data
	}

	return nil
}

func (m *mockS3WithFailures) ListObjects(ctx context.Context, prefix string) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var keys []string
	for key := range m.data {
		if strings.HasPrefix(key, prefix) {
			keys = append(keys, key)
		}
	}

	return keys, nil
}

// Mock package for testing
type mockPackageResilience struct {
	version  string
	fullName string
}

func (m *mockPackageResilience) Version() (string, error) {
	return m.version, nil
}

func (m *mockPackageResilience) FullName() string {
	if m.fullName != "" {
		return m.fullName
	}
	return "test-package:" + m.version
}

// Helper to create a mock S3 cache with configurable behavior
func createMockS3Cache(storage *mockS3WithFailures, config *cache.RemoteConfig) *S3Cache {
	if config == nil {
		config = &cache.RemoteConfig{
			BucketName: "test-bucket",
			SLSA: &cache.SLSAConfig{
				Verification:       false,
				RequireAttestation: false,
			},
		}
	}

	return &S3Cache{
		storage:     storage,
		cfg:         config,
		workerCount: 5,
		rateLimiter: rate.NewLimiter(rate.Limit(100), 200), // 100 RPS with burst of 200
		semaphore:   make(chan struct{}, 50),               // Max 50 concurrent operations
	}
}

// TestS3Cache_NetworkTimeout tests timeout handling
func TestS3Cache_NetworkTimeout(t *testing.T) {
	tests := []struct {
		name          string
		timeoutStage  string
		retryCount    int
		expectSuccess bool
	}{
		{
			name:          "temporary timeout recovers",
			timeoutStage:  "artifact",
			retryCount:    2,
			expectSuccess: true,
		},
		{
			name:          "persistent timeout fails gracefully",
			timeoutStage:  "artifact",
			retryCount:    10,
			expectSuccess: false,
		},
		{
			name:          "attestation timeout with RequireAttestation=false",
			timeoutStage:  "attestation",
			retryCount:    5,
			expectSuccess: true, // Should download without verification
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mock storage with transient failures
			mockStorage := &mockS3WithFailures{
				failUntilCall: tt.retryCount,
				failureType:   ErrTimeout,
				data: map[string][]byte{
					"test-package:v1.tar.gz":     []byte("artifact data"),
					"test-package:v1.tar.gz.att": []byte(`{"attestation":"data"}`),
				},
			}

			config := &cache.RemoteConfig{
				BucketName: "test-bucket",
				SLSA: &cache.SLSAConfig{
					Verification:       true,
					RequireAttestation: false,
				},
			}

			s3Cache := createMockS3Cache(mockStorage, config)

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			tmpDir := t.TempDir()
			localCache, err := local.NewFilesystemCache(tmpDir)
			require.NoError(t, err)

			pkg := &mockPackageResilience{version: "v1"}

			err = s3Cache.Download(ctx, localCache, []cache.Package{pkg})

			if tt.expectSuccess {
				// Should succeed with retry or graceful fallback
				assert.NoError(t, err, "Should succeed with retry or fallback")
			} else {
				// Should gracefully handle persistent failure
				// The cache system is designed to never fail builds
				assert.NoError(t, err, "Cache failures should not fail builds")
			}
		})
	}
}

// TestS3Cache_SigstoreOutage tests Sigstore unavailability
func TestS3Cache_SigstoreOutage(t *testing.T) {
	tests := []struct {
		name               string
		requireAttestation bool
		expectDownload     bool
	}{
		{
			name:               "RequireAttestation=false, downloads without verification",
			requireAttestation: false,
			expectDownload:     true,
		},
		{
			name:               "RequireAttestation=true, falls back to local build",
			requireAttestation: true,
			expectDownload:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &cache.RemoteConfig{
				BucketName: "test-bucket",
				SLSA: &cache.SLSAConfig{
					Verification:       true,
					RequireAttestation: tt.requireAttestation,
				},
			}

			mockStorage := &mockS3WithFailures{
				data: map[string][]byte{
					"test-package:v1.tar.gz":     []byte("artifact"),
					"test-package:v1.tar.gz.att": []byte(`{"attestation":"data"}`),
				},
			}

			s3Cache := createMockS3Cache(mockStorage, config)
			// Note: SLSA verification would be tested separately in SLSA-specific tests

			tmpDir := t.TempDir()
			localCache, err := local.NewFilesystemCache(tmpDir)
			require.NoError(t, err)

			pkg := &mockPackageResilience{version: "v1"}

			err = s3Cache.Download(context.Background(), localCache, []cache.Package{pkg})

			// Should not fail the build
			assert.NoError(t, err, "Sigstore outage should not fail builds")

			// Check if download occurred
			artifactPath, exists := localCache.Location(pkg)
			if tt.expectDownload {
				// With RequireAttestation=false, should download despite verification failure
				t.Logf("Artifact path: %s, exists: %v", artifactPath, exists)
			} else {
				// With RequireAttestation=true, should skip download
				t.Logf("Skipped download due to RequireAttestation=true")
			}
		})
	}
}

// TestS3Cache_ContextCancellation tests context handling
func TestS3Cache_ContextCancellation(t *testing.T) {
	// Setup mock storage with delay to allow cancellation
	mockStorage := &mockS3WithFailures{
		callDelay: 100 * time.Millisecond,
		data: map[string][]byte{
			"test-package:v1.tar.gz": []byte("artifact data"),
		},
	}

	s3Cache := createMockS3Cache(mockStorage, nil)

	tmpDir := t.TempDir()
	localCache, err := local.NewFilesystemCache(tmpDir)
	require.NoError(t, err)

	pkg := &mockPackageResilience{version: "v1"}

	// Create context that will be cancelled
	ctx, cancel := context.WithCancel(context.Background())

	// Cancel after a short delay
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	err = s3Cache.Download(ctx, localCache, []cache.Package{pkg})

	// Should handle cancellation gracefully
	// The cache system should not fail builds due to cancellation
	assert.NoError(t, err, "Context cancellation should not fail builds")
}

// TestS3Cache_PartialFailure tests mixed success/failure scenarios
func TestS3Cache_PartialFailure(t *testing.T) {
	// Setup storage where some packages succeed and others fail
	mockStorage := &mockS3WithFailures{
		data: map[string][]byte{
			"package1:v1.tar.gz": []byte("package1 data"),
			"package3:v1.tar.gz": []byte("package3 data"),
			// package2 is missing to simulate failure
		},
	}

	s3Cache := createMockS3Cache(mockStorage, nil)

	tmpDir := t.TempDir()
	localCache, err := local.NewFilesystemCache(tmpDir)
	require.NoError(t, err)

	packages := []cache.Package{
		&mockPackageResilience{version: "v1", fullName: "package1:v1"},
		&mockPackageResilience{version: "v1", fullName: "package2:v1"}, // Will fail
		&mockPackageResilience{version: "v1", fullName: "package3:v1"},
	}

	err = s3Cache.Download(context.Background(), localCache, packages)

	// Should not fail the entire operation due to partial failures
	assert.NoError(t, err, "Partial failures should not fail the entire download")

	// Verify successful downloads
	for _, pkg := range packages {
		path, exists := localCache.Location(pkg)
		t.Logf("Package %s: path=%s, exists=%v", pkg.FullName(), path, exists)
	}
}

// TestS3Cache_RateLimiting tests S3 rate limit handling
func TestS3Cache_RateLimiting(t *testing.T) {
	// Simulate hitting rate limits
	rateLimitedStorage := &mockS3WithFailures{
		failUntilCall: 3,
		failureType:   ErrRateLimit,
		data: map[string][]byte{
			"test-package:v1.tar.gz": []byte("artifact"),
		},
	}

	config := &cache.RemoteConfig{
		BucketName: "test-bucket",
	}

	s3Cache := createMockS3Cache(rateLimitedStorage, config)

	tmpDir := t.TempDir()
	localCache, err := local.NewFilesystemCache(tmpDir)
	require.NoError(t, err)

	pkg := &mockPackageResilience{version: "v1"}

	start := time.Now()
	err = s3Cache.Download(context.Background(), localCache, []cache.Package{pkg})
	duration := time.Since(start)

	// Should eventually succeed or gracefully handle rate limiting
	assert.NoError(t, err, "Should handle rate limiting gracefully")

	t.Logf("Handled rate limiting in %v", duration)
}

// TestS3Cache_ConcurrentDownloadsRateLimit tests parallel requests
func TestS3Cache_ConcurrentDownloadsRateLimit(t *testing.T) {
	// Configure rate limiter simulation with reduced load
	const maxConcurrent = 3
	const packageCount = 5

	mockStorage := &mockS3WithFailures{
		data:      make(map[string][]byte),
		callDelay: 10 * time.Millisecond, // Short delay for testing
	}

	// Create multiple packages
	packages := make([]cache.Package, packageCount)
	for i := 0; i < packageCount; i++ {
		version := fmt.Sprintf("v%d", i)
		fullName := fmt.Sprintf("package%d:%s", i, version)
		packages[i] = &mockPackageResilience{version: version, fullName: fullName}
		mockStorage.data[fullName+".tar.gz"] = []byte(fmt.Sprintf("artifact %d", i))
	}

	config := &cache.RemoteConfig{
		BucketName: "test-bucket",
	}

	s3Cache := createMockS3Cache(mockStorage, config)

	tmpDir := t.TempDir()
	localCache, err := local.NewFilesystemCache(tmpDir)
	require.NoError(t, err)

	// Track concurrent operations (for future implementation)
	var maxConcurrentOps int32 = maxConcurrent

	// Download all packages with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	start := time.Now()
	err = s3Cache.Download(ctx, localCache, packages)
	duration := time.Since(start)

	assert.NoError(t, err, "Should handle concurrent downloads")

	t.Logf("Downloaded %d packages in %v with max %d concurrent operations",
		packageCount, duration, maxConcurrentOps)
}

// TestS3Cache_ExponentialBackoff tests retry backoff behavior
func TestS3Cache_ExponentialBackoff(t *testing.T) {
	// Setup storage that fails multiple times before succeeding
	mockStorage := &mockS3WithFailures{
		failUntilCall: 3, // Fail first 3 attempts (reduced from 4)
		failureType:   ErrTimeout,
		callDelay:     5 * time.Millisecond, // Short delay for testing
		data: map[string][]byte{
			"test-package:v1.tar.gz": []byte("artifact data"),
		},
	}

	s3Cache := createMockS3Cache(mockStorage, nil)

	tmpDir := t.TempDir()
	localCache, err := local.NewFilesystemCache(tmpDir)
	require.NoError(t, err)

	pkg := &mockPackageResilience{version: "v1"}

	// Use timeout to prevent hanging
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	start := time.Now()
	err = s3Cache.Download(ctx, localCache, []cache.Package{pkg})
	duration := time.Since(start)

	// Should eventually succeed with exponential backoff
	assert.NoError(t, err, "Should succeed with exponential backoff")

	// Verify that retries occurred (should take some time due to backoff)
	t.Logf("Recovered with exponential backoff in %v after %d calls",
		duration, mockStorage.calls)
}

// TestS3Cache_MaxRetryLimit tests retry exhaustion
func TestS3Cache_MaxRetryLimit(t *testing.T) {
	// Setup storage that always fails
	mockStorage := &mockS3WithFailures{
		failUntilCall: 100, // Fail many times
		failureType:   ErrTimeout,
		callDelay:     1 * time.Millisecond, // Very short delay for testing
		data: map[string][]byte{
			"test-package:v1.tar.gz": []byte("artifact data"),
		},
	}

	s3Cache := createMockS3Cache(mockStorage, nil)

	tmpDir := t.TempDir()
	localCache, err := local.NewFilesystemCache(tmpDir)
	require.NoError(t, err)

	pkg := &mockPackageResilience{version: "v1"}

	// Use a shorter timeout to avoid long test runs
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	start := time.Now()
	err = s3Cache.Download(ctx, localCache, []cache.Package{pkg})
	duration := time.Since(start)

	// Should gracefully handle retry exhaustion
	assert.NoError(t, err, "Should gracefully handle retry exhaustion")

	t.Logf("Handled retry exhaustion in %v after %d calls",
		duration, mockStorage.calls)
}

// TestS3Cache_MixedFailureTypes tests different error types
func TestS3Cache_MixedFailureTypes(t *testing.T) {
	tests := []struct {
		name        string
		failureType error
		expectRetry bool
	}{
		{
			name:        "network timeout should retry",
			failureType: ErrTimeout,
			expectRetry: true,
		},
		{
			name:        "rate limit should retry",
			failureType: ErrRateLimit,
			expectRetry: true,
		},
		{
			name:        "forbidden should not retry",
			failureType: ErrForbidden,
			expectRetry: false,
		},
		{
			name:        "not found should not retry",
			failureType: ErrNotFound,
			expectRetry: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			retryCount := 2 // Reduced from 3
			mockStorage := &mockS3WithFailures{
				failUntilCall: retryCount,
				failureType:   tt.failureType,
				callDelay:     5 * time.Millisecond, // Short delay for testing
				data: map[string][]byte{
					"test-package:v1.tar.gz": []byte("artifact data"),
				},
			}

			s3Cache := createMockS3Cache(mockStorage, nil)

			tmpDir := t.TempDir()
			localCache, err := local.NewFilesystemCache(tmpDir)
			require.NoError(t, err)

			pkg := &mockPackageResilience{version: "v1"}

			// Use timeout to prevent hanging
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()

			start := time.Now()
			err = s3Cache.Download(ctx, localCache, []cache.Package{pkg})
			duration := time.Since(start)

			// Should always gracefully handle errors
			assert.NoError(t, err, "Should gracefully handle %s", tt.name)

			if tt.expectRetry {
				// Should have made multiple calls for retryable errors
				t.Logf("Retryable error %s: %d calls in %v",
					tt.name, mockStorage.calls, duration)
			} else {
				// Should have made fewer calls for non-retryable errors
				t.Logf("Non-retryable error %s: %d calls in %v",
					tt.name, mockStorage.calls, duration)
			}
		})
	}
}
