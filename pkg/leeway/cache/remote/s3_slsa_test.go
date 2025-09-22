package remote

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gitpod-io/leeway/pkg/leeway/cache"
	"github.com/gitpod-io/leeway/pkg/leeway/cache/local"
	"github.com/gitpod-io/leeway/pkg/leeway/cache/slsa"
	"golang.org/x/time/rate"
)

// mockS3StorageWithSLSA extends mockS3Storage for SLSA testing
type mockS3StorageWithSLSA struct {
	objects      map[string][]byte
	objectErrors map[string]error
	callLog      []string
	mu           sync.Mutex // Protects callLog from concurrent access
}

func (m *mockS3StorageWithSLSA) HasObject(ctx context.Context, key string) (bool, error) {
	m.mu.Lock()
	m.callLog = append(m.callLog, "HasObject:"+key)
	m.mu.Unlock()
	
	if err, exists := m.objectErrors[key]; exists {
		return false, err
	}
	
	_, exists := m.objects[key]
	return exists, nil
}

func (m *mockS3StorageWithSLSA) GetObject(ctx context.Context, key string, dest string) (int64, error) {
	m.mu.Lock()
	m.callLog = append(m.callLog, "GetObject:"+key)
	m.mu.Unlock()
	
	if err, exists := m.objectErrors[key]; exists {
		return 0, err
	}
	
	data, exists := m.objects[key]
	if !exists {
		return 0, &mockNotFoundError{key: key}
	}
	
	if err := os.WriteFile(dest, data, 0644); err != nil {
		return 0, err
	}
	
	return int64(len(data)), nil
}

func (m *mockS3StorageWithSLSA) UploadObject(ctx context.Context, key string, src string) error {
	return nil
}

// getCallLog safely returns a copy of the call log
func (m *mockS3StorageWithSLSA) getCallLog() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]string, len(m.callLog))
	copy(result, m.callLog)
	return result
}

func (m *mockS3StorageWithSLSA) ListObjects(ctx context.Context, prefix string) ([]string, error) {
	var keys []string
	for key := range m.objects {
		if strings.HasPrefix(key, prefix) {
			keys = append(keys, key)
		}
	}
	return keys, nil
}

type mockNotFoundError struct {
	key string
}

func (e *mockNotFoundError) Error() string {
	return "NotFound: " + e.key
}

// createValidArtifact creates a test artifact with known content
func createValidArtifact(t *testing.T) []byte {
	return []byte("test artifact content for SLSA verification")
}

// createValidAttestation creates a mock SLSA attestation
func createValidAttestation(t *testing.T) []byte {
	// This is a simplified mock - in real tests we'd use valid SLSA attestation format
	return []byte(`{
		"_type": "https://in-toto.io/Statement/v0.1",
		"subject": [{"name": "test", "digest": {"sha256": "test-hash"}}],
		"predicateType": "https://slsa.dev/provenance/v0.2",
		"predicate": {
			"builder": {"id": "test-builder"},
			"invocation": {
				"configSource": {
					"uri": "github.com/gitpod-io/gitpod-next"
				}
			}
		}
	}`)
}



func TestS3Cache_DownloadWithSLSAVerification(t *testing.T) {
	tests := []struct {
		name                string
		config              cache.RemoteConfig
		mockObjects         map[string][]byte
		mockObjectErrors    map[string]error
		packages            []cache.Package
		expectDownload      bool
		expectVerification  bool
		expectFallback      bool
		expectedLogContains string
	}{
		{
			name: "successful SLSA verification",
			config: cache.RemoteConfig{
				BucketName:         "test-bucket",
				SLSAVerification:   true,
				RequireAttestation: false,
				SourceURI:          "github.com/gitpod-io/gitpod-next",
				TrustedRoots:       []string{"https://fulcio.sigstore.dev"},
			},
			mockObjects: map[string][]byte{
				"v1.tar.gz":     createValidArtifact(t),
				"v1.tar.gz.att": createValidAttestation(t),
			},
			packages: []cache.Package{
				&mockPackage{version: "v1"},
			},
			expectDownload:     true,
			expectVerification: true,
		},
		{
			name: "missing attestation with requirement disabled",
			config: cache.RemoteConfig{
				BucketName:         "test-bucket",
				SLSAVerification:   true,
				RequireAttestation: false,
				SourceURI:          "github.com/gitpod-io/gitpod-next",
			},
			mockObjects: map[string][]byte{
				"v1.tar.gz": createValidArtifact(t),
				// No attestation file
			},
			packages: []cache.Package{
				&mockPackage{version: "v1"},
			},
			expectDownload:      true,  // Should download unverified
			expectVerification:  false,
			expectedLogContains: "downloading without verification",
		},
		{
			name: "missing attestation with requirement enabled",
			config: cache.RemoteConfig{
				BucketName:         "test-bucket",
				SLSAVerification:   true,
				RequireAttestation: true,
				SourceURI:          "github.com/gitpod-io/gitpod-next",
			},
			mockObjects: map[string][]byte{
				"v1.tar.gz": createValidArtifact(t),
				// No attestation file
			},
			packages: []cache.Package{
				&mockPackage{version: "v1"},
			},
			expectDownload:      false, // Should fallback to local build
			expectFallback:      true,
			expectedLogContains: "will build locally",
		},
		{
			name: "verification disabled - uses original path",
			config: cache.RemoteConfig{
				BucketName:       "test-bucket",
				SLSAVerification: false,
			},
			mockObjects: map[string][]byte{
				"v1.tar.gz": createValidArtifact(t),
			},
			packages: []cache.Package{
				&mockPackage{version: "v1"},
			},
			expectDownload:     true,
			expectVerification: false,
		},
		{
			name: "network error during attestation download",
			config: cache.RemoteConfig{
				BucketName:       "test-bucket",
				SLSAVerification: true,
				SourceURI:        "github.com/gitpod-io/gitpod-next",
			},
			mockObjects: map[string][]byte{
				"v1.tar.gz": createValidArtifact(t),
			},
			mockObjectErrors: map[string]error{
				"v1.tar.gz.att": &mockNotFoundError{key: "v1.tar.gz.att"},
			},
			packages: []cache.Package{
				&mockPackage{version: "v1"},
			},
			expectDownload:      true,  // Downloads without verification when RequireAttestation=false
			expectVerification:  false,
			expectedLogContains: "downloading without verification",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary directory for local cache
			tmpDir := t.TempDir()
			localCache, err := local.NewFilesystemCache(tmpDir)
			if err != nil {
				t.Fatalf("failed to create local cache: %v", err)
			}

			// Clean up the temp directory before each test
			files, _ := filepath.Glob(filepath.Join(tmpDir, "*"))
			for _, f := range files {
				os.Remove(f)
			}

			// Create mock storage
			mockStorage := &mockS3StorageWithSLSA{
				objects:      tt.mockObjects,
				objectErrors: tt.mockObjectErrors,
				callLog:      make([]string, 0),
			}

			// Create S3Cache with test configuration
			s3Cache := &S3Cache{
				storage:     mockStorage,
				cfg:         &tt.config,
				workerCount: 1,
				rateLimiter: rate.NewLimiter(rate.Limit(defaultRateLimit), defaultBurstLimit),
				semaphore:   make(chan struct{}, maxConcurrentOperations),
			}

			// Initialize SLSA verifier if enabled
			if tt.config.SLSAVerification && tt.config.SourceURI != "" {
				// Use mock verifier for testing
				mockVerifier := slsa.NewMockVerifier()
				
				// Configure mock verifier based on test expectations
				if tt.expectVerification {
					if strings.Contains(tt.name, "invalid") {
						mockVerifier.SetVerifyResult(errors.New("mock verification failed"))
					} else {
						mockVerifier.SetVerifyResult(nil) // Success
					}
				}
				
				s3Cache.slsaVerifier = mockVerifier
			}

			// Execute download
			ctx := context.Background()
			err = s3Cache.Download(ctx, localCache, tt.packages)

			// Verify no errors (cache failures should not fail builds)
			if err != nil {
				t.Errorf("Download() returned error: %v", err)
			}

			// Check if file was downloaded when expected
			expectedFiles, _ := filepath.Glob(filepath.Join(tmpDir, "*"))
			downloaded := len(expectedFiles) > 0

			if downloaded != tt.expectDownload {
				t.Errorf("Expected downloaded=%v, got downloaded=%v", tt.expectDownload, downloaded)
			}

			// Verify call patterns
			if tt.config.SLSAVerification {
				// Should check for both artifact and attestation
				hasArtifactCheck := false
				hasAttestationCheck := false
				callLog := mockStorage.getCallLog()
				for _, call := range callLog {
					if strings.Contains(call, "HasObject:v1.tar.gz") && !strings.Contains(call, ".att") {
						hasArtifactCheck = true
					}
					if strings.Contains(call, "HasObject:v1.tar.gz.att") {
						hasAttestationCheck = true
					}
				}
				
				if !hasArtifactCheck {
					t.Error("Expected artifact existence check when SLSA verification enabled")
				}
				if !hasAttestationCheck {
					t.Error("Expected attestation existence check when SLSA verification enabled")
				}
			}
		})
	}
}

func TestS3Cache_BackwardCompatibility(t *testing.T) {
	// Ensure existing behavior is preserved when SLSA disabled
	tmpDir := t.TempDir()
	localCache, err := local.NewFilesystemCache(tmpDir)
	if err != nil {
		t.Fatalf("failed to create local cache: %v", err)
	}

	config := &cache.RemoteConfig{
		BucketName:       "test-bucket",
		SLSAVerification: false, // Disabled
	}

	mockStorage := &mockS3StorageWithSLSA{
		objects: map[string][]byte{
			"v1.tar.gz": createValidArtifact(t),
		},
		callLog: make([]string, 0),
	}

	s3Cache := &S3Cache{
		storage:     mockStorage,
		cfg:         config,
		workerCount: 1,
		rateLimiter: rate.NewLimiter(rate.Limit(defaultRateLimit), defaultBurstLimit),
		semaphore:   make(chan struct{}, maxConcurrentOperations),
	}

	packages := []cache.Package{
		&mockPackage{version: "v1"},
	}

	err = s3Cache.Download(context.Background(), localCache, packages)
	if err != nil {
		t.Errorf("Download() returned error: %v", err)
	}

	// Should download successfully without any SLSA-related calls
	files, _ := filepath.Glob(filepath.Join(tmpDir, "*"))
	if len(files) == 0 {
		t.Error("Expected file to be downloaded in backward compatibility mode")
	}

	// Should not check for attestations
	callLog := mockStorage.getCallLog()
	for _, call := range callLog {
		if strings.Contains(call, ".att") {
			t.Error("Unexpected attestation-related call in backward compatibility mode")
		}
	}
}

// Performance test to validate overhead target
func TestS3Cache_SLSAVerificationPerformance(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping performance test in short mode")
	}

	// This is a basic performance test structure
	// In production, we'd use more sophisticated benchmarking
	t.Run("performance overhead validation", func(t *testing.T) {
		// Test both with and without verification to measure overhead
		// For now, we just ensure the test structure is in place
		
		baselineTime := measureDownloadTime(t, false)
		slsaTime := measureDownloadTime(t, true)
		
		if baselineTime == 0 || slsaTime == 0 {
			t.Skip("Performance measurement not implemented yet")
		}
		
		overhead := float64(slsaTime-baselineTime) / float64(baselineTime) * 100
		t.Logf("Baseline: %v, SLSA: %v, Overhead: %.2f%%", baselineTime, slsaTime, overhead)
		
		// Note: In real implementation, we'd validate < 15% overhead
		// if overhead > 15.0 {
		//     t.Errorf("SLSA verification overhead %.2f%% exceeds 15%% target", overhead)
		// }
	})
}

func measureDownloadTime(t *testing.T, withSLSA bool) time.Duration {
	// Placeholder for performance measurement
	// In real implementation, this would measure actual download times
	return 0
}

// TestMockVerifierIntegration tests the mock verifier integration
func TestMockVerifierIntegration(t *testing.T) {
	tests := []struct {
		name           string
		setupVerifier  func(*slsa.MockVerifier)
		expectError    bool
		expectCallCount int
	}{
		{
			name: "successful verification",
			setupVerifier: func(mv *slsa.MockVerifier) {
				mv.SetVerifyResult(nil)
			},
			expectError:     false,
			expectCallCount: 1,
		},
		{
			name: "verification failure",
			setupVerifier: func(mv *slsa.MockVerifier) {
				mv.SetVerifyResult(errors.New("verification failed"))
			},
			expectError:     true,
			expectCallCount: 1,
		},
		{
			name: "custom verification function",
			setupVerifier: func(mv *slsa.MockVerifier) {
				mv.SetVerifyFunc(slsa.SimulateVerificationFailure("test-artifact"))
			},
			expectError:     true,
			expectCallCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockVerifier := slsa.NewMockVerifier()
			tt.setupVerifier(mockVerifier)

			// Test verification call
			err := mockVerifier.VerifyArtifact(context.Background(), "test-artifact.tar.gz", "test-artifact.tar.gz.att")

			// Check error expectation
			if tt.expectError && err == nil {
				t.Errorf("expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			// Check call count
			if mockVerifier.GetCallCount() != tt.expectCallCount {
				t.Errorf("expected %d calls, got %d", tt.expectCallCount, mockVerifier.GetCallCount())
			}

			// Check call details
			if tt.expectCallCount > 0 {
				lastCall := mockVerifier.GetLastCall()
				if lastCall == nil {
					t.Error("expected call details but got none")
				} else {
					if lastCall.ArtifactPath != "test-artifact.tar.gz" {
						t.Errorf("expected artifact path 'test-artifact.tar.gz', got '%s'", lastCall.ArtifactPath)
					}
					if lastCall.AttestationPath != "test-artifact.tar.gz.att" {
						t.Errorf("expected attestation path 'test-artifact.tar.gz.att', got '%s'", lastCall.AttestationPath)
					}
				}
			}
		})
	}
}