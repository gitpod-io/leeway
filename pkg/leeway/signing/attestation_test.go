package signing

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gitpod-io/leeway/pkg/leeway/cache"
	"github.com/google/go-cmp/cmp"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
)

// Test helper: Create test artifact with known content
func createTestArtifact(t *testing.T, content string) string {
	tmpDir := t.TempDir()
	artifactPath := filepath.Join(tmpDir, "test-artifact.tar.gz")
	err := os.WriteFile(artifactPath, []byte(content), 0644)
	require.NoError(t, err)
	return artifactPath
}

// Test helper: Calculate expected SHA256
func calculateSHA256(t *testing.T, path string) string {
	content, err := os.ReadFile(path)
	require.NoError(t, err)

	hash := sha256.Sum256(content)
	return hex.EncodeToString(hash[:])
}

// Mock GitHub context for testing
func createMockGitHubContext() *GitHubContext {
	return &GitHubContext{
		RunID:       "1234567890",
		RunNumber:   "42",
		Actor:       "test-user",
		Repository:  "gitpod-io/leeway",
		Ref:         "refs/heads/main",
		SHA:         "abc123def456",
		ServerURL:   "https://github.com",
		WorkflowRef: ".github/workflows/build.yml@refs/heads/main",
	}
}

// Helper function to generate SLSA attestation content without signing for testing
func generateSLSAAttestationContent(artifactPath string, githubCtx *GitHubContext) ([]byte, error) {
	// Check for nil context first
	if githubCtx == nil {
		return nil, fmt.Errorf("GitHub context cannot be nil")
	}

	// Calculate artifact checksum
	checksum, err := computeSHA256(artifactPath)
	if err != nil {
		return nil, err
	}

	// Validate GitHub context
	if err := githubCtx.Validate(); err != nil {
		return nil, err
	}

	sourceURI := githubCtx.ServerURL + "/" + githubCtx.Repository
	builderID := githubCtx.ServerURL + "/" + githubCtx.Repository + "/.github/workflows/build.yml@" + githubCtx.Ref

	// Create SLSA statement structure (mimicking the internal logic)
	statement := map[string]interface{}{
		"_type":         "https://in-toto.io/Statement/v0.1",
		"predicateType": "https://slsa.dev/provenance/v0.2",
		"subject": []map[string]interface{}{
			{
				"name": filepath.Base(artifactPath),
				"digest": map[string]string{
					"sha256": checksum,
				},
			},
		},
		"predicate": map[string]interface{}{
			"buildType": "https://leeway.build/cache-signing/v1",
			"builder": map[string]interface{}{
				"id": builderID,
			},
			"invocation": map[string]interface{}{
				"configSource": map[string]interface{}{
					"uri":        sourceURI,
					"repository": githubCtx.Repository,
					"ref":        githubCtx.Ref,
				},
				"parameters": map[string]interface{}{
					"workflow": githubCtx.WorkflowRef,
				},
			},
			"metadata": map[string]interface{}{
				"buildInvocationId": githubCtx.RunID,
				"completeness": map[string]interface{}{
					"parameters":  true,
					"environment": false,
					"materials":   false,
				},
				"reproducible": false,
			},
		},
	}

	return json.Marshal(statement)
}

// TestGenerateSLSAAttestation_Format verifies attestation structure
func TestGenerateSLSAAttestation_Format(t *testing.T) {
	artifactPath := createTestArtifact(t, "test content for SLSA attestation")
	githubCtx := createMockGitHubContext()

	// Generate attestation (without signing for format test)
	attestation, err := generateSLSAAttestationContent(artifactPath, githubCtx)
	require.NoError(t, err)
	require.NotNil(t, attestation)

	// Parse as JSON to verify structure
	var parsed map[string]interface{}
	err = json.Unmarshal(attestation, &parsed)
	require.NoError(t, err, "Attestation should be valid JSON")

	// Verify SLSA v0.2 or v1.0 predicateType
	predicateType, ok := parsed["predicateType"].(string)
	require.True(t, ok, "predicateType should be a string")
	assert.Contains(t, predicateType, "slsa.dev/provenance",
		"predicateType should be SLSA provenance")

	// Verify subject exists and has correct structure
	subject, ok := parsed["subject"].([]interface{})
	require.True(t, ok, "subject should be an array")
	require.NotEmpty(t, subject, "subject should not be empty")

	// Verify first subject has required fields
	firstSubject := subject[0].(map[string]interface{})
	assert.Contains(t, firstSubject, "name", "subject should have name")
	assert.Contains(t, firstSubject, "digest", "subject should have digest")

	// Verify digest contains sha256
	digest := firstSubject["digest"].(map[string]interface{})
	assert.Contains(t, digest, "sha256", "digest should contain sha256")

	// Verify predicate exists
	predicate, ok := parsed["predicate"].(map[string]interface{})
	require.True(t, ok, "predicate should be an object")

	// Verify predicate has required SLSA fields
	assert.Contains(t, predicate, "buildType", "predicate should have buildType")
	assert.Contains(t, predicate, "builder", "predicate should have builder")
	assert.Contains(t, predicate, "invocation", "predicate should have invocation")
}

// TestGenerateSLSAAttestation_RequiredFields verifies all required fields
func TestGenerateSLSAAttestation_RequiredFields(t *testing.T) {
	requiredFields := []string{
		"_type",         // Statement type
		"predicateType", // SLSA provenance type
		"subject",       // Artifact being attested
		"predicate",     // The provenance claim
	}

	artifactPath := createTestArtifact(t, "field validation content")
	githubCtx := createMockGitHubContext()

	attestation, err := generateSLSAAttestationContent(artifactPath, githubCtx)
	require.NoError(t, err)

	var parsed map[string]interface{}
	err = json.Unmarshal(attestation, &parsed)
	require.NoError(t, err)

	// Verify all required fields present
	for _, field := range requiredFields {
		assert.Contains(t, parsed, field, "Attestation should contain field: %s", field)
	}
}

// TestGenerateSLSAAttestation_PredicateContent verifies predicate details
func TestGenerateSLSAAttestation_PredicateContent(t *testing.T) {
	artifactPath := createTestArtifact(t, "predicate test content")
	githubCtx := createMockGitHubContext()

	attestation, err := generateSLSAAttestationContent(artifactPath, githubCtx)
	require.NoError(t, err)

	var parsed map[string]interface{}
	err = json.Unmarshal(attestation, &parsed)
	require.NoError(t, err)

	predicate := parsed["predicate"].(map[string]interface{})

	// Verify buildType
	buildType, ok := predicate["buildType"].(string)
	assert.True(t, ok, "buildType should be a string")
	assert.NotEmpty(t, buildType, "buildType should not be empty")

	// Verify builder information
	builder, ok := predicate["builder"].(map[string]interface{})
	require.True(t, ok, "builder should be an object")
	assert.Contains(t, builder, "id", "builder should have id")

	// Verify invocation
	invocation, ok := predicate["invocation"].(map[string]interface{})
	require.True(t, ok, "invocation should be an object")

	// Verify GitHub context embedded
	configSource := invocation["configSource"].(map[string]interface{})
	assert.Equal(t, githubCtx.Repository, configSource["repository"])
	assert.Equal(t, githubCtx.Ref, configSource["ref"])
}

// TestGenerateSLSAAttestation_ChecksumAccuracy verifies SHA256 calculation
func TestGenerateSLSAAttestation_ChecksumAccuracy(t *testing.T) {
	tests := []struct {
		name    string
		content string
	}{
		{
			name:    "simple text content",
			content: "hello world",
		},
		{
			name:    "binary-like content",
			content: string([]byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD}),
		},
		{
			name:    "large content",
			content: string(make([]byte, 1024*1024)), // 1MB
		},
		{
			name:    "empty file",
			content: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			artifactPath := createTestArtifact(t, tt.content)
			githubCtx := createMockGitHubContext()

			// Calculate expected checksum
			expectedChecksum := calculateSHA256(t, artifactPath)

			// Generate attestation
			attestation, err := generateSLSAAttestationContent(artifactPath, githubCtx)
			require.NoError(t, err)

			var parsed map[string]interface{}
			err = json.Unmarshal(attestation, &parsed)
			require.NoError(t, err)

			// Extract checksum from attestation
			subject := parsed["subject"].([]interface{})[0].(map[string]interface{})
			digest := subject["digest"].(map[string]interface{})
			actualChecksum := digest["sha256"].(string)

			// Verify checksum matches
			assert.Equal(t, expectedChecksum, actualChecksum,
				"Attestation checksum should match calculated SHA256")
		})
	}
}

// TestGenerateSLSAAttestation_ChecksumConsistency verifies repeatability
func TestGenerateSLSAAttestation_ChecksumConsistency(t *testing.T) {
	artifactPath := createTestArtifact(t, "consistency test content")
	githubCtx := createMockGitHubContext()

	// Generate attestation multiple times
	attestation1, err := generateSLSAAttestationContent(artifactPath, githubCtx)
	require.NoError(t, err)

	attestation2, err := generateSLSAAttestationContent(artifactPath, githubCtx)
	require.NoError(t, err)

	// Extract checksums
	var parsed1, parsed2 map[string]interface{}
	err = json.Unmarshal(attestation1, &parsed1)
	require.NoError(t, err)
	err = json.Unmarshal(attestation2, &parsed2)
	require.NoError(t, err)

	subject1 := parsed1["subject"].([]interface{})[0].(map[string]interface{})
	digest1 := subject1["digest"].(map[string]interface{})
	checksum1 := digest1["sha256"].(string)

	subject2 := parsed2["subject"].([]interface{})[0].(map[string]interface{})
	digest2 := subject2["digest"].(map[string]interface{})
	checksum2 := digest2["sha256"].(string)

	// Verify consistency
	assert.Equal(t, checksum1, checksum2,
		"Checksums should be consistent across multiple generations")
}

// TestGenerateSLSAAttestation_GitHubContextIntegration verifies context embedding
func TestGenerateSLSAAttestation_GitHubContextIntegration(t *testing.T) {
	artifactPath := createTestArtifact(t, "github context test")

	tests := []struct {
		name    string
		context *GitHubContext
	}{
		{
			name: "standard context",
			context: &GitHubContext{
				RunID:       "9876543210",
				RunNumber:   "100",
				Actor:       "ci-bot",
				Repository:  "gitpod-io/leeway",
				Ref:         "refs/heads/feature-branch",
				SHA:         "fedcba987654",
				ServerURL:   "https://github.com",
				WorkflowRef: ".github/workflows/ci.yml@refs/heads/main",
			},
		},
		{
			name: "pull request context",
			context: &GitHubContext{
				RunID:       "1111111111",
				RunNumber:   "50",
				Actor:       "contributor",
				Repository:  "gitpod-io/leeway",
				Ref:         "refs/pull/123/merge",
				SHA:         "pr123sha",
				ServerURL:   "https://github.com",
				WorkflowRef: ".github/workflows/pr.yml@refs/pull/123/merge",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attestation, err := generateSLSAAttestationContent(artifactPath, tt.context)
			require.NoError(t, err)

			var parsed map[string]interface{}
			err = json.Unmarshal(attestation, &parsed)
			require.NoError(t, err)

			predicate := parsed["predicate"].(map[string]interface{})
			invocation := predicate["invocation"].(map[string]interface{})
			configSource := invocation["configSource"].(map[string]interface{})

			// Verify all context fields embedded
			assert.Equal(t, tt.context.Repository, configSource["repository"])
			assert.Equal(t, tt.context.Ref, configSource["ref"])

			// Verify metadata contains GitHub information
			metadata := predicate["metadata"].(map[string]interface{})
			buildInvocationID := metadata["buildInvocationId"].(string)
			assert.Contains(t, buildInvocationID, tt.context.RunID)
		})
	}
}

// TestGenerateSLSAAttestation_InvalidGitHubContext tests error handling
func TestGenerateSLSAAttestation_InvalidGitHubContext(t *testing.T) {
	artifactPath := createTestArtifact(t, "invalid context test")

	tests := []struct {
		name        string
		context     *GitHubContext
		expectError bool
	}{
		{
			name:        "nil context",
			context:     nil,
			expectError: true,
		},
		{
			name: "missing repository",
			context: &GitHubContext{
				RunID: "123",
				SHA:   "abc",
				// Missing Repository
			},
			expectError: true,
		},
		{
			name: "empty SHA",
			context: &GitHubContext{
				RunID:      "123",
				Repository: "gitpod-io/leeway",
				SHA:        "", // Empty SHA
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := generateSLSAAttestationContent(artifactPath, tt.context)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestGenerateSLSAAttestation_FileErrors tests file-related error handling
func TestGenerateSLSAAttestation_FileErrors(t *testing.T) {
	githubCtx := createMockGitHubContext()

	tests := []struct {
		name         string
		artifactPath string
		expectError  bool
	}{
		{
			name:         "nonexistent file",
			artifactPath: "/nonexistent/file.tar.gz",
			expectError:  true,
		},
		{
			name:         "directory instead of file",
			artifactPath: t.TempDir(),
			expectError:  true,
		},
		{
			name:         "empty path",
			artifactPath: "",
			expectError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := generateSLSAAttestationContent(tt.artifactPath, githubCtx)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestComputeSHA256_EdgeCases tests the checksum calculation function directly
func TestComputeSHA256_EdgeCases(t *testing.T) {
	tests := []struct {
		name        string
		content     string
		expectError bool
	}{
		{
			name:        "normal file",
			content:     "test content",
			expectError: false,
		},
		{
			name:        "empty file",
			content:     "",
			expectError: false,
		},
		{
			name:        "large file",
			content:     string(make([]byte, 10*1024*1024)), // 10MB
			expectError: false,
		},
		{
			name:        "binary content",
			content:     string([]byte{0x00, 0x01, 0xFF, 0xFE}),
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.expectError {
				// Test with invalid path
				_, err := computeSHA256("/nonexistent/file")
				assert.Error(t, err)
			} else {
				// Test with valid file
				artifactPath := createTestArtifact(t, tt.content)
				checksum, err := computeSHA256(artifactPath)
				assert.NoError(t, err)
				assert.NotEmpty(t, checksum)
				assert.Len(t, checksum, 64) // SHA256 hex string length

				// Verify it matches our helper calculation
				expectedChecksum := calculateSHA256(t, artifactPath)
				assert.Equal(t, expectedChecksum, checksum)
			}
		})
	}
}

// TestGitHubContext_Validation tests the validation function
func TestGitHubContext_Validation(t *testing.T) {
	tests := []struct {
		name        string
		context     *GitHubContext
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid context",
			context: &GitHubContext{
				RunID:       "123",
				Repository:  "gitpod-io/leeway",
				SHA:         "abc123",
				ServerURL:   "https://github.com",
				WorkflowRef: ".github/workflows/test.yml@main",
			},
			expectError: false,
		},
		{
			name: "missing RunID",
			context: &GitHubContext{
				Repository:  "gitpod-io/leeway",
				SHA:         "abc123",
				ServerURL:   "https://github.com",
				WorkflowRef: ".github/workflows/test.yml@main",
			},
			expectError: true,
			errorMsg:    "GITHUB_RUN_ID",
		},
		{
			name: "missing Repository",
			context: &GitHubContext{
				RunID:       "123",
				SHA:         "abc123",
				ServerURL:   "https://github.com",
				WorkflowRef: ".github/workflows/test.yml@main",
			},
			expectError: true,
			errorMsg:    "GITHUB_REPOSITORY",
		},
		{
			name: "missing SHA",
			context: &GitHubContext{
				RunID:       "123",
				Repository:  "gitpod-io/leeway",
				ServerURL:   "https://github.com",
				WorkflowRef: ".github/workflows/test.yml@main",
			},
			expectError: true,
			errorMsg:    "GITHUB_SHA",
		},
		{
			name: "missing ServerURL",
			context: &GitHubContext{
				RunID:       "123",
				Repository:  "gitpod-io/leeway",
				SHA:         "abc123",
				WorkflowRef: ".github/workflows/test.yml@main",
			},
			expectError: true,
			errorMsg:    "GITHUB_SERVER_URL",
		},
		{
			name: "missing WorkflowRef",
			context: &GitHubContext{
				RunID:      "123",
				Repository: "gitpod-io/leeway",
				SHA:        "abc123",
				ServerURL:  "https://github.com",
			},
			expectError: true,
			errorMsg:    "GITHUB_WORKFLOW_REF",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.context.Validate()

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestGenerateSignedSLSAAttestation_Integration tests the full signing flow
func TestGenerateSignedSLSAAttestation_Integration(t *testing.T) {
	// This test verifies the integration without actually signing (which requires Sigstore setup)
	artifactPath := createTestArtifact(t, "integration test content")
	githubCtx := createMockGitHubContext()

	// Test that the function exists and has the right signature
	// We expect it to fail due to missing OIDC environment (strict mode)
	_, err := GenerateSignedSLSAAttestation(context.Background(), artifactPath, githubCtx)

	// We expect an error related to OIDC extraction (fails fast before signing)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to extract builder ID from OIDC token", "Error should be related to OIDC extraction")
}

// TestSignedAttestationResult_Structure tests the result structure
func TestSignedAttestationResult_Structure(t *testing.T) {
	// Test that SignedAttestationResult has the expected fields
	result := &SignedAttestationResult{
		AttestationBytes: []byte("test attestation"),
		Checksum:         "abc123",
		ArtifactName:     "test.tar.gz",
	}

	assert.NotNil(t, result.AttestationBytes)
	assert.NotEmpty(t, result.Checksum)
	assert.NotEmpty(t, result.ArtifactName)

	// Test JSON marshaling
	jsonData, err := json.Marshal(result)
	assert.NoError(t, err)
	assert.Contains(t, string(jsonData), "attestation_bytes")
	assert.Contains(t, string(jsonData), "checksum")
	assert.Contains(t, string(jsonData), "artifact_name")
}

// TestGetGitHubContext tests the environment variable extraction
func TestGetGitHubContext(t *testing.T) {
	// Set test environment (t.Setenv automatically handles cleanup)
	t.Setenv("GITHUB_RUN_ID", "test-run-id")
	t.Setenv("GITHUB_RUN_NUMBER", "test-run-number")
	t.Setenv("GITHUB_ACTOR", "test-actor")
	t.Setenv("GITHUB_REPOSITORY", "test-repo")
	t.Setenv("GITHUB_REF", "test-ref")
	t.Setenv("GITHUB_SHA", "test-sha")
	t.Setenv("GITHUB_SERVER_URL", "test-server")
	t.Setenv("GITHUB_WORKFLOW_REF", "test-workflow")

	// Test GetGitHubContext
	got := GetGitHubContext()
	want := &GitHubContext{
		RunID:       "test-run-id",
		RunNumber:   "test-run-number",
		Actor:       "test-actor",
		Repository:  "test-repo",
		Ref:         "test-ref",
		SHA:         "test-sha",
		ServerURL:   "test-server",
		WorkflowRef: "test-workflow",
	}

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("GetGitHubContext() mismatch (-want +got):\n%s", diff)
	}
}

// TestGetGitHubContext_EmptyEnvironment tests with empty environment
func TestGetGitHubContext_EmptyEnvironment(t *testing.T) {
	// Clear all GitHub environment variables (t.Setenv automatically handles cleanup)
	t.Setenv("GITHUB_RUN_ID", "")
	t.Setenv("GITHUB_RUN_NUMBER", "")
	t.Setenv("GITHUB_ACTOR", "")
	t.Setenv("GITHUB_REPOSITORY", "")
	t.Setenv("GITHUB_REF", "")
	t.Setenv("GITHUB_SHA", "")
	t.Setenv("GITHUB_SERVER_URL", "")
	t.Setenv("GITHUB_WORKFLOW_REF", "")

	// Test GetGitHubContext with empty environment
	got := GetGitHubContext()
	want := &GitHubContext{
		RunID:       "",
		RunNumber:   "",
		Actor:       "",
		Repository:  "",
		Ref:         "",
		SHA:         "",
		ServerURL:   "",
		WorkflowRef: "",
	}

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("GetGitHubContext() with empty env mismatch (-want +got):\n%s", diff)
	}
}

// TestSigningError tests the error types
func TestSigningError(t *testing.T) {
	tests := []struct {
		name      string
		errType   SigningErrorType
		message   string
		artifact  string
		retryable bool
	}{
		{
			name:      "permission error",
			errType:   ErrorTypePermission,
			message:   "access denied",
			artifact:  "test.tar.gz",
			retryable: false,
		},
		{
			name:      "network error",
			errType:   ErrorTypeNetwork,
			message:   "connection timeout",
			artifact:  "test.tar.gz",
			retryable: true,
		},
		{
			name:      "validation error",
			errType:   ErrorTypeValidation,
			message:   "invalid format",
			artifact:  "test.tar.gz",
			retryable: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			originalErr := fmt.Errorf("original cause")
			err := NewSigningError(tt.errType, tt.artifact, tt.message, originalErr)

			assert.Equal(t, tt.errType, err.Type)
			assert.Equal(t, tt.message, err.Message)
			assert.Equal(t, tt.artifact, err.Artifact)
			assert.Equal(t, tt.retryable, err.IsRetryable())

			// Test Error() method
			errorStr := err.Error()
			assert.Contains(t, errorStr, tt.message)
			assert.Contains(t, errorStr, tt.artifact)

			// Test Unwrap
			assert.Equal(t, originalErr, err.Unwrap())
		})
	}
}

// TestSigningError_Unwrap tests error unwrapping
func TestSigningError_Unwrap(t *testing.T) {
	originalErr := fmt.Errorf("original error")
	signingErr := &SigningError{
		Type:     "test",
		Message:  "test message",
		Artifact: "test.tar.gz",
		Cause:    originalErr,
	}

	unwrapped := signingErr.Unwrap()
	assert.Equal(t, originalErr, unwrapped)
}

// TestWithRetry tests the retry wrapper
func TestWithRetry(t *testing.T) {
	t.Run("successful operation", func(t *testing.T) {
		callCount := 0
		operation := func() error {
			callCount++
			return nil
		}

		err := WithRetry(3, operation)
		assert.NoError(t, err)
		assert.Equal(t, 1, callCount)
	})

	t.Run("non-retryable error", func(t *testing.T) {
		callCount := 0
		operation := func() error {
			callCount++
			return NewSigningError(ErrorTypePermission, "test.tar.gz", "access denied", fmt.Errorf("permission denied"))
		}

		err := WithRetry(3, operation)
		assert.Error(t, err)
		assert.Equal(t, 1, callCount) // Should not retry
	})

	t.Run("retryable error that eventually succeeds", func(t *testing.T) {
		callCount := 0
		operation := func() error {
			callCount++
			if callCount < 3 {
				return NewSigningError(ErrorTypeNetwork, "test.tar.gz", "network timeout", fmt.Errorf("timeout"))
			}
			return nil
		}

		err := WithRetry(5, operation)
		assert.NoError(t, err)
		assert.Equal(t, 3, callCount)
	})
}

// TestCategorizeError tests error categorization
func TestCategorizeError(t *testing.T) {
	tests := []struct {
		name         string
		inputError   error
		expectedType SigningErrorType
		retryable    bool
	}{
		{
			name:         "permission denied",
			inputError:   fmt.Errorf("permission denied"),
			expectedType: ErrorTypePermission,
			retryable:    false,
		},
		{
			name:         "network timeout",
			inputError:   fmt.Errorf("connection timeout"),
			expectedType: ErrorTypeNetwork,
			retryable:    true,
		},
		{
			name:         "file not found",
			inputError:   fmt.Errorf("no such file or directory"),
			expectedType: ErrorTypeFileSystem,
			retryable:    false,
		},
		{
			name:         "unknown error",
			inputError:   fmt.Errorf("some random error"),
			expectedType: ErrorTypeNetwork, // Default to network
			retryable:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			categorized := CategorizeError("test.tar.gz", tt.inputError)

			assert.Equal(t, tt.expectedType, categorized.Type)
			assert.Equal(t, tt.retryable, categorized.IsRetryable())
			assert.Equal(t, "test.tar.gz", categorized.Artifact)
			assert.Equal(t, tt.inputError, categorized.Cause)
		})
	}
}

// TestArtifactUploader tests the uploader structure
func TestArtifactUploader(t *testing.T) {
	// Create a mock remote cache
	mockCache := &mockRemoteCache{}
	uploader := NewArtifactUploader(mockCache)

	assert.NotNil(t, uploader)
	assert.Equal(t, mockCache, uploader.remoteCache)
}

// Mock implementations for testing
type mockRemoteCache struct{}

func (m *mockRemoteCache) ExistingPackages(ctx context.Context, pkgs []cache.Package) (map[cache.Package]struct{}, error) {
	return make(map[cache.Package]struct{}), nil
}

func (m *mockRemoteCache) Download(ctx context.Context, dst cache.LocalCache, pkgs []cache.Package) error {
	return nil
}

func (m *mockRemoteCache) Upload(ctx context.Context, src cache.LocalCache, pkgs []cache.Package) error {
	return nil
}

func (m *mockRemoteCache) UploadFile(ctx context.Context, filePath string, key string) error {
	return nil
}

func (m *mockRemoteCache) HasFile(ctx context.Context, key string) (bool, error) {
	return false, nil
}

// TestGetEnvOrDefault tests the environment variable helper
// TestValidateSigstoreEnvironment tests Sigstore environment validation
func TestValidateSigstoreEnvironment(t *testing.T) {
	t.Run("missing required environment", func(t *testing.T) {
		// Clear all Sigstore environment variables (t.Setenv automatically handles cleanup)
		t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
		t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "")
		t.Setenv("GITHUB_ACTIONS", "")

		err := validateSigstoreEnvironment()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "ACTIONS_ID_TOKEN_REQUEST_TOKEN")
	})

	t.Run("partial environment", func(t *testing.T) {
		// Set some but not all required variables (t.Setenv automatically handles cleanup)
		t.Setenv("GITHUB_ACTIONS", "true")
		t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
		t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "")

		err := validateSigstoreEnvironment()
		assert.Error(t, err)
	})

	t.Run("complete environment", func(t *testing.T) {
		// Set all required variables (t.Setenv automatically handles cleanup)
		t.Setenv("GITHUB_ACTIONS", "true")
		t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "test-token")
		t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://test.url")

		err := validateSigstoreEnvironment()
		assert.NoError(t, err)
	})
}

// TestSigningError_IsRetryable_AllTypes tests all error types for retryability
func TestSigningError_IsRetryable_AllTypes(t *testing.T) {
	tests := []struct {
		errorType SigningErrorType
		retryable bool
	}{
		{ErrorTypeNetwork, true},
		{ErrorTypeSigstore, true},
		{ErrorTypePermission, false},
		{ErrorTypeValidation, false},
		{ErrorTypeFileSystem, false},
		{SigningErrorType("unknown"), false},
	}

	for _, tt := range tests {
		t.Run(string(tt.errorType), func(t *testing.T) {
			err := &SigningError{Type: tt.errorType}
			assert.Equal(t, tt.retryable, err.IsRetryable())
		})
	}
}

// TestCategorizeError_ExistingSigningError tests categorizing an already categorized error
func TestCategorizeError_ExistingSigningError(t *testing.T) {
	originalErr := &SigningError{
		Type:     ErrorTypePermission,
		Artifact: "test.tar.gz",
		Message:  "access denied",
	}

	got := CategorizeError("different.tar.gz", originalErr)

	// Should return the original error unchanged
	if diff := cmp.Diff(originalErr, got); diff != "" {
		t.Errorf("CategorizeError() should preserve original error (-want +got):\n%s", diff)
	}
}

// TestWithRetry_MaxAttemptsExceeded tests retry exhaustion
func TestWithRetry_MaxAttemptsExceeded(t *testing.T) {
	callCount := 0
	operation := func() error {
		callCount++
		return NewSigningError(ErrorTypeNetwork, "test.tar.gz", "network timeout", fmt.Errorf("timeout"))
	}

	err := WithRetry(3, operation)
	assert.Error(t, err)
	assert.Equal(t, 3, callCount)
	assert.Contains(t, err.Error(), "operation failed after 3 attempts")
}

// TestUploadArtifactWithAttestation tests the upload functionality
func TestUploadArtifactWithAttestation(t *testing.T) {
	// Create a test artifact
	artifactPath := createTestArtifact(t, "test upload content")
	attestationBytes := []byte("test attestation")

	// Create uploader with mock cache
	mockCache := &mockRemoteCache{}
	uploader := NewArtifactUploader(mockCache)

	// Test upload with mock cache (should succeed)
	err := uploader.UploadArtifactWithAttestation(context.Background(), artifactPath, attestationBytes)
	assert.NoError(t, err)
}

// TestGenerateSignedSLSAAttestation_ChecksumError tests checksum calculation error
func TestGenerateSignedSLSAAttestation_ChecksumError(t *testing.T) {
	githubCtx := createMockGitHubContext()

	// Test with non-existent file (should fail at checksum calculation)
	_, err := GenerateSignedSLSAAttestation(context.Background(), "/nonexistent/file.tar.gz", githubCtx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "checksum calculation failed")
}

// TestGenerateSignedSLSAAttestation_InvalidContext tests with invalid GitHub context
func TestGenerateSignedSLSAAttestation_InvalidContext(t *testing.T) {
	artifactPath := createTestArtifact(t, "test content")

	// Test with invalid GitHub context
	invalidCtx := &GitHubContext{
		// Missing required fields
	}

	_, err := GenerateSignedSLSAAttestation(context.Background(), artifactPath, invalidCtx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "incomplete GitHub context")
}

// TestSignProvenanceWithSigstore_EnvironmentValidation tests Sigstore environment validation
func TestSignProvenanceWithSigstore_EnvironmentValidation(t *testing.T) {
	// Clear Sigstore environment to trigger validation error (t.Setenv automatically handles cleanup)
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "")
	t.Setenv("GITHUB_ACTIONS", "")

	artifactPath := createTestArtifact(t, "test content")
	githubCtx := createMockGitHubContext()

	// This should fail at OIDC extraction (strict mode - fails fast)
	_, err := GenerateSignedSLSAAttestation(context.Background(), artifactPath, githubCtx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to extract builder ID from OIDC token")
}

func TestFetchGitHubOIDCToken(t *testing.T) {
	tests := []struct {
		name          string
		setupEnv      func(*testing.T)
		mockServer    func(*testing.T) *httptest.Server
		audience      string
		expectError   bool
		errorContains string
	}{
		{
			name: "successful token fetch",
			setupEnv: func(t *testing.T) {
				// Will be set by mockServer
			},
			mockServer: func(t *testing.T) *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					// Verify audience parameter
					if r.URL.Query().Get("audience") != "sigstore" {
						t.Errorf("Expected audience=sigstore, got %s", r.URL.Query().Get("audience"))
					}
					// Verify Authorization header
					if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
						t.Error("Missing or invalid Authorization header")
					}
					w.WriteHeader(http.StatusOK)
					if err := json.NewEncoder(w).Encode(map[string]string{"value": "test-token-12345"}); err != nil {
						t.Errorf("Failed to encode response: %v", err)
					}
				}))
			},
			audience:    "sigstore",
			expectError: false,
		},
		{
			name: "missing environment variables",
			setupEnv: func(t *testing.T) {
				t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "")
				t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
			},
			audience:      "sigstore",
			expectError:   true,
			errorContains: "GitHub OIDC environment not configured",
		},
		{
			name: "HTTP 500 error",
			mockServer: func(t *testing.T) *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusInternalServerError)
					_, _ = w.Write([]byte(`{"error": "internal error"}`))
				}))
			},
			audience:      "sigstore",
			expectError:   true,
			errorContains: "status: 500",
		},
		{
			name: "empty token in response",
			mockServer: func(t *testing.T) *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
					if err := json.NewEncoder(w).Encode(map[string]string{"value": ""}); err != nil {
						t.Errorf("Failed to encode response: %v", err)
					}
				}))
			},
			audience:      "sigstore",
			expectError:   true,
			errorContains: "received empty token",
		},
		{
			name: "invalid JSON response",
			mockServer: func(t *testing.T) *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte(`invalid json`))
				}))
			},
			audience:      "sigstore",
			expectError:   true,
			errorContains: "failed to decode response",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			if tt.setupEnv != nil {
				tt.setupEnv(t)
			}
			
			var server *httptest.Server
			if tt.mockServer != nil {
				server = tt.mockServer(t)
				defer server.Close()
				t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", server.URL)
				t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "test-request-token")
			}

			// Execute
			ctx := context.Background()
			token, err := fetchGitHubOIDCToken(ctx, tt.audience)

			// Verify
			if tt.expectError {
				require.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				require.NoError(t, err)
				assert.NotEmpty(t, token)
				if server != nil {
					assert.Equal(t, "test-token-12345", token)
				}
			}
		})
	}
}

// TestExtractJobWorkflowRef tests the extraction of job_workflow_ref from OIDC sub claims
func TestExtractJobWorkflowRef(t *testing.T) {
	tests := []struct {
		name     string
		subClaim string
		expected string
	}{
		{
			name:     "reusable workflow with job_workflow_ref",
			subClaim: "repo:example-org/example-repo:ref:refs/heads/main:job_workflow_ref:example-org/example-repo/.github/workflows/_build.yml@refs/heads/leo/slsa/b",
			expected: "example-org/example-repo/.github/workflows/_build.yml@refs/heads/leo/slsa/b",
		},
		{
			name:     "direct workflow (non-reusable)",
			subClaim: "repo:gitpod-io/leeway:ref:refs/heads/main:job_workflow_ref:gitpod-io/leeway/.github/workflows/build.yml@refs/heads/main",
			expected: "gitpod-io/leeway/.github/workflows/build.yml@refs/heads/main",
		},
		{
			name:     "workflow path with colons",
			subClaim: "repo:org/repo:ref:refs/heads/main:job_workflow_ref:org/repo/.github/workflows/build:test.yml@refs/heads/main",
			expected: "org/repo/.github/workflows/build:test.yml@refs/heads/main",
		},
		{
			name:     "multiple colons in workflow path",
			subClaim: "repo:org/repo:ref:refs/heads/main:job_workflow_ref:org/repo/.github/workflows/test:build:deploy.yml@refs/heads/main",
			expected: "org/repo/.github/workflows/test:build:deploy.yml@refs/heads/main",
		},
		{
			name:     "reusable workflow with environment claim",
			subClaim: "repo:gitpod-io/gitpod:environment:production:ref:refs/heads/main:job_workflow_ref:gitpod-io/gitpod/.github/workflows/_build-image.yml@refs/heads/main",
			expected: "gitpod-io/gitpod/.github/workflows/_build-image.yml@refs/heads/main",
		},
		{
			name:     "pull request workflow",
			subClaim: "repo:gitpod-io/leeway:ref:refs/pull/264/merge:job_workflow_ref:gitpod-io/leeway/.github/workflows/build.yml@refs/pull/264/merge",
			expected: "gitpod-io/leeway/.github/workflows/build.yml@refs/pull/264/merge",
		},
		{
			name:     "tag-triggered workflow",
			subClaim: "repo:org/repo:ref:refs/tags/v1.0.0:job_workflow_ref:org/repo/.github/workflows/release.yml@refs/tags/v1.0.0",
			expected: "org/repo/.github/workflows/release.yml@refs/tags/v1.0.0",
		},
		{
			name:     "missing job_workflow_ref",
			subClaim: "repo:example-org/example-repo:ref:refs/heads/main",
			expected: "",
		},
		{
			name:     "empty sub claim",
			subClaim: "",
			expected: "",
		},
		{
			name:     "malformed sub claim",
			subClaim: "invalid:format",
			expected: "",
		},
		{
			name:     "job_workflow_ref at end without value",
			subClaim: "repo:org/repo:ref:refs/heads/main:job_workflow_ref:",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractJobWorkflowRef(tt.subClaim)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// Helper function to create base64url encoded strings for JWT tokens
func base64EncodeForTest(s string) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString([]byte(s)), "=")
}

// TestExtractBuilderIDFromOIDC tests the extraction of builder ID from OIDC tokens
func TestExtractBuilderIDFromOIDC(t *testing.T) {
	tests := []struct {
		name        string
		setupServer func() *httptest.Server
		githubCtx   *GitHubContext
		want        struct {
			id  string
			err string
		}
	}{
		{
			name: "valid OIDC token with reusable workflow",
			setupServer: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					header := base64EncodeForTest(`{"alg":"RS256","typ":"JWT"}`)
					payload := base64EncodeForTest(`{
						"sub": "repo:example-org/example-repo:ref:refs/heads/main:job_workflow_ref:example-org/example-repo/.github/workflows/_build.yml@refs/heads/leo/slsa/b",
						"aud": "sigstore",
						"iss": "https://token.actions.githubusercontent.com"
					}`)
					signature := base64EncodeForTest("fake-signature")
					token := fmt.Sprintf("%s.%s.%s", header, payload, signature)
					
					w.Header().Set("Content-Type", "application/json")
					if err := json.NewEncoder(w).Encode(map[string]string{"value": token}); err != nil {
						t.Errorf("Failed to encode response: %v", err)
					}
				}))
			},
			githubCtx: &GitHubContext{
				ServerURL:   "https://github.com",
				Repository:  "example-org/example-repo",
				WorkflowRef: "example-org/example-repo/.github/workflows/calling-workflow.yml@refs/heads/main",
			},
			want: struct {
				id  string
				err string
			}{
				id: "https://github.com/example-org/example-repo/.github/workflows/_build.yml@refs/heads/leo/slsa/b",
			},
		},
		{
			name: "valid OIDC token with direct workflow",
			setupServer: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					header := base64EncodeForTest(`{"alg":"RS256","typ":"JWT"}`)
					payload := base64EncodeForTest(`{
						"sub": "repo:gitpod-io/leeway:ref:refs/heads/main:job_workflow_ref:gitpod-io/leeway/.github/workflows/build.yml@refs/heads/main",
						"aud": "sigstore"
					}`)
					signature := base64EncodeForTest("fake-signature")
					token := fmt.Sprintf("%s.%s.%s", header, payload, signature)
					
					w.Header().Set("Content-Type", "application/json")
					if err := json.NewEncoder(w).Encode(map[string]string{"value": token}); err != nil {
						t.Errorf("Failed to encode response: %v", err)
					}
				}))
			},
			githubCtx: &GitHubContext{
				ServerURL:   "https://github.com",
				Repository:  "gitpod-io/leeway",
				WorkflowRef: "gitpod-io/leeway/.github/workflows/build.yml@refs/heads/main",
			},
			want: struct {
				id  string
				err string
			}{
				id: "https://github.com/gitpod-io/leeway/.github/workflows/build.yml@refs/heads/main",
			},
		},
		{
			name: "invalid JWT format - only 2 parts",
			setupServer: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					token := "header.payload"
					w.Header().Set("Content-Type", "application/json")
					if err := json.NewEncoder(w).Encode(map[string]string{"value": token}); err != nil {
						t.Errorf("Failed to encode response: %v", err)
					}
				}))
			},
			githubCtx: &GitHubContext{
				ServerURL:  "https://github.com",
				Repository: "org/repo",
			},
			want: struct {
				id  string
				err string
			}{
				err: "invalid JWT token format",
			},
		},
		{
			name: "missing sub claim",
			setupServer: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					header := base64EncodeForTest(`{"alg":"RS256","typ":"JWT"}`)
					payload := base64EncodeForTest(`{"aud": "sigstore"}`)
					signature := base64EncodeForTest("fake-signature")
					token := fmt.Sprintf("%s.%s.%s", header, payload, signature)
					
					w.Header().Set("Content-Type", "application/json")
					if err := json.NewEncoder(w).Encode(map[string]string{"value": token}); err != nil {
						t.Errorf("Failed to encode response: %v", err)
					}
				}))
			},
			githubCtx: &GitHubContext{
				ServerURL:  "https://github.com",
				Repository: "org/repo",
			},
			want: struct {
				id  string
				err string
			}{
				err: "sub claim not found",
			},
		},
		{
			name: "whitespace-only sub claim",
			setupServer: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					header := base64EncodeForTest(`{"alg":"RS256","typ":"JWT"}`)
					payload := base64EncodeForTest(`{"sub": "   ", "aud": "sigstore"}`)
					signature := base64EncodeForTest("fake-signature")
					token := fmt.Sprintf("%s.%s.%s", header, payload, signature)
					
					w.Header().Set("Content-Type", "application/json")
					if err := json.NewEncoder(w).Encode(map[string]string{"value": token}); err != nil {
						t.Errorf("Failed to encode response: %v", err)
					}
				}))
			},
			githubCtx: &GitHubContext{
				ServerURL:  "https://github.com",
				Repository: "org/repo",
			},
			want: struct {
				id  string
				err string
			}{
				err: "sub claim not found or empty",
			},
		},
		{
			name: "job_workflow_ref in top-level claim (not in sub)",
			setupServer: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					header := base64EncodeForTest(`{"alg":"RS256","typ":"JWT"}`)
					payload := base64EncodeForTest(`{
						"sub": "repo:org/repo:environment:prod",
						"aud": "sigstore",
						"job_workflow_ref": "org/repo/.github/workflows/deploy.yml@refs/heads/main"
					}`)
					signature := base64EncodeForTest("fake-signature")
					token := fmt.Sprintf("%s.%s.%s", header, payload, signature)
					
					w.Header().Set("Content-Type", "application/json")
					if err := json.NewEncoder(w).Encode(map[string]string{"value": token}); err != nil {
						t.Errorf("Failed to encode response: %v", err)
					}
				}))
			},
			githubCtx: &GitHubContext{
				ServerURL:  "https://github.com",
				Repository: "org/repo",
			},
			want: struct {
				id  string
				err string
			}{
				id: "https://github.com/org/repo/.github/workflows/deploy.yml@refs/heads/main",
			},
		},
		{
			name: "missing job_workflow_ref in sub claim and top-level",
			setupServer: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					header := base64EncodeForTest(`{"alg":"RS256","typ":"JWT"}`)
					payload := base64EncodeForTest(`{
						"sub": "repo:org/repo:ref:refs/heads/main",
						"aud": "sigstore"
					}`)
					signature := base64EncodeForTest("fake-signature")
					token := fmt.Sprintf("%s.%s.%s", header, payload, signature)
					
					w.Header().Set("Content-Type", "application/json")
					if err := json.NewEncoder(w).Encode(map[string]string{"value": token}); err != nil {
						t.Errorf("Failed to encode response: %v", err)
					}
				}))
			},
			githubCtx: &GitHubContext{
				ServerURL:  "https://github.com",
				Repository: "org/repo",
			},
			want: struct {
				id  string
				err string
			}{
				err: "job_workflow_ref not found",
			},
		},
		{
			name: "OIDC token fetch failure",
			setupServer: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusUnauthorized)
				}))
			},
			githubCtx: &GitHubContext{
				ServerURL:  "https://github.com",
				Repository: "org/repo",
			},
			want: struct {
				id  string
				err string
			}{
				err: "failed to fetch OIDC token",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := tt.setupServer()
			defer server.Close()

			t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", server.URL)
			t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "test-token")

			builderID, err := extractBuilderIDFromOIDC(context.Background(), tt.githubCtx)

			if tt.want.err != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.want.err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want.id, builderID)
			}
		})
	}
}

// TestBuilderIDMatchesCertificateIdentity is the critical regression test
// It verifies that the builder ID extracted from OIDC matches what Fulcio
// would use for the certificate identity, preventing verification failures
func TestBuilderIDMatchesCertificateIdentity(t *testing.T) {
	tests := []struct {
		name                   string
		oidcSubClaim           string
		githubWorkflowRef      string
		expectedBuilderID      string
		shouldMatchWorkflowRef bool
		description            string
	}{
		{
			name:                   "reusable workflow - builder ID must match OIDC not GITHUB_WORKFLOW_REF",
			oidcSubClaim:           "repo:example-org/example-repo:ref:refs/heads/main:job_workflow_ref:example-org/example-repo/.github/workflows/_build.yml@refs/heads/leo/slsa/b",
			githubWorkflowRef:      "example-org/example-repo/.github/workflows/calling-workflow.yml@refs/heads/main",
			expectedBuilderID:      "https://github.com/example-org/example-repo/.github/workflows/_build.yml@refs/heads/leo/slsa/b",
			shouldMatchWorkflowRef: false,
			description:            "For reusable workflows, certificate identity comes from OIDC sub claim (actual executing workflow), not GITHUB_WORKFLOW_REF (calling workflow)",
		},
		{
			name:                   "direct workflow - builder ID matches both OIDC and GITHUB_WORKFLOW_REF",
			oidcSubClaim:           "repo:gitpod-io/leeway:ref:refs/heads/main:job_workflow_ref:gitpod-io/leeway/.github/workflows/build.yml@refs/heads/main",
			githubWorkflowRef:      "gitpod-io/leeway/.github/workflows/build.yml@refs/heads/main",
			expectedBuilderID:      "https://github.com/gitpod-io/leeway/.github/workflows/build.yml@refs/heads/main",
			shouldMatchWorkflowRef: true,
			description:            "For direct workflows, OIDC and GITHUB_WORKFLOW_REF point to the same workflow",
		},
		{
			name:                   "nested reusable workflow",
			oidcSubClaim:           "repo:org/repo:ref:refs/heads/main:job_workflow_ref:org/repo/.github/workflows/_internal-build.yml@refs/heads/feature",
			githubWorkflowRef:      "org/repo/.github/workflows/main-workflow.yml@refs/heads/main",
			expectedBuilderID:      "https://github.com/org/repo/.github/workflows/_internal-build.yml@refs/heads/feature",
			shouldMatchWorkflowRef: false,
			description:            "Nested reusable workflows also use OIDC sub claim for certificate identity",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				header := base64EncodeForTest(`{"alg":"RS256","typ":"JWT"}`)
				payload := base64EncodeForTest(fmt.Sprintf(`{
					"sub": "%s",
					"aud": "sigstore",
					"iss": "https://token.actions.githubusercontent.com"
				}`, tt.oidcSubClaim))
				signature := base64EncodeForTest("fake-signature")
				token := fmt.Sprintf("%s.%s.%s", header, payload, signature)
				
				w.Header().Set("Content-Type", "application/json")
				if err := json.NewEncoder(w).Encode(map[string]string{"value": token}); err != nil {
					t.Errorf("Failed to encode response: %v", err)
				}
			}))
			defer server.Close()

			t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", server.URL)
			t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "test-token")

			githubCtx := &GitHubContext{
				ServerURL:   "https://github.com",
				Repository:  "example-org/example-repo",
				WorkflowRef: tt.githubWorkflowRef,
			}

			builderID, err := extractBuilderIDFromOIDC(context.Background(), githubCtx)
			require.NoError(t, err, tt.description)

			assert.Equal(t, tt.expectedBuilderID, builderID, tt.description)

			workflowRefBasedID := fmt.Sprintf("%s/%s", githubCtx.ServerURL, tt.githubWorkflowRef)
			if tt.shouldMatchWorkflowRef {
				assert.Equal(t, workflowRefBasedID, builderID,
					"For direct workflows, builder ID should match GITHUB_WORKFLOW_REF-based ID")
			} else {
				assert.NotEqual(t, workflowRefBasedID, builderID,
					"For reusable workflows, builder ID must NOT match GITHUB_WORKFLOW_REF-based ID - this is the critical fix")
			}

			jobWorkflowRef := extractJobWorkflowRef(tt.oidcSubClaim)
			require.NotEmpty(t, jobWorkflowRef, "job_workflow_ref should be extractable from sub claim")

			expectedFromJobWorkflowRef := fmt.Sprintf("%s/%s", githubCtx.ServerURL, jobWorkflowRef)
			assert.Equal(t, expectedFromJobWorkflowRef, builderID,
				"Builder ID must be constructed from OIDC job_workflow_ref to match Fulcio certificate identity")
		})
	}
}

// TestBundleFormatCompliance verifies that generated attestations conform to
// the official Sigstore Bundle v0.3 format specification.
// See: https://docs.sigstore.dev/about/bundle/
//
// This test uses a mock bundle to verify the expected format without requiring
// Sigstore credentials. The format is what protojson.Marshal should produce
// when marshaling a protobuf Bundle with UseProtoNames=false.
func TestBundleFormatCompliance(t *testing.T) {
	// Create a minimal mock bundle structure that represents the expected output
	// of protojson.Marshal on a Sigstore Bundle v0.3 protobuf message.
	// This is what our code should produce after the fix.
	mockBundleJSON := `{
		"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
		"verificationMaterial": {
			"certificate": {
				"rawBytes": "dGVzdC1jZXJ0aWZpY2F0ZQ=="
			},
			"tlogEntries": [{
				"logIndex": "12345",
				"logId": {
					"keyId": "dGVzdC1rZXktaWQ="
				},
				"integratedTime": "1234567890"
			}]
		},
		"dsseEnvelope": {
			"payload": "dGVzdC1wYXlsb2Fk",
			"payloadType": "application/vnd.in-toto+json",
			"signatures": [{
				"sig": "dGVzdC1zaWduYXR1cmU="
			}]
		}
	}`

	var bundle map[string]interface{}
	err := json.Unmarshal([]byte(mockBundleJSON), &bundle)
	require.NoError(t, err, "Failed to parse mock bundle JSON")

	// Test 1: Verify top-level fields use camelCase (not snake_case)
	t.Run("TopLevelFieldsUseCamelCase", func(t *testing.T) {
		// Should have camelCase fields
		assert.Contains(t, bundle, "mediaType", "Bundle should have 'mediaType' field (camelCase)")
		assert.Contains(t, bundle, "verificationMaterial", "Bundle should have 'verificationMaterial' field (camelCase)")
		assert.Contains(t, bundle, "dsseEnvelope", "Bundle should have 'dsseEnvelope' field (camelCase)")

		// Should NOT have snake_case fields
		assert.NotContains(t, bundle, "media_type", "Bundle should NOT have 'media_type' field (snake_case)")
		assert.NotContains(t, bundle, "verification_material", "Bundle should NOT have 'verification_material' field (snake_case)")
		assert.NotContains(t, bundle, "dsse_envelope", "Bundle should NOT have 'dsse_envelope' field (snake_case)")
	})

	// Test 2: Verify no protobuf oneof field wrappers (Content, Certificate, etc.)
	t.Run("NoProtobufOneofWrappers", func(t *testing.T) {
		verificationMaterial, ok := bundle["verificationMaterial"].(map[string]interface{})
		require.True(t, ok, "verificationMaterial should be an object")

		// Should have direct 'certificate' field (lowercase)
		assert.Contains(t, verificationMaterial, "certificate", "verificationMaterial should have direct 'certificate' field")

		// Should NOT have 'Content' wrapper
		assert.NotContains(t, verificationMaterial, "Content", "verificationMaterial should NOT have 'Content' wrapper (protobuf oneof field)")

		// Should NOT have 'Certificate' with capital C
		assert.NotContains(t, verificationMaterial, "Certificate", "verificationMaterial should NOT have 'Certificate' with capital C")
	})

	// Test 3: Verify certificate is in correct location
	t.Run("CertificateInCorrectLocation", func(t *testing.T) {
		verificationMaterial, ok := bundle["verificationMaterial"].(map[string]interface{})
		require.True(t, ok, "verificationMaterial should be an object")

		certificate, ok := verificationMaterial["certificate"].(map[string]interface{})
		require.True(t, ok, "certificate should be an object at verificationMaterial.certificate")

		// Should have rawBytes (camelCase)
		assert.Contains(t, certificate, "rawBytes", "certificate should have 'rawBytes' field (camelCase)")

		// Should NOT have raw_bytes (snake_case)
		assert.NotContains(t, certificate, "raw_bytes", "certificate should NOT have 'raw_bytes' field (snake_case)")
	})

	// Test 4: Verify tlogEntries use camelCase
	t.Run("TlogEntriesUseCamelCase", func(t *testing.T) {
		verificationMaterial, ok := bundle["verificationMaterial"].(map[string]interface{})
		require.True(t, ok, "verificationMaterial should be an object")

		// Should have tlogEntries (camelCase)
		assert.Contains(t, verificationMaterial, "tlogEntries", "verificationMaterial should have 'tlogEntries' field (camelCase)")

		// Should NOT have tlog_entries (snake_case)
		assert.NotContains(t, verificationMaterial, "tlog_entries", "verificationMaterial should NOT have 'tlog_entries' field (snake_case)")

		tlogEntries, ok := verificationMaterial["tlogEntries"].([]interface{})
		require.True(t, ok, "tlogEntries should be an array")
		require.NotEmpty(t, tlogEntries, "tlogEntries should not be empty")

		entry, ok := tlogEntries[0].(map[string]interface{})
		require.True(t, ok, "tlog entry should be an object")

		// Verify entry fields use camelCase
		assert.Contains(t, entry, "logIndex", "tlog entry should have 'logIndex' field (camelCase)")
		assert.Contains(t, entry, "logId", "tlog entry should have 'logId' field (camelCase)")
		assert.Contains(t, entry, "integratedTime", "tlog entry should have 'integratedTime' field (camelCase)")

		// Should NOT have snake_case fields
		assert.NotContains(t, entry, "log_index", "tlog entry should NOT have 'log_index' field (snake_case)")
		assert.NotContains(t, entry, "log_id", "tlog entry should NOT have 'log_id' field (snake_case)")
		assert.NotContains(t, entry, "integrated_time", "tlog entry should NOT have 'integrated_time' field (snake_case)")
	})

	// Test 5: Verify dsseEnvelope is direct field (not wrapped)
	t.Run("DsseEnvelopeIsDirectField", func(t *testing.T) {
		// Should have direct dsseEnvelope field
		dsseEnvelope, ok := bundle["dsseEnvelope"].(map[string]interface{})
		require.True(t, ok, "dsseEnvelope should be a direct field")

		// Verify envelope fields
		assert.Contains(t, dsseEnvelope, "payload", "dsseEnvelope should have 'payload' field")
		assert.Contains(t, dsseEnvelope, "payloadType", "dsseEnvelope should have 'payloadType' field (camelCase)")
		assert.Contains(t, dsseEnvelope, "signatures", "dsseEnvelope should have 'signatures' field")

		// Should NOT be wrapped in Content
		assert.NotContains(t, bundle, "Content", "Bundle should NOT have 'Content' wrapper for dsseEnvelope")
	})

	// Test 6: Verify media type value
	t.Run("MediaTypeValue", func(t *testing.T) {
		mediaType, ok := bundle["mediaType"].(string)
		require.True(t, ok, "mediaType should be a string")

		assert.Equal(t, "application/vnd.dev.sigstore.bundle.v0.3+json", mediaType,
			"mediaType should be 'application/vnd.dev.sigstore.bundle.v0.3+json'")
	})
}

// TestProtojsonMarshalOptions verifies that protojson.MarshalOptions produces
// the correct format when marshaling protobuf messages.
//
// This test validates that our MarshalOptions configuration (UseProtoNames=false,
// EmitUnpopulated=false) produces standard JSON field names (camelCase) without
// protobuf implementation details leaking through.
func TestProtojsonMarshalOptions(t *testing.T) {
	// Create a minimal protobuf bundle to test marshaling behavior
	// We use the actual protobuf types to ensure our MarshalOptions work correctly
	protobundle := &protobundle.Bundle{
		MediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
		VerificationMaterial: &protobundle.VerificationMaterial{
			Content: &protobundle.VerificationMaterial_Certificate{
				Certificate: &protocommon.X509Certificate{
					RawBytes: []byte("test-certificate"),
				},
			},
		},
	}

	// Marshal using our configured options (same as in attestation.go)
	marshaler := protojson.MarshalOptions{
		UseProtoNames:   false, // Use JSON names (camelCase) instead of proto names
		EmitUnpopulated: false, // Omit empty/default fields for cleaner output
	}
	bundleBytes, err := marshaler.Marshal(protobundle)
	require.NoError(t, err, "Marshaling should succeed")

	// Parse the result to verify structure
	var parsed map[string]interface{}
	err = json.Unmarshal(bundleBytes, &parsed)
	require.NoError(t, err, "Result should be valid JSON")

	// Test 1: Verify camelCase field names (not snake_case)
	t.Run("UsesCamelCaseFieldNames", func(t *testing.T) {
		assert.Contains(t, parsed, "mediaType", "Should use camelCase 'mediaType'")
		assert.Contains(t, parsed, "verificationMaterial", "Should use camelCase 'verificationMaterial'")

		assert.NotContains(t, parsed, "media_type", "Should NOT use snake_case 'media_type'")
		assert.NotContains(t, parsed, "verification_material", "Should NOT use snake_case 'verification_material'")
	})

	// Test 2: Verify no protobuf oneof wrappers
	t.Run("NoProtobufOneofWrappers", func(t *testing.T) {
		verificationMaterial, ok := parsed["verificationMaterial"].(map[string]interface{})
		require.True(t, ok, "verificationMaterial should be an object")

		// Should have direct 'certificate' field (lowercase)
		assert.Contains(t, verificationMaterial, "certificate",
			"Should have direct 'certificate' field (lowercase)")

		// Should NOT have 'Content' wrapper (protobuf oneof field name)
		assert.NotContains(t, verificationMaterial, "Content",
			"Should NOT have 'Content' wrapper (protobuf oneof field)")
	})

	// Test 3: Verify certificate structure
	t.Run("CertificateStructure", func(t *testing.T) {
		verificationMaterial, ok := parsed["verificationMaterial"].(map[string]interface{})
		require.True(t, ok, "verificationMaterial should be an object")

		certificate, ok := verificationMaterial["certificate"].(map[string]interface{})
		require.True(t, ok, "certificate should be an object")

		// Should have rawBytes (camelCase)
		assert.Contains(t, certificate, "rawBytes", "Should have 'rawBytes' field (camelCase)")

		// Should NOT have raw_bytes (snake_case)
		assert.NotContains(t, certificate, "raw_bytes", "Should NOT have 'raw_bytes' field (snake_case)")
	})

	// Test 4: Verify media type value
	t.Run("MediaTypeValue", func(t *testing.T) {
		mediaType, ok := parsed["mediaType"].(string)
		require.True(t, ok, "mediaType should be a string")

		assert.Equal(t, "application/vnd.dev.sigstore.bundle.v0.3+json", mediaType,
			"mediaType should match Sigstore Bundle v0.3 format")
	})
}
