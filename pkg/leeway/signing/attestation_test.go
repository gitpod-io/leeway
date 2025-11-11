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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	// We expect it to fail due to missing Sigstore environment, but that's expected
	_, err := GenerateSignedSLSAAttestation(context.Background(), artifactPath, githubCtx)

	// We expect an error related to Sigstore/signing, not basic validation
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "sign", "Error should be related to signing process")
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
	// Save original environment
	originalEnv := map[string]string{
		"GITHUB_RUN_ID":       os.Getenv("GITHUB_RUN_ID"),
		"GITHUB_RUN_NUMBER":   os.Getenv("GITHUB_RUN_NUMBER"),
		"GITHUB_ACTOR":        os.Getenv("GITHUB_ACTOR"),
		"GITHUB_REPOSITORY":   os.Getenv("GITHUB_REPOSITORY"),
		"GITHUB_REF":          os.Getenv("GITHUB_REF"),
		"GITHUB_SHA":          os.Getenv("GITHUB_SHA"),
		"GITHUB_SERVER_URL":   os.Getenv("GITHUB_SERVER_URL"),
		"GITHUB_WORKFLOW_REF": os.Getenv("GITHUB_WORKFLOW_REF"),
	}

	// Clean up after test
	defer func() {
		for k, v := range originalEnv {
			if v == "" {
				_ = os.Unsetenv(k)
			} else {
				_ = os.Setenv(k, v)
			}
		}
	}()

	// Set test environment
	testEnv := map[string]string{
		"GITHUB_RUN_ID":       "test-run-id",
		"GITHUB_RUN_NUMBER":   "test-run-number",
		"GITHUB_ACTOR":        "test-actor",
		"GITHUB_REPOSITORY":   "test-repo",
		"GITHUB_REF":          "test-ref",
		"GITHUB_SHA":          "test-sha",
		"GITHUB_SERVER_URL":   "test-server",
		"GITHUB_WORKFLOW_REF": "test-workflow",
	}

	for k, v := range testEnv {
		_ = os.Setenv(k, v)
	}

	// Test GetGitHubContext
	ctx := GetGitHubContext()

	assert.Equal(t, testEnv["GITHUB_RUN_ID"], ctx.RunID)
	assert.Equal(t, testEnv["GITHUB_RUN_NUMBER"], ctx.RunNumber)
	assert.Equal(t, testEnv["GITHUB_ACTOR"], ctx.Actor)
	assert.Equal(t, testEnv["GITHUB_REPOSITORY"], ctx.Repository)
	assert.Equal(t, testEnv["GITHUB_REF"], ctx.Ref)
	assert.Equal(t, testEnv["GITHUB_SHA"], ctx.SHA)
	assert.Equal(t, testEnv["GITHUB_SERVER_URL"], ctx.ServerURL)
	assert.Equal(t, testEnv["GITHUB_WORKFLOW_REF"], ctx.WorkflowRef)
}

// TestGetGitHubContext_EmptyEnvironment tests with empty environment
func TestGetGitHubContext_EmptyEnvironment(t *testing.T) {
	// Save original environment
	originalEnv := map[string]string{
		"GITHUB_RUN_ID":       os.Getenv("GITHUB_RUN_ID"),
		"GITHUB_RUN_NUMBER":   os.Getenv("GITHUB_RUN_NUMBER"),
		"GITHUB_ACTOR":        os.Getenv("GITHUB_ACTOR"),
		"GITHUB_REPOSITORY":   os.Getenv("GITHUB_REPOSITORY"),
		"GITHUB_REF":          os.Getenv("GITHUB_REF"),
		"GITHUB_SHA":          os.Getenv("GITHUB_SHA"),
		"GITHUB_SERVER_URL":   os.Getenv("GITHUB_SERVER_URL"),
		"GITHUB_WORKFLOW_REF": os.Getenv("GITHUB_WORKFLOW_REF"),
	}

	// Clean up after test
	defer func() {
		for k, v := range originalEnv {
			if v == "" {
				_ = os.Unsetenv(k)
			} else {
				_ = os.Setenv(k, v)
			}
		}
	}()

	// Clear all GitHub environment variables
	githubVars := []string{
		"GITHUB_RUN_ID", "GITHUB_RUN_NUMBER", "GITHUB_ACTOR",
		"GITHUB_REPOSITORY", "GITHUB_REF", "GITHUB_SHA",
		"GITHUB_SERVER_URL", "GITHUB_WORKFLOW_REF",
	}

	for _, v := range githubVars {
		_ = os.Unsetenv(v)
	}

	// Test GetGitHubContext with empty environment
	ctx := GetGitHubContext()

	assert.Empty(t, ctx.RunID)
	assert.Empty(t, ctx.RunNumber)
	assert.Empty(t, ctx.Actor)
	assert.Empty(t, ctx.Repository)
	assert.Empty(t, ctx.Ref)
	assert.Empty(t, ctx.SHA)
	assert.Empty(t, ctx.ServerURL)
	assert.Empty(t, ctx.WorkflowRef)
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

// TestGetEnvOrDefault tests the environment variable helper
// TestValidateSigstoreEnvironment tests Sigstore environment validation
func TestValidateSigstoreEnvironment(t *testing.T) {
	// Save original environment
	originalEnv := map[string]string{
		"ACTIONS_ID_TOKEN_REQUEST_TOKEN": os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN"),
		"ACTIONS_ID_TOKEN_REQUEST_URL":   os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL"),
		"GITHUB_ACTIONS":                 os.Getenv("GITHUB_ACTIONS"),
	}

	// Clean up after test
	defer func() {
		for k, v := range originalEnv {
			if v == "" {
				_ = os.Unsetenv(k)
			} else {
				_ = os.Setenv(k, v)
			}
		}
	}()

	t.Run("missing required environment", func(t *testing.T) {
		// Clear all Sigstore environment variables
		_ = os.Unsetenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
		_ = os.Unsetenv("ACTIONS_ID_TOKEN_REQUEST_URL")
		_ = os.Unsetenv("GITHUB_ACTIONS")

		err := validateSigstoreEnvironment()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "ACTIONS_ID_TOKEN_REQUEST_TOKEN")
	})

	t.Run("partial environment", func(t *testing.T) {
		// Set some but not all required variables
		_ = os.Setenv("GITHUB_ACTIONS", "true")
		_ = os.Unsetenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
		_ = os.Unsetenv("ACTIONS_ID_TOKEN_REQUEST_URL")

		err := validateSigstoreEnvironment()
		assert.Error(t, err)
	})

	t.Run("complete environment", func(t *testing.T) {
		// Set all required variables
		_ = os.Setenv("GITHUB_ACTIONS", "true")
		_ = os.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "test-token")
		_ = os.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://test.url")

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

	result := CategorizeError("different.tar.gz", originalErr)

	// Should return the original error unchanged
	assert.Equal(t, originalErr, result)
	assert.Equal(t, ErrorTypePermission, result.Type)
	assert.Equal(t, "test.tar.gz", result.Artifact) // Original artifact preserved
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
	// Save original environment
	originalEnv := map[string]string{
		"ACTIONS_ID_TOKEN_REQUEST_TOKEN": os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN"),
		"ACTIONS_ID_TOKEN_REQUEST_URL":   os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL"),
		"GITHUB_ACTIONS":                 os.Getenv("GITHUB_ACTIONS"),
	}

	// Clean up after test
	defer func() {
		for k, v := range originalEnv {
			if v == "" {
				_ = os.Unsetenv(k)
			} else {
				_ = os.Setenv(k, v)
			}
		}
	}()

	// Clear Sigstore environment to trigger validation error
	_ = os.Unsetenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
	_ = os.Unsetenv("ACTIONS_ID_TOKEN_REQUEST_URL")
	_ = os.Unsetenv("GITHUB_ACTIONS")

	artifactPath := createTestArtifact(t, "test content")
	githubCtx := createMockGitHubContext()

	// This should fail at Sigstore environment validation
	_, err := GenerateSignedSLSAAttestation(context.Background(), artifactPath, githubCtx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to sign SLSA provenance")
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
		{
			name:     "multiple colons in workflow path",
			subClaim: "repo:org/repo:ref:refs/heads/main:job_workflow_ref:org/repo/.github/workflows/test:build:deploy.yml@refs/heads/main",
			expected: "org/repo/.github/workflows/test:build:deploy.yml@refs/heads/main",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractJobWorkflowRef(tt.subClaim)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestExtractJobWorkflowRef_RealWorldExamples tests with actual GitHub OIDC token formats
func TestExtractJobWorkflowRef_RealWorldExamples(t *testing.T) {
	tests := []struct {
		name        string
		subClaim    string
		expected    string
		description string
	}{
		{
			name:        "GitHub Actions reusable workflow",
			subClaim:    "repo:gitpod-io/gitpod:environment:production:ref:refs/heads/main:job_workflow_ref:gitpod-io/gitpod/.github/workflows/_build-image.yml@refs/heads/main",
			expected:    "gitpod-io/gitpod/.github/workflows/_build-image.yml@refs/heads/main",
			description: "Reusable workflow with environment claim",
		},
		{
			name:        "Pull request workflow",
			subClaim:    "repo:gitpod-io/leeway:ref:refs/pull/264/merge:job_workflow_ref:gitpod-io/leeway/.github/workflows/build.yml@refs/pull/264/merge",
			expected:    "gitpod-io/leeway/.github/workflows/build.yml@refs/pull/264/merge",
			description: "Pull request merge ref",
		},
		{
			name:        "Tag-triggered workflow",
			subClaim:    "repo:org/repo:ref:refs/tags/v1.0.0:job_workflow_ref:org/repo/.github/workflows/release.yml@refs/tags/v1.0.0",
			expected:    "org/repo/.github/workflows/release.yml@refs/tags/v1.0.0",
			description: "Tag reference",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractJobWorkflowRef(tt.subClaim)
			assert.Equal(t, tt.expected, result, tt.description)
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
		expectError bool
		expectedID  string
		errorMsg    string
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
					json.NewEncoder(w).Encode(map[string]string{"value": token})
				}))
			},
			githubCtx: &GitHubContext{
				ServerURL:   "https://github.com",
				Repository:  "example-org/example-repo",
				WorkflowRef: "example-org/example-repo/.github/workflows/calling-workflow.yml@refs/heads/main",
			},
			expectError: false,
			expectedID:  "https://github.com/example-org/example-repo/.github/workflows/_build.yml@refs/heads/leo/slsa/b",
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
					json.NewEncoder(w).Encode(map[string]string{"value": token})
				}))
			},
			githubCtx: &GitHubContext{
				ServerURL:   "https://github.com",
				Repository:  "gitpod-io/leeway",
				WorkflowRef: "gitpod-io/leeway/.github/workflows/build.yml@refs/heads/main",
			},
			expectError: false,
			expectedID:  "https://github.com/gitpod-io/leeway/.github/workflows/build.yml@refs/heads/main",
		},
		{
			name: "invalid JWT format - only 2 parts",
			setupServer: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					token := "header.payload"
					w.Header().Set("Content-Type", "application/json")
					json.NewEncoder(w).Encode(map[string]string{"value": token})
				}))
			},
			githubCtx: &GitHubContext{
				ServerURL:  "https://github.com",
				Repository: "org/repo",
			},
			expectError: true,
			errorMsg:    "invalid JWT token format",
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
					json.NewEncoder(w).Encode(map[string]string{"value": token})
				}))
			},
			githubCtx: &GitHubContext{
				ServerURL:  "https://github.com",
				Repository: "org/repo",
			},
			expectError: true,
			errorMsg:    "sub claim not found",
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
			expectError: false,
			expectedID:  "https://github.com/org/repo/.github/workflows/deploy.yml@refs/heads/main",
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
			expectError: true,
			errorMsg:    "job_workflow_ref not found",
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
			expectError: true,
			errorMsg:    "failed to fetch OIDC token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := tt.setupServer()
			defer server.Close()

			oldRequestURL := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL")
			oldRequestToken := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
			defer func() {
				os.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", oldRequestURL)
				os.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", oldRequestToken)
			}()

			os.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", server.URL)
			os.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "test-token")

			builderID, err := extractBuilderIDFromOIDC(context.Background(), tt.githubCtx)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedID, builderID)
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
				json.NewEncoder(w).Encode(map[string]string{"value": token})
			}))
			defer server.Close()

			oldRequestURL := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL")
			oldRequestToken := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
			defer func() {
				os.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", oldRequestURL)
				os.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", oldRequestToken)
			}()

			os.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", server.URL)
			os.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "test-token")

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
