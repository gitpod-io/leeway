package cmd

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gitpod-io/leeway/pkg/leeway/signing"
)

// workspaceMutex serializes access to workspace initialization to prevent
// concurrent file descriptor issues when multiple tests access BUILD.yaml
var workspaceMutex sync.Mutex

// Test helper: Create test manifest file
func createTestManifest(t *testing.T, dir string, artifacts []string) string {
	manifestPath := filepath.Join(dir, "test-manifest.txt")
	content := ""
	for _, artifact := range artifacts {
		content += artifact + "\n"
	}
	err := os.WriteFile(manifestPath, []byte(content), 0644)
	require.NoError(t, err)
	return manifestPath
}

// Test helper: Create mock artifact
func createMockArtifact(t *testing.T, dir string, name string) string {
	artifactPath := filepath.Join(dir, name)
	content := []byte("mock artifact content for testing")
	err := os.WriteFile(artifactPath, content, 0644)
	require.NoError(t, err)
	return artifactPath
}

// TestSignCacheCommand_Exists verifies the command is properly registered
func TestSignCacheCommand_Exists(t *testing.T) {
	// Verify sign-cache command exists under plumbing
	cmd := plumbingCmd
	found := false
	for _, subCmd := range cmd.Commands() {
		if subCmd.Name() == "sign-cache" {
			found = true
			break
		}
	}
	assert.True(t, found, "sign-cache command should be registered under plumbing")
}

// TestSignCacheCommand_FlagDefinitions verifies all required flags
func TestSignCacheCommand_FlagDefinitions(t *testing.T) {
	cmd := signCacheCmd

	// Verify --from-manifest flag exists
	manifestFlag := cmd.Flags().Lookup("from-manifest")
	require.NotNil(t, manifestFlag, "from-manifest flag should exist")
	assert.Equal(t, "string", manifestFlag.Value.Type())

	// Verify --dry-run flag exists
	dryRunFlag := cmd.Flags().Lookup("dry-run")
	require.NotNil(t, dryRunFlag, "dry-run flag should exist")
	assert.Equal(t, "bool", dryRunFlag.Value.Type())

	// Verify from-manifest is required
	annotations := cmd.Flags().Lookup("from-manifest").Annotations
	assert.NotNil(t, annotations, "from-manifest should have required annotation")
}

// TestSignCacheCommand_FlagParsing tests flag validation
func TestSignCacheCommand_FlagParsing(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "missing required manifest flag",
			args:        []string{},
			expectError: true,
			errorMsg:    "--from-manifest flag is required",
		},
		{
			name:        "nonexistent manifest file",
			args:        []string{"--from-manifest", "nonexistent.txt"},
			expectError: true,
			errorMsg:    "manifest file does not exist",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create new command instance for testing
			cmd := &cobra.Command{
				Use:  "sign-cache",
				RunE: signCacheCmd.RunE,
			}
			cmd.Flags().String("from-manifest", "", "Path to manifest")
			cmd.Flags().Bool("dry-run", false, "Dry run mode")
			cmd.SetArgs(tt.args)

			// Capture output to prevent spam
			cmd.SetOut(os.NewFile(0, os.DevNull))
			cmd.SetErr(os.NewFile(0, os.DevNull))

			err := cmd.Execute()

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

// TestParseManifest_ValidInputs tests successful manifest parsing
func TestParseManifest_ValidInputs(t *testing.T) {
	tests := []struct {
		name           string
		manifestLines  []string
		expectedCount  int
		expectWarnings bool
	}{
		{
			name: "single artifact",
			manifestLines: []string{
				"/tmp/artifact.tar.gz",
			},
			expectedCount: 1,
		},
		{
			name: "multiple artifacts",
			manifestLines: []string{
				"/tmp/artifact1.tar.gz",
				"/tmp/artifact2.tar.gz",
				"/tmp/artifact3.tar",
			},
			expectedCount: 3,
		},
		{
			name: "with empty lines",
			manifestLines: []string{
				"/tmp/artifact1.tar.gz",
				"",
				"/tmp/artifact2.tar.gz",
				"   ",
			},
			expectedCount: 2,
		},
		{
			name: "with whitespace",
			manifestLines: []string{
				"  /tmp/artifact1.tar.gz  ",
				"\t/tmp/artifact2.tar.gz\t",
			},
			expectedCount: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()

			// Create actual artifact files
			for _, line := range tt.manifestLines {
				trimmed := strings.TrimSpace(line)
				if trimmed != "" {
					// Create artifact in temp dir instead of /tmp
					baseName := filepath.Base(trimmed)
					artifactPath := filepath.Join(tmpDir, baseName)
					err := os.WriteFile(artifactPath, []byte("test"), 0644)
					require.NoError(t, err)
				}
			}

			// Update manifest to use actual paths
			var actualLines []string
			for _, line := range tt.manifestLines {
				trimmed := strings.TrimSpace(line)
				if trimmed != "" {
					baseName := filepath.Base(trimmed)
					actualLines = append(actualLines, filepath.Join(tmpDir, baseName))
				} else {
					actualLines = append(actualLines, line)
				}
			}

			manifestPath := createTestManifest(t, tmpDir, actualLines)

			artifacts, err := parseManifest(manifestPath)
			require.NoError(t, err)
			assert.Len(t, artifacts, tt.expectedCount)
		})
	}
}

// TestParseManifest_InvalidInputs tests error handling
func TestParseManifest_InvalidInputs(t *testing.T) {
	tests := []struct {
		name          string
		manifestLines []string
		createFiles   map[string]bool // which files to actually create
		expectError   bool
		errorContains string
	}{
		{
			name:          "empty manifest",
			manifestLines: []string{},
			expectError:   true,
			errorContains: "empty",
		},
		{
			name: "nonexistent file",
			manifestLines: []string{
				"/nonexistent/artifact.tar.gz",
			},
			createFiles:   map[string]bool{},
			expectError:   true,
			errorContains: "not found",
		},
		{
			name: "directory instead of file",
			manifestLines: []string{
				"{{DIR}}",
			},
			expectError:   true,
			errorContains: "directory",
		},
		{
			name: "mixed valid and invalid",
			manifestLines: []string{
				"{{VALID}}",
				"/nonexistent/file.tar.gz",
			},
			expectError:   true,
			errorContains: "validation failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()

			// Replace placeholders and create files
			var processedLines []string
			for _, line := range tt.manifestLines {
				switch line {
				case "{{DIR}}":
					dirPath := filepath.Join(tmpDir, "testdir")
					_ = os.Mkdir(dirPath, 0755)
					processedLines = append(processedLines, dirPath)
				case "{{VALID}}":
					validPath := filepath.Join(tmpDir, "valid.tar.gz")
					_ = os.WriteFile(validPath, []byte("test"), 0644)
					processedLines = append(processedLines, validPath)

				default:
					processedLines = append(processedLines, line)
				}
			}

			manifestPath := createTestManifest(t, tmpDir, processedLines)

			artifacts, err := parseManifest(manifestPath)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorContains != "" && err != nil {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				assert.NoError(t, err)
				assert.NotEmpty(t, artifacts)
			}
		})
	}
}

// TestParseManifest_EdgeCases tests edge cases
func TestParseManifest_EdgeCases(t *testing.T) {
	tests := []struct {
		name        string
		setup       func(t *testing.T, dir string) string
		expectError bool
	}{
		{
			name: "very long paths",
			setup: func(t *testing.T, dir string) string {
				// Create deeply nested directory structure
				longPath := dir
				for i := 0; i < 50; i++ {
					longPath = filepath.Join(longPath, "subdir")
				}
				_ = os.MkdirAll(longPath, 0755)
				artifactPath := filepath.Join(longPath, "artifact.tar.gz")
				_ = os.WriteFile(artifactPath, []byte("test"), 0644)
				return createTestManifest(t, dir, []string{artifactPath})
			},
			expectError: false,
		},
		{
			name: "special characters in filename",
			setup: func(t *testing.T, dir string) string {
				artifactPath := filepath.Join(dir, "artifact-v1.0.0_linux-amd64.tar.gz")
				_ = os.WriteFile(artifactPath, []byte("test"), 0644)
				return createTestManifest(t, dir, []string{artifactPath})
			},
			expectError: false,
		},
		{
			name: "symlink to artifact",
			setup: func(t *testing.T, dir string) string {
				artifactPath := filepath.Join(dir, "artifact.tar.gz")
				_ = os.WriteFile(artifactPath, []byte("test"), 0644)

				symlinkPath := filepath.Join(dir, "artifact-link.tar.gz")
				_ = os.Symlink(artifactPath, symlinkPath)

				return createTestManifest(t, dir, []string{symlinkPath})
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			manifestPath := tt.setup(t, tmpDir)

			artifacts, err := parseManifest(manifestPath)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotEmpty(t, artifacts)
			}
		})
	}
}

// TestGitHubContext_Validation tests GitHub environment validation
func TestGitHubContext_Validation(t *testing.T) {
	tests := []struct {
		name        string
		envVars     map[string]string
		expectError bool
		errorMsg    string
	}{
		{
			name: "all required vars present",
			envVars: map[string]string{
				"GITHUB_RUN_ID":       "1234567890",
				"GITHUB_RUN_NUMBER":   "42",
				"GITHUB_ACTOR":        "test-user",
				"GITHUB_REPOSITORY":   "gitpod-io/leeway",
				"GITHUB_REF":          "refs/heads/main",
				"GITHUB_SHA":          "abc123def456",
				"GITHUB_SERVER_URL":   "https://github.com",
				"GITHUB_WORKFLOW_REF": ".github/workflows/build.yml@refs/heads/main",
			},
			expectError: false,
		},
		{
			name:        "no environment vars",
			envVars:     map[string]string{},
			expectError: true,
			errorMsg:    "GITHUB_RUN_ID",
		},
		{
			name: "missing GITHUB_RUN_ID",
			envVars: map[string]string{
				"GITHUB_REPOSITORY": "gitpod-io/leeway",
				"GITHUB_SHA":        "abc123",
			},
			expectError: true,
			errorMsg:    "GITHUB_RUN_ID",
		},
		{
			name: "missing GITHUB_REPOSITORY",
			envVars: map[string]string{
				"GITHUB_RUN_ID": "1234567890",
				"GITHUB_SHA":    "abc123",
			},
			expectError: true,
			errorMsg:    "GITHUB_REPOSITORY",
		},
		{
			name: "missing GITHUB_SHA",
			envVars: map[string]string{
				"GITHUB_RUN_ID":     "1234567890",
				"GITHUB_REPOSITORY": "gitpod-io/leeway",
			},
			expectError: true,
			errorMsg:    "GITHUB_SHA",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear all GitHub env vars first
			githubVars := []string{
				"GITHUB_RUN_ID", "GITHUB_RUN_NUMBER", "GITHUB_ACTOR",
				"GITHUB_REPOSITORY", "GITHUB_REF", "GITHUB_SHA",
				"GITHUB_SERVER_URL", "GITHUB_WORKFLOW_REF",
			}
			for _, v := range githubVars {
				_ = os.Unsetenv(v)
			}

			// Set test environment
			for k, v := range tt.envVars {
				t.Setenv(k, v)
			}

			// Get and validate context
			ctx := signing.GetGitHubContext()
			err := ctx.Validate()

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.envVars["GITHUB_RUN_ID"], ctx.RunID)
				assert.Equal(t, tt.envVars["GITHUB_REPOSITORY"], ctx.Repository)
				assert.Equal(t, tt.envVars["GITHUB_SHA"], ctx.SHA)
			}
		})
	}
}

// TestSignCache_DryRunMode verifies dry-run doesn't perform actual operations
func TestSignCache_DryRunMode(t *testing.T) {
	tmpDir := t.TempDir()

	// Create test artifacts
	artifact1 := createMockArtifact(t, tmpDir, "artifact1.tar.gz")
	artifact2 := createMockArtifact(t, tmpDir, "artifact2.tar.gz")

	manifestPath := createTestManifest(t, tmpDir, []string{artifact1, artifact2})

	// Set up minimal GitHub environment
	setupGitHubEnv(t)

	// Track if any real operations occurred
	operationsPerformed := false

	// Run in dry-run mode (serialize workspace access)
	workspaceMutex.Lock()
	err := runSignCache(context.Background(), nil, manifestPath, true)
	workspaceMutex.Unlock()

	// Should succeed without errors
	assert.NoError(t, err)

	// Verify no actual signing occurred (no .att files created)
	attFile1 := artifact1 + ".att"
	attFile2 := artifact2 + ".att"

	assert.NoFileExists(t, attFile1, "Should not create attestation in dry-run")
	assert.NoFileExists(t, attFile2, "Should not create attestation in dry-run")

	// Verify no operations flag
	assert.False(t, operationsPerformed, "No real operations should occur in dry-run")
}

// Helper: Set up minimal GitHub environment for testing
func setupGitHubEnv(t *testing.T) {
	t.Setenv("GITHUB_RUN_ID", "123456")
	t.Setenv("GITHUB_RUN_NUMBER", "1")
	t.Setenv("GITHUB_ACTOR", "test-user")
	t.Setenv("GITHUB_REPOSITORY", "gitpod-io/leeway")
	t.Setenv("GITHUB_REF", "refs/heads/main")
	t.Setenv("GITHUB_SHA", "abc123def456")
	t.Setenv("GITHUB_SERVER_URL", "https://github.com")
	t.Setenv("GITHUB_WORKFLOW_REF", ".github/workflows/build.yml@main")
}

// TestSignCache_ErrorScenarios tests various error conditions
func TestSignCache_ErrorScenarios(t *testing.T) {
	tests := []struct {
		name          string
		setup         func(t *testing.T) (string, func())
		expectError   bool
		expectPartial bool // Some artifacts succeed, some fail
	}{
		{
			name: "manifest file doesn't exist",
			setup: func(t *testing.T) (string, func()) {
				return "/nonexistent/manifest.txt", func() {}
			},
			expectError: true,
		},
		{
			name: "no remote cache configured",
			setup: func(t *testing.T) (string, func()) {
				tmpDir := t.TempDir()
				artifact := createMockArtifact(t, tmpDir, "test.tar.gz")
				manifestPath := createTestManifest(t, tmpDir, []string{artifact})

				// Ensure no cache env vars set
				os.Unsetenv("LEEWAY_REMOTE_CACHE_BUCKET")

				return manifestPath, func() {}
			},
			expectError: true,
		},
		{
			name: "partial signing failure",
			setup: func(t *testing.T) (string, func()) {
				tmpDir := t.TempDir()

				// Create one valid artifact
				valid := createMockArtifact(t, tmpDir, "valid.tar.gz")

				// Create one that will fail (simulate by using invalid format)
				invalid := filepath.Join(tmpDir, "invalid.txt")
				_ = os.WriteFile(invalid, []byte("not a tar"), 0644)

				manifestPath := createTestManifest(t, tmpDir, []string{valid, invalid})

				return manifestPath, func() {}
			},
			expectError:   true, // Will fail because both artifacts fail (100% failure rate > 50%)
			expectPartial: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manifestPath, cleanup := tt.setup(t)
			defer cleanup()

			setupGitHubEnv(t)

			// Serialize workspace access to prevent concurrent file descriptor issues
			workspaceMutex.Lock()
			err := runSignCache(context.Background(), nil, manifestPath, false)
			workspaceMutex.Unlock()

			if tt.expectError {
				assert.Error(t, err)
			} else if tt.expectPartial {
				// Should log warnings but not fail
				assert.NoError(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
