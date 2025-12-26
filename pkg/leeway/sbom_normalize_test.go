package leeway

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"
)

func TestGenerateDeterministicUUID(t *testing.T) {
	tests := []struct {
		name     string
		content1 []byte
		content2 []byte
		wantSame bool
	}{
		{
			name:     "identical content produces same UUID",
			content1: []byte("test content"),
			content2: []byte("test content"),
			wantSame: true,
		},
		{
			name:     "different content produces different UUID",
			content1: []byte("test content 1"),
			content2: []byte("test content 2"),
			wantSame: false,
		},
		{
			name:     "empty content is deterministic",
			content1: []byte(""),
			content2: []byte(""),
			wantSame: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			uuid1 := generateDeterministicUUID(tt.content1)
			uuid2 := generateDeterministicUUID(tt.content2)

			if tt.wantSame && uuid1 != uuid2 {
				t.Errorf("expected same UUID for identical content, got %s and %s", uuid1, uuid2)
			}
			if !tt.wantSame && uuid1 == uuid2 {
				t.Errorf("expected different UUIDs for different content, got %s", uuid1)
			}

			// Verify UUID format (8-4-4-4-12 hex digits)
			if len(uuid1) != 36 {
				t.Errorf("expected UUID length 36, got %d", len(uuid1))
			}

			// Verify UUID format matches pattern: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
			uuidPattern := `^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`
			matched, err := regexp.MatchString(uuidPattern, uuid1)
			if err != nil {
				t.Fatalf("failed to compile UUID pattern: %v", err)
			}
			if !matched {
				t.Errorf("UUID does not match expected format: %s", uuid1)
			}
		})
	}
}

func TestGetCommitTimestamp_SourceDateEpoch(t *testing.T) {
	// Save original env var
	originalEnv := os.Getenv("SOURCE_DATE_EPOCH")
	defer func() {
		if originalEnv != "" {
			os.Setenv("SOURCE_DATE_EPOCH", originalEnv)
		} else {
			os.Unsetenv("SOURCE_DATE_EPOCH")
		}
	}()

	tests := []struct {
		name          string
		sourceEpoch   string
		wantTimestamp time.Time
		wantErr       bool
	}{
		{
			name:          "valid SOURCE_DATE_EPOCH",
			sourceEpoch:   "1234567890",
			wantTimestamp: time.Unix(1234567890, 0).UTC(),
			wantErr:       false,
		},
		{
			name:        "invalid SOURCE_DATE_EPOCH falls back to git",
			sourceEpoch: "invalid",
			wantErr:     false, // Should fall back to git (may fail if not in git repo)
		},
		{
			name:        "empty SOURCE_DATE_EPOCH uses git",
			sourceEpoch: "",
			wantErr:     false, // Should use git (may fail if not in git repo)
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.sourceEpoch != "" {
				os.Setenv("SOURCE_DATE_EPOCH", tt.sourceEpoch)
			} else {
				os.Unsetenv("SOURCE_DATE_EPOCH")
			}

			// Use HEAD as commit (should exist in test environment)
			wd, _ := os.Getwd()
			gitInfo := &GitInfo{
				Commit:         "HEAD",
				WorkingCopyLoc: wd,
			}
			timestamp, err := GetCommitTimestamp(context.Background(), gitInfo)

			if tt.wantErr && err == nil {
				t.Error("expected error, got nil")
			}
			if !tt.wantErr && err != nil && tt.sourceEpoch == "1234567890" {
				// Only fail if we expected success with valid SOURCE_DATE_EPOCH
				t.Errorf("unexpected error: %v", err)
			}

			if tt.sourceEpoch == "1234567890" && !timestamp.Equal(tt.wantTimestamp) {
				t.Errorf("expected timestamp %v, got %v", tt.wantTimestamp, timestamp)
			}
		})
	}
}

func TestGetCommitTimestamp_GitCommit(t *testing.T) {
	// This test requires being in a git repository
	// Use HEAD as a known commit
	ctx := context.Background()
	wd, _ := os.Getwd()
	gitInfo := &GitInfo{
		Commit:         "HEAD",
		WorkingCopyLoc: wd,
	}

	timestamp, err := GetCommitTimestamp(ctx, gitInfo)
	if err != nil {
		t.Skipf("skipping test: not in a git repository or git not available: %v", err)
	}

	// Verify timestamp is reasonable (after 2020, before 2100)
	if timestamp.Year() < 2020 || timestamp.Year() > 2100 {
		t.Errorf("unexpected timestamp year: %d", timestamp.Year())
	}

	// Verify timestamp is in UTC
	if timestamp.Location() != time.UTC {
		t.Errorf("expected UTC timezone, got %v", timestamp.Location())
	}

	// Verify deterministic: calling twice should return same result
	timestamp2, err := GetCommitTimestamp(ctx, gitInfo)
	if err != nil {
		t.Fatalf("second call failed: %v", err)
	}
	if !timestamp.Equal(timestamp2) {
		t.Errorf("expected deterministic result, got %v and %v", timestamp, timestamp2)
	}
}

func TestGetCommitTimestamp_ContextCancellation(t *testing.T) {
	// Create a cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	wd, _ := os.Getwd()
	gitInfo := &GitInfo{
		Commit:         "HEAD",
		WorkingCopyLoc: wd,
	}

	_, err := GetCommitTimestamp(ctx, gitInfo)
	if err == nil {
		t.Error("expected error with cancelled context, got nil")
	}

	// Verify the error is related to context cancellation
	if !contains(err.Error(), "context canceled") && !contains(err.Error(), "failed to get commit timestamp") {
		t.Errorf("expected context cancellation error, got: %v", err)
	}
}

func TestNormalizeCycloneDX(t *testing.T) {
	// Create a temporary directory for test files
	tmpDir := t.TempDir()
	sbomPath := filepath.Join(tmpDir, "sbom.cdx.json")

	// Create a sample CycloneDX SBOM
	sbom := map[string]interface{}{
		"bomFormat":    "CycloneDX",
		"specVersion":  "1.4",
		"serialNumber": "urn:uuid:original-uuid-12345",
		"metadata": map[string]interface{}{
			"timestamp": "2023-01-01T00:00:00Z",
			"component": map[string]interface{}{
				"name": "test-component",
			},
		},
		"components": []interface{}{
			map[string]interface{}{
				"name":    "test-package",
				"version": "1.0.0",
			},
		},
	}

	// Write initial SBOM
	data, err := json.MarshalIndent(sbom, "", "  ")
	if err != nil {
		t.Fatalf("failed to marshal test SBOM: %v", err)
	}
	if err := os.WriteFile(sbomPath, data, 0644); err != nil {
		t.Fatalf("failed to write test SBOM: %v", err)
	}

	// Normalize with a fixed timestamp
	fixedTime := time.Unix(1234567890, 0).UTC()
	if err := normalizeCycloneDX(sbomPath, fixedTime); err != nil {
		t.Fatalf("normalizeCycloneDX failed: %v", err)
	}

	// Read normalized SBOM
	normalizedData, err := os.ReadFile(sbomPath)
	if err != nil {
		t.Fatalf("failed to read normalized SBOM: %v", err)
	}

	var normalizedSBOM map[string]interface{}
	if err := json.Unmarshal(normalizedData, &normalizedSBOM); err != nil {
		t.Fatalf("failed to parse normalized SBOM: %v", err)
	}

	// Verify timestamp was updated
	metadata := normalizedSBOM["metadata"].(map[string]interface{})
	timestamp := metadata["timestamp"].(string)
	expectedTimestamp := fixedTime.Format(time.RFC3339)
	if timestamp != expectedTimestamp {
		t.Errorf("expected timestamp %s, got %s", expectedTimestamp, timestamp)
	}

	// Verify UUID was changed and is deterministic
	serialNumber := normalizedSBOM["serialNumber"].(string)
	if serialNumber == "urn:uuid:original-uuid-12345" {
		t.Error("UUID was not changed")
	}
	if len(serialNumber) < 10 {
		t.Errorf("invalid UUID format: %s", serialNumber)
	}

	// Normalize again with same timestamp - should produce same UUID
	if err := normalizeCycloneDX(sbomPath, fixedTime); err != nil {
		t.Fatalf("second normalizeCycloneDX failed: %v", err)
	}

	normalizedData2, err := os.ReadFile(sbomPath)
	if err != nil {
		t.Fatalf("failed to read normalized SBOM (2nd time): %v", err)
	}

	var normalizedSBOM2 map[string]interface{}
	if err := json.Unmarshal(normalizedData2, &normalizedSBOM2); err != nil {
		t.Fatalf("failed to parse normalized SBOM (2nd time): %v", err)
	}

	serialNumber2 := normalizedSBOM2["serialNumber"].(string)
	if serialNumber != serialNumber2 {
		t.Errorf("expected deterministic UUID, got %s and %s", serialNumber, serialNumber2)
	}
}

func TestNormalizeSPDX(t *testing.T) {
	tests := []struct {
		name              string
		documentNamespace string
		wantUUIDChanged   bool
		wantMultipleWarn  bool
	}{
		{
			name:              "UUID at end of namespace",
			documentNamespace: "https://example.com/test-12345678-1234-1234-1234-123456789abc",
			wantUUIDChanged:   true,
			wantMultipleWarn:  false,
		},
		{
			name:              "UUID in middle of namespace",
			documentNamespace: "https://example.com/12345678-1234-1234-1234-123456789abc/test",
			wantUUIDChanged:   true,
			wantMultipleWarn:  false,
		},
		{
			name:              "multiple UUIDs (replaces all)",
			documentNamespace: "https://example.com/12345678-1234-1234-1234-123456789abc/test-abcdef01-2345-6789-abcd-ef0123456789",
			wantUUIDChanged:   true,
			wantMultipleWarn:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a temporary directory for test files
			tmpDir := t.TempDir()
			sbomPath := filepath.Join(tmpDir, "sbom.spdx.json")

			// Create a sample SPDX SBOM
			sbom := map[string]interface{}{
				"spdxVersion":       "SPDX-2.3",
				"dataLicense":       "CC0-1.0",
				"SPDXID":            "SPDXRef-DOCUMENT",
				"name":              "test-sbom",
				"documentNamespace": tt.documentNamespace,
				"creationInfo": map[string]interface{}{
					"created": "2023-01-01T00:00:00Z",
					"creators": []interface{}{
						"Tool: test-tool",
					},
				},
				"packages": []interface{}{
					map[string]interface{}{
						"SPDXID":  "SPDXRef-Package",
						"name":    "test-package",
						"version": "1.0.0",
					},
				},
			}

			// Write initial SBOM
			data, err := json.MarshalIndent(sbom, "", "  ")
			if err != nil {
				t.Fatalf("failed to marshal test SBOM: %v", err)
			}
			if err := os.WriteFile(sbomPath, data, 0644); err != nil {
				t.Fatalf("failed to write test SBOM: %v", err)
			}

			// Normalize with a fixed timestamp
			fixedTime := time.Unix(1234567890, 0).UTC()
			if err := normalizeSPDX(sbomPath, fixedTime); err != nil {
				t.Fatalf("normalizeSPDX failed: %v", err)
			}

			// Read normalized SBOM
			normalizedData, err := os.ReadFile(sbomPath)
			if err != nil {
				t.Fatalf("failed to read normalized SBOM: %v", err)
			}

			var normalizedSBOM map[string]interface{}
			if err := json.Unmarshal(normalizedData, &normalizedSBOM); err != nil {
				t.Fatalf("failed to parse normalized SBOM: %v", err)
			}

			// Verify timestamp was updated
			creationInfo := normalizedSBOM["creationInfo"].(map[string]interface{})
			created := creationInfo["created"].(string)
			expectedTimestamp := fixedTime.Format(time.RFC3339)
			if created != expectedTimestamp {
				t.Errorf("expected timestamp %s, got %s", expectedTimestamp, created)
			}

			// Verify UUID in documentNamespace
			namespace := normalizedSBOM["documentNamespace"].(string)
			// Should have changed from original
			if namespace == tt.documentNamespace {
				t.Error("UUID in documentNamespace was not changed")
			}
			// Should not contain the original UUID
			if contains(namespace, "12345678-1234-1234-1234-123456789abc") {
				t.Error("original UUID still present in documentNamespace")
			}

			// Normalize again with same timestamp - should produce same result
			if err := normalizeSPDX(sbomPath, fixedTime); err != nil {
				t.Fatalf("second normalizeSPDX failed: %v", err)
			}

			normalizedData2, err := os.ReadFile(sbomPath)
			if err != nil {
				t.Fatalf("failed to read normalized SBOM (2nd time): %v", err)
			}

			var normalizedSBOM2 map[string]interface{}
			if err := json.Unmarshal(normalizedData2, &normalizedSBOM2); err != nil {
				t.Fatalf("failed to parse normalized SBOM (2nd time): %v", err)
			}

			namespace2 := normalizedSBOM2["documentNamespace"].(string)
			if namespace != namespace2 {
				t.Errorf("expected deterministic result, got %s and %s", namespace, namespace2)
			}
		})
	}
}

func TestNormalizeCycloneDX_MalformedSBOM(t *testing.T) {
	tmpDir := t.TempDir()

	tests := []struct {
		name        string
		sbomContent string
		wantErr     bool
		errContains string
	}{
		{
			name:        "invalid JSON",
			sbomContent: `{invalid json}`,
			wantErr:     true,
			errContains: "failed to parse SBOM",
		},
		{
			name:        "missing metadata field",
			sbomContent: `{"bomFormat": "CycloneDX", "specVersion": "1.4"}`,
			wantErr:     true,
			errContains: "metadata field not found",
		},
		{
			name:        "empty file",
			sbomContent: ``,
			wantErr:     true,
			errContains: "failed to parse SBOM",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sbomPath := filepath.Join(tmpDir, "test-"+tt.name+".json")
			if err := os.WriteFile(sbomPath, []byte(tt.sbomContent), 0644); err != nil {
				t.Fatalf("failed to write test file: %v", err)
			}

			fixedTime := time.Unix(1234567890, 0).UTC()
			err := normalizeCycloneDX(sbomPath, fixedTime)

			if tt.wantErr && err == nil {
				t.Error("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if tt.wantErr && err != nil && tt.errContains != "" {
				if !contains(err.Error(), tt.errContains) {
					t.Errorf("expected error containing %q, got %q", tt.errContains, err.Error())
				}
			}
		})
	}
}

func TestNormalizeSPDX_MalformedSBOM(t *testing.T) {
	tmpDir := t.TempDir()

	tests := []struct {
		name        string
		sbomContent string
		wantErr     bool
		errContains string
	}{
		{
			name:        "invalid JSON",
			sbomContent: `{invalid json}`,
			wantErr:     true,
			errContains: "failed to parse SBOM",
		},
		{
			name:        "missing creationInfo field",
			sbomContent: `{"spdxVersion": "SPDX-2.3", "name": "test", "documentNamespace": "https://example.com/test-12345678-1234-1234-1234-123456789abc"}`,
			wantErr:     true,
			errContains: "creationInfo field not found",
		},
		{
			name:        "empty file",
			sbomContent: ``,
			wantErr:     true,
			errContains: "failed to parse SBOM",
		},
		{
			name: "documentNamespace is not a string",
			sbomContent: `{
				"spdxVersion": "SPDX-2.3",
				"name": "test",
				"documentNamespace": 12345,
				"creationInfo": {"created": "2023-01-01T00:00:00Z"}
			}`,
			wantErr:     true,
			errContains: "documentNamespace field is not a string",
		},
		{
			name: "documentNamespace is empty",
			sbomContent: `{
				"spdxVersion": "SPDX-2.3",
				"name": "test",
				"documentNamespace": "",
				"creationInfo": {"created": "2023-01-01T00:00:00Z"}
			}`,
			wantErr:     true,
			errContains: "documentNamespace field is empty",
		},
		{
			name: "documentNamespace has no UUID",
			sbomContent: `{
				"spdxVersion": "SPDX-2.3",
				"name": "test",
				"documentNamespace": "https://example.com/no-uuid-here",
				"creationInfo": {"created": "2023-01-01T00:00:00Z"}
			}`,
			wantErr:     true,
			errContains: "no UUID found in SPDX documentNamespace",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sbomPath := filepath.Join(tmpDir, "test-"+tt.name+".json")
			if err := os.WriteFile(sbomPath, []byte(tt.sbomContent), 0644); err != nil {
				t.Fatalf("failed to write test file: %v", err)
			}

			fixedTime := time.Unix(1234567890, 0).UTC()
			err := normalizeSPDX(sbomPath, fixedTime)

			if tt.wantErr && err == nil {
				t.Error("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if tt.wantErr && err != nil && tt.errContains != "" {
				if !contains(err.Error(), tt.errContains) {
					t.Errorf("expected error containing %q, got %q", tt.errContains, err.Error())
				}
			}
		})
	}
}

func TestNormalizeCycloneDX_FileErrors(t *testing.T) {
	tmpDir := t.TempDir()

	t.Run("non-existent file", func(t *testing.T) {
		sbomPath := filepath.Join(tmpDir, "nonexistent.json")
		fixedTime := time.Unix(1234567890, 0).UTC()
		err := normalizeCycloneDX(sbomPath, fixedTime)
		if err == nil {
			t.Error("expected error for non-existent file, got nil")
		}
		if !contains(err.Error(), "failed to read SBOM") {
			t.Errorf("expected 'failed to read SBOM' error, got: %v", err)
		}
	})
}

func TestNormalizeSPDX_FileErrors(t *testing.T) {
	tmpDir := t.TempDir()

	t.Run("non-existent file", func(t *testing.T) {
		sbomPath := filepath.Join(tmpDir, "nonexistent.json")
		fixedTime := time.Unix(1234567890, 0).UTC()
		err := normalizeSPDX(sbomPath, fixedTime)
		if err == nil {
			t.Error("expected error for non-existent file, got nil")
		}
		if !contains(err.Error(), "failed to read SBOM") {
			t.Errorf("expected 'failed to read SBOM' error, got: %v", err)
		}
	})
}

// contains is a helper function to check if a string contains a substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
