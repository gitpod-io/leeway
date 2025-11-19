package leeway_test

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/gitpod-io/leeway/pkg/leeway"
)

func TestAccessAttestationBundleInCachedArchive(t *testing.T) {
	tests := []struct {
		name          string
		setupFunc     func(t *testing.T, dir string) string
		expectError   bool
		expectContent string
	}{
		{
			name: "provenance exists outside tar.gz",
			setupFunc: func(t *testing.T, dir string) string {
				artifactPath := filepath.Join(dir, "test.tar.gz")
				provenancePath := artifactPath + ".provenance.jsonl"
				
				// Create empty artifact
				if err := os.WriteFile(artifactPath, []byte("fake tar.gz"), 0644); err != nil {
					t.Fatal(err)
				}
				
				// Create provenance file
				content := `{"test": "provenance"}`
				if err := os.WriteFile(provenancePath, []byte(content), 0644); err != nil {
					t.Fatal(err)
				}
				
				return artifactPath
			},
			expectError:   false,
			expectContent: `{"test": "provenance"}`,
		},
		{
			name: "provenance does not exist",
			setupFunc: func(t *testing.T, dir string) string {
				artifactPath := filepath.Join(dir, "test.tar.gz")
				
				// Create only artifact, no provenance
				if err := os.WriteFile(artifactPath, []byte("fake tar.gz"), 0644); err != nil {
					t.Fatal(err)
				}
				
				return artifactPath
			},
			expectError: true,
		},
		{
			name: "artifact does not exist",
			setupFunc: func(t *testing.T, dir string) string {
				return filepath.Join(dir, "nonexistent.tar.gz")
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			artifactPath := tt.setupFunc(t, tmpDir)

			var content []byte
			err := leeway.AccessAttestationBundleInCachedArchive(artifactPath, func(bundle io.Reader) error {
				var readErr error
				content, readErr = io.ReadAll(bundle)
				return readErr
			})

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if string(content) != tt.expectContent {
					t.Errorf("expected content %q, got %q", tt.expectContent, string(content))
				}
			}
		})
	}
}
