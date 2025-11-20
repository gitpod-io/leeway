package leeway_test

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
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
				provenancePath := artifactPath + leeway.ProvenanceBundleFilename

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

func TestProvenanceNotInTarGz(t *testing.T) {
	// Create a test tar.gz with provenance inside (old behavior)
	tmpDir := t.TempDir()
	artifactPath := filepath.Join(tmpDir, "test.tar.gz")

	// Create tar.gz with provenance-bundle.jsonl inside
	f, err := os.Create(artifactPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	gw := gzip.NewWriter(f)
	defer gw.Close()

	tw := tar.NewWriter(gw)
	defer tw.Close()

	// Add a regular file
	if err := tw.WriteHeader(&tar.Header{
		Name: "./test.txt",
		Mode: 0644,
		Size: 4,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte("test")); err != nil {
		t.Fatal(err)
	}

	// Add provenance-bundle.jsonl inside tar (old behavior - should NOT happen)
	provenanceContent := `{"test": "provenance"}`
	if err := tw.WriteHeader(&tar.Header{
		Name: "./provenance-bundle.jsonl",
		Mode: 0644,
		Size: int64(len(provenanceContent)),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte(provenanceContent)); err != nil {
		t.Fatal(err)
	}

	tw.Close()
	gw.Close()
	f.Close()

	// Verify that AccessAttestationBundleInCachedArchive does NOT find it inside tar.gz
	err = leeway.AccessAttestationBundleInCachedArchive(artifactPath, func(bundle io.Reader) error {
		t.Error("Should not find provenance inside tar.gz with new implementation")
		return nil
	})

	if !errors.Is(err, leeway.ErrNoAttestationBundle) {
		t.Errorf("Expected ErrNoAttestationBundle when provenance is only inside tar.gz, got: %v", err)
	}
}

func TestProvenanceOutsideTarGz(t *testing.T) {
	tmpDir := t.TempDir()
	artifactPath := filepath.Join(tmpDir, "test.tar.gz")
	provenancePath := artifactPath + leeway.ProvenanceBundleFilename

	// Create a simple tar.gz WITHOUT provenance inside
	f, err := os.Create(artifactPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	gw := gzip.NewWriter(f)
	defer gw.Close()

	tw := tar.NewWriter(gw)
	defer tw.Close()

	// Add a regular file
	if err := tw.WriteHeader(&tar.Header{
		Name: "./test.txt",
		Mode: 0644,
		Size: 4,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte("test")); err != nil {
		t.Fatal(err)
	}

	tw.Close()
	gw.Close()
	f.Close()

	// Create provenance OUTSIDE tar.gz (new behavior)
	provenanceContent := `{"test": "provenance outside"}`
	if err := os.WriteFile(provenancePath, []byte(provenanceContent), 0644); err != nil {
		t.Fatal(err)
	}

	// Verify tar.gz does NOT contain provenance
	tarContainsProvenance := false
	f2, err := os.Open(artifactPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f2.Close()

	gr, err := gzip.NewReader(f2)
	if err != nil {
		t.Fatal(err)
	}
	defer gr.Close()

	tr := tar.NewReader(gr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(hdr.Name, "provenance") {
			tarContainsProvenance = true
			break
		}
	}

	if tarContainsProvenance {
		t.Error("tar.gz should NOT contain provenance file")
	}

	// Verify we can read provenance from outside
	var readContent []byte
	err = leeway.AccessAttestationBundleInCachedArchive(artifactPath, func(bundle io.Reader) error {
		readContent, err = io.ReadAll(bundle)
		return err
	})

	if err != nil {
		t.Errorf("Failed to read provenance from outside tar.gz: %v", err)
	}

	if string(readContent) != provenanceContent {
		t.Errorf("Expected content %q, got %q", provenanceContent, string(readContent))
	}
}

func TestProvenancePathExtensionHandling(t *testing.T) {
	tests := []struct {
		name             string
		artifactPath     string
		expectedProvPath string
	}{
		{
			name:             "tar.gz extension",
			artifactPath:     "/cache/pkg.tar.gz",
			expectedProvPath: "/cache/pkg.tar.gz.provenance.jsonl",
		},
		{
			name:             "tar extension",
			artifactPath:     "/cache/pkg.tar",
			expectedProvPath: "/cache/pkg.tar.provenance.jsonl",
		},
		{
			name:             "no extension",
			artifactPath:     "/cache/pkg",
			expectedProvPath: "/cache/pkg.provenance.jsonl",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// The provenance path is always <artifact>.provenance.jsonl
			// This is handled by AccessAttestationBundleInCachedArchive
			expectedPath := tt.artifactPath + leeway.ProvenanceBundleFilename
			if expectedPath != tt.expectedProvPath {
				t.Errorf("Expected provenance path %q, got %q", tt.expectedProvPath, expectedPath)
			}
		})
	}
}

func TestProvenanceDirectoryCreation(t *testing.T) {
	tmpDir := t.TempDir()

	// Create nested directory structure
	nestedDir := filepath.Join(tmpDir, "cache", "subdir", "nested")
	artifactPath := filepath.Join(nestedDir, "test.tar.gz")
	provenancePath := artifactPath + leeway.ProvenanceBundleFilename

	// Directory doesn't exist yet
	if _, err := os.Stat(nestedDir); !os.IsNotExist(err) {
		t.Fatal("Directory should not exist yet")
	}

	// Create directory and write provenance
	if err := os.MkdirAll(filepath.Dir(provenancePath), 0755); err != nil {
		t.Fatalf("Failed to create directory: %v", err)
	}

	provenanceContent := `{"test": "provenance"}`
	if err := os.WriteFile(provenancePath, []byte(provenanceContent), 0644); err != nil {
		t.Fatalf("Failed to write provenance: %v", err)
	}

	// Verify directory was created
	if _, err := os.Stat(nestedDir); os.IsNotExist(err) {
		t.Error("Directory should have been created")
	}

	// Verify provenance file exists
	if _, err := os.Stat(provenancePath); os.IsNotExist(err) {
		t.Error("Provenance file should exist")
	}

	// Verify we can read it
	content, err := os.ReadFile(provenancePath)
	if err != nil {
		t.Fatalf("Failed to read provenance: %v", err)
	}

	if string(content) != provenanceContent {
		t.Errorf("Expected content %q, got %q", provenanceContent, string(content))
	}
}
