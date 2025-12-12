package leeway

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestAccessSBOMInCachedArchive_SeparateFile(t *testing.T) {
	// Create a temp directory
	tmpDir := t.TempDir()

	// Create a dummy artifact file (empty tar.gz)
	artifactPath := filepath.Join(tmpDir, "artifact.tar.gz")
	if err := createEmptyTarGz(artifactPath); err != nil {
		t.Fatalf("failed to create artifact: %v", err)
	}

	// Create a separate SBOM file alongside the artifact
	sbomContent := `{"bomFormat":"CycloneDX","specVersion":"1.4"}`
	sbomPath := artifactPath + ".sbom.cdx.json"
	if err := os.WriteFile(sbomPath, []byte(sbomContent), 0644); err != nil {
		t.Fatalf("failed to create SBOM file: %v", err)
	}

	// Test that AccessSBOMInCachedArchive reads from the separate file
	var readContent bytes.Buffer
	err := AccessSBOMInCachedArchive(artifactPath, "cyclonedx", func(r io.Reader) error {
		_, err := io.Copy(&readContent, r)
		return err
	})
	if err != nil {
		t.Fatalf("AccessSBOMInCachedArchive failed: %v", err)
	}

	if readContent.String() != sbomContent {
		t.Errorf("expected %q, got %q", sbomContent, readContent.String())
	}
}

func TestAccessSBOMInCachedArchive_LegacyTarGz(t *testing.T) {
	// Create a temp directory
	tmpDir := t.TempDir()

	// Create a tar.gz with SBOM inside (legacy format)
	artifactPath := filepath.Join(tmpDir, "artifact.tar.gz")
	sbomContent := `{"bomFormat":"CycloneDX","specVersion":"1.4"}`
	if err := createTarGzWithSBOM(artifactPath, "sbom.cdx.json", sbomContent); err != nil {
		t.Fatalf("failed to create artifact with SBOM: %v", err)
	}

	// Test that AccessSBOMInCachedArchive falls back to extracting from tar
	var readContent bytes.Buffer
	err := AccessSBOMInCachedArchive(artifactPath, "cyclonedx", func(r io.Reader) error {
		_, err := io.Copy(&readContent, r)
		return err
	})
	if err != nil {
		t.Fatalf("AccessSBOMInCachedArchive failed: %v", err)
	}

	if readContent.String() != sbomContent {
		t.Errorf("expected %q, got %q", sbomContent, readContent.String())
	}
}

func TestAccessSBOMInCachedArchive_SeparateFileTakesPrecedence(t *testing.T) {
	// Create a temp directory
	tmpDir := t.TempDir()

	// Create a tar.gz with old SBOM inside
	artifactPath := filepath.Join(tmpDir, "artifact.tar.gz")
	oldContent := `{"bomFormat":"CycloneDX","specVersion":"1.3","old":true}`
	if err := createTarGzWithSBOM(artifactPath, "sbom.cdx.json", oldContent); err != nil {
		t.Fatalf("failed to create artifact with SBOM: %v", err)
	}

	// Create a separate SBOM file with newer content
	newContent := `{"bomFormat":"CycloneDX","specVersion":"1.4","new":true}`
	sbomPath := artifactPath + ".sbom.cdx.json"
	if err := os.WriteFile(sbomPath, []byte(newContent), 0644); err != nil {
		t.Fatalf("failed to create SBOM file: %v", err)
	}

	// Test that separate file takes precedence
	var readContent bytes.Buffer
	err := AccessSBOMInCachedArchive(artifactPath, "cyclonedx", func(r io.Reader) error {
		_, err := io.Copy(&readContent, r)
		return err
	})
	if err != nil {
		t.Fatalf("AccessSBOMInCachedArchive failed: %v", err)
	}

	if readContent.String() != newContent {
		t.Errorf("expected separate file content %q, got %q", newContent, readContent.String())
	}
}

func TestAccessSBOMInCachedArchive_NoSBOM(t *testing.T) {
	// Create a temp directory
	tmpDir := t.TempDir()

	// Create an empty tar.gz without SBOM
	artifactPath := filepath.Join(tmpDir, "artifact.tar.gz")
	if err := createEmptyTarGz(artifactPath); err != nil {
		t.Fatalf("failed to create artifact: %v", err)
	}

	// Test that ErrNoSBOMFile is returned
	err := AccessSBOMInCachedArchive(artifactPath, "cyclonedx", func(r io.Reader) error {
		return nil
	})
	if err != ErrNoSBOMFile {
		t.Errorf("expected ErrNoSBOMFile, got %v", err)
	}
}

func TestAccessSBOMInCachedArchive_AllFormats(t *testing.T) {
	formats := []struct {
		name string
		ext  string
	}{
		{"cyclonedx", ".sbom.cdx.json"},
		{"spdx", ".sbom.spdx.json"},
		{"syft", ".sbom.json"},
	}

	for _, format := range formats {
		t.Run(format.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			artifactPath := filepath.Join(tmpDir, "artifact.tar.gz")
			if err := createEmptyTarGz(artifactPath); err != nil {
				t.Fatalf("failed to create artifact: %v", err)
			}

			sbomContent := `{"format":"` + format.name + `"}`
			sbomPath := artifactPath + format.ext
			if err := os.WriteFile(sbomPath, []byte(sbomContent), 0644); err != nil {
				t.Fatalf("failed to create SBOM file: %v", err)
			}

			var readContent bytes.Buffer
			err := AccessSBOMInCachedArchive(artifactPath, format.name, func(r io.Reader) error {
				_, err := io.Copy(&readContent, r)
				return err
			})
			if err != nil {
				t.Fatalf("AccessSBOMInCachedArchive failed for %s: %v", format.name, err)
			}

			if readContent.String() != sbomContent {
				t.Errorf("expected %q, got %q", sbomContent, readContent.String())
			}
		})
	}
}

// Helper functions

func createEmptyTarGz(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	gw := gzip.NewWriter(f)
	defer gw.Close()

	tw := tar.NewWriter(gw)
	defer tw.Close()

	return nil
}

func createTarGzWithSBOM(path, sbomName, sbomContent string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	gw := gzip.NewWriter(f)
	defer gw.Close()

	tw := tar.NewWriter(gw)
	defer tw.Close()

	// Add SBOM file to tar
	hdr := &tar.Header{
		Name: sbomName,
		Mode: 0644,
		Size: int64(len(sbomContent)),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	if _, err := tw.Write([]byte(sbomContent)); err != nil {
		return err
	}

	return nil
}
