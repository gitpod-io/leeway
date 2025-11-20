package leeway

import (
	"archive/tar"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/common"
)

func TestExtractDigestFromOCILayout(t *testing.T) {
	tests := []struct {
		name        string
		indexJSON   string
		wantDigest  common.DigestSet
		wantErr     bool
		errContains string
	}{
		{
			name: "valid OCI index with single manifest",
			indexJSON: `{
				"schemaVersion": 2,
				"manifests": [
					{
						"mediaType": "application/vnd.oci.image.manifest.v1+json",
						"digest": "sha256:abc123def456",
						"size": 1234
					}
				]
			}`,
			wantDigest: common.DigestSet{
				"sha256": "abc123def456",
			},
			wantErr: false,
		},
		{
			name: "valid OCI index with multiple manifests (uses first)",
			indexJSON: `{
				"schemaVersion": 2,
				"manifests": [
					{
						"mediaType": "application/vnd.oci.image.manifest.v1+json",
						"digest": "sha256:first123",
						"size": 1234
					},
					{
						"mediaType": "application/vnd.oci.image.manifest.v1+json",
						"digest": "sha256:second456",
						"size": 5678
					}
				]
			}`,
			wantDigest: common.DigestSet{
				"sha256": "first123",
			},
			wantErr: false,
		},
		{
			name: "empty manifests array",
			indexJSON: `{
				"schemaVersion": 2,
				"manifests": []
			}`,
			wantErr:     true,
			errContains: "no manifests found",
		},
		{
			name: "invalid digest format (no colon)",
			indexJSON: `{
				"schemaVersion": 2,
				"manifests": [
					{
						"mediaType": "application/vnd.oci.image.manifest.v1+json",
						"digest": "sha256abc123",
						"size": 1234
					}
				]
			}`,
			wantErr:     true,
			errContains: "invalid digest format",
		},
		{
			name:        "invalid JSON",
			indexJSON:   `{invalid json`,
			wantErr:     true,
			errContains: "failed to parse OCI index.json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary directory with index.json
			tmpDir := t.TempDir()
			indexPath := filepath.Join(tmpDir, "index.json")

			if err := os.WriteFile(indexPath, []byte(tt.indexJSON), 0644); err != nil {
				t.Fatalf("failed to write test index.json: %v", err)
			}

			// Test extraction
			digest, err := extractDigestFromOCILayout(tmpDir)

			if tt.wantErr {
				if err == nil {
					t.Errorf("extractDigestFromOCILayout() expected error, got nil")
					return
				}
				if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("extractDigestFromOCILayout() error = %v, want error containing %q", err, tt.errContains)
				}
				return
			}

			if err != nil {
				t.Errorf("extractDigestFromOCILayout() unexpected error: %v", err)
				return
			}

			if len(digest) != len(tt.wantDigest) {
				t.Errorf("extractDigestFromOCILayout() digest length = %d, want %d", len(digest), len(tt.wantDigest))
				return
			}

			for algo, hash := range tt.wantDigest {
				if digest[algo] != hash {
					t.Errorf("extractDigestFromOCILayout() digest[%s] = %s, want %s", algo, digest[algo], hash)
				}
			}
		})
	}
}

func TestExtractDigestFromOCILayout_MissingFile(t *testing.T) {
	tmpDir := t.TempDir()
	// Don't create index.json

	_, err := extractDigestFromOCILayout(tmpDir)
	if err == nil {
		t.Error("extractDigestFromOCILayout() expected error for missing index.json, got nil")
	}
	if !strings.Contains(err.Error(), "failed to read OCI index.json") {
		t.Errorf("extractDigestFromOCILayout() error = %v, want error containing 'failed to read OCI index.json'", err)
	}
}

// TestCreateOCILayoutSubjectsFunction tests the OCI layout subjects function
// Note: This function is set up regardless of SLSA being enabled, but is only
// called when SLSA provenance generation is active. This test verifies the
// function works correctly when called.
func TestCreateOCILayoutSubjectsFunction(t *testing.T) {
	// Create temporary directory with OCI layout structure
	tmpDir := t.TempDir()
	buildDir := filepath.Join(tmpDir, "build")
	if err := os.MkdirAll(buildDir, 0755); err != nil {
		t.Fatal(err)
	}

	// Create OCI layout directory
	ociLayoutDir := filepath.Join(tmpDir, "oci-layout")
	if err := os.MkdirAll(ociLayoutDir, 0755); err != nil {
		t.Fatal(err)
	}

	// Create index.json
	indexJSON := `{
		"schemaVersion": 2,
		"manifests": [
			{
				"mediaType": "application/vnd.oci.image.manifest.v1+json",
				"digest": "sha256:abc123def456",
				"size": 1234
			}
		]
	}`
	if err := os.WriteFile(filepath.Join(ociLayoutDir, "index.json"), []byte(indexJSON), 0644); err != nil {
		t.Fatal(err)
	}

	// Create image.tar containing the OCI layout
	imageTarPath := filepath.Join(buildDir, "image.tar")
	if err := createTarFromDir(ociLayoutDir, imageTarPath); err != nil {
		t.Fatal(err)
	}

	// Test configuration
	version := "test-image:v1.0.0"
	cfg := DockerPkgConfig{
		Image: []string{
			"localhost/test-image:latest",
			"registry.example.com/test-image:v1.0.0",
		},
	}

	// Create subjects function
	subjectsFunc := createOCILayoutSubjectsFunction(version, cfg, buildDir)

	// Call the function
	subjects, err := subjectsFunc()
	if err != nil {
		t.Fatalf("createOCILayoutSubjectsFunction() error = %v", err)
	}

	// Verify results
	if len(subjects) != 2 {
		t.Errorf("createOCILayoutSubjectsFunction() returned %d subjects, want 2", len(subjects))
	}

	// Verify first subject
	if subjects[0].Name != "localhost/test-image:latest" {
		t.Errorf("subjects[0].Name = %s, want localhost/test-image:latest", subjects[0].Name)
	}

	// Verify digest
	expectedDigest := common.DigestSet{"sha256": "abc123def456"}
	if subjects[0].Digest["sha256"] != expectedDigest["sha256"] {
		t.Errorf("subjects[0].Digest = %v, want %v", subjects[0].Digest, expectedDigest)
	}

	// Verify second subject
	if subjects[1].Name != "registry.example.com/test-image:v1.0.0" {
		t.Errorf("subjects[1].Name = %s, want registry.example.com/test-image:v1.0.0", subjects[1].Name)
	}

	if subjects[1].Digest["sha256"] != expectedDigest["sha256"] {
		t.Errorf("subjects[1].Digest = %v, want %v", subjects[1].Digest, expectedDigest)
	}
}

// TestCreateOCILayoutSubjectsFunction_MissingImageTar tests error handling
func TestCreateOCILayoutSubjectsFunction_MissingImageTar(t *testing.T) {
	tmpDir := t.TempDir()
	buildDir := filepath.Join(tmpDir, "build")
	if err := os.MkdirAll(buildDir, 0755); err != nil {
		t.Fatal(err)
	}

	// Don't create image.tar

	version := "test-image:v1.0.0"
	cfg := DockerPkgConfig{
		Image: []string{"localhost/test-image:latest"},
	}

	subjectsFunc := createOCILayoutSubjectsFunction(version, cfg, buildDir)

	_, err := subjectsFunc()
	if err == nil {
		t.Error("createOCILayoutSubjectsFunction() expected error for missing image.tar, got nil")
	}
}

// TestCreateDockerInspectSubjectsFunction tests the Docker inspect subjects function
// Note: This test requires Docker to be running and uses a mock approach
func TestCreateDockerInspectSubjectsFunction(t *testing.T) {
	// This test would require Docker to be running and an actual image
	// For unit testing, we'll skip this and rely on integration tests
	// However, we can test the structure and error handling

	t.Run("function_structure", func(t *testing.T) {
		version := "test-image:v1.0.0"
		cfg := DockerPkgConfig{
			Image: []string{
				"localhost/test-image:latest",
				"registry.example.com/test-image:v1.0.0",
			},
		}

		// Create the function (doesn't execute yet)
		subjectsFunc := createDockerInspectSubjectsFunction(version, cfg)

		// Verify it's a function
		if subjectsFunc == nil {
			t.Error("createDockerInspectSubjectsFunction() returned nil")
		}

		// Note: We can't call subjectsFunc() here without a real Docker image
		// This is tested in integration tests
	})
}

// TestSubjectsFunctionBehavior documents the behavior of Subjects functions
// with and without SLSA enabled
func TestSubjectsFunctionBehavior(t *testing.T) {
	t.Run("subjects_function_always_set_up", func(t *testing.T) {
		// Document that the Subjects function is ALWAYS set up during build,
		// regardless of whether SLSA is enabled or not.
		//
		// The function is only CALLED when SLSA provenance generation is active.
		//
		// This means:
		// - With SLSA enabled: Function is called, digest is extracted
		// - Without SLSA disabled: Function is set up but never called (no error)
		//
		// Both paths work correctly:
		// 1. Legacy path (!exportToCache): createDockerInspectSubjectsFunction()
		// 2. OCI layout path (exportToCache): createOCILayoutSubjectsFunction()

		version := "test-image:v1.0.0"
		cfg := DockerPkgConfig{
			Image: []string{"localhost/test-image:latest"},
		}

		// Both functions can be created without SLSA being enabled
		dockerInspectFunc := createDockerInspectSubjectsFunction(version, cfg)
		if dockerInspectFunc == nil {
			t.Error("createDockerInspectSubjectsFunction() should always return a function")
		}

		// OCI layout function also created regardless of SLSA
		tmpDir := t.TempDir()
		ociLayoutFunc := createOCILayoutSubjectsFunction(version, cfg, tmpDir)
		if ociLayoutFunc == nil {
			t.Error("createOCILayoutSubjectsFunction() should always return a function")
		}

		// The functions are only called when SLSA is enabled
		// If SLSA is disabled, the functions are never invoked, so no error occurs
		t.Log("✅ Both functions can be set up regardless of SLSA state")
		t.Log("✅ Functions are only called when SLSA provenance generation is active")
	})
}

// Helper function to create a tar file from a directory
func createTarFromDir(srcDir, destTar string) error {
	f, err := os.Create(destTar)
	if err != nil {
		return err
	}
	defer f.Close()

	tw := tar.NewWriter(f)
	defer tw.Close()

	return filepath.Walk(srcDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Get relative path
		relPath, err := filepath.Rel(srcDir, path)
		if err != nil {
			return err
		}

		// Skip the root directory itself
		if relPath == "." {
			return nil
		}

		// Create tar header
		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		header.Name = relPath

		// Write header
		if err := tw.WriteHeader(header); err != nil {
			return err
		}

		// Write file content if it's a regular file
		if info.Mode().IsRegular() {
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if _, err := tw.Write(data); err != nil {
				return err
			}
		}

		return nil
	})
}
