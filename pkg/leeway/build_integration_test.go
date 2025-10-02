//go:build integration
// +build integration

package leeway

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gitpod-io/leeway/pkg/leeway/cache/local"
)

// extractDockerMetadataFromCache extracts Docker image metadata from a cached package
// This is a test helper function only used in integration tests
func extractDockerMetadataFromCache(cacheBundleFN string) (*DockerImageMetadata, error) {
	f, err := os.Open(cacheBundleFN)
	if err != nil {
		return nil, fmt.Errorf("failed to open cache bundle: %w", err)
	}
	defer f.Close()

	gzin, err := gzip.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gzin.Close()

	tarin := tar.NewReader(gzin)
	for {
		hdr, err := tarin.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to read tar: %w", err)
		}

		if hdr.Typeflag != tar.TypeReg {
			continue
		}

		if filepath.Base(hdr.Name) != "docker-export-metadata.json" {
			continue
		}

		metadataBytes := make([]byte, hdr.Size)
		if _, err := io.ReadFull(tarin, metadataBytes); err != nil {
			return nil, fmt.Errorf("failed to read metadata: %w", err)
		}

		var metadata DockerImageMetadata
		if err := json.Unmarshal(metadataBytes, &metadata); err != nil {
			return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
		}

		return &metadata, nil
	}

	return nil, fmt.Errorf("docker-export-metadata.json not found in cache bundle")
}

func TestDockerPackage_ExportToCache_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Ensure Docker is available
	if err := exec.Command("docker", "version").Run(); err != nil {
		t.Skip("Docker not available, skipping integration test")
	}

	tests := []struct {
		name          string
		exportToCache bool
		hasImages     bool
		expectFiles   []string
	}{
		{
			name:          "legacy push behavior",
			exportToCache: false,
			hasImages:     true,
			expectFiles:   []string{"imgnames.txt", "metadata.yaml"},
		},
		{
			name:          "new export behavior",
			exportToCache: true,
			hasImages:     true,
			expectFiles:   []string{"image.tar", "imgnames.txt", "docker-export-metadata.json"},
		},
		{
			name:          "export without image config",
			exportToCache: true,
			hasImages:     false,
			expectFiles:   []string{"content/"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary workspace
			tmpDir := t.TempDir()

			// Create a simple Dockerfile
			dockerfile := `FROM alpine:latest
LABEL test="true"
CMD ["echo", "test"]`

			dockerfilePath := filepath.Join(tmpDir, "Dockerfile")
			if err := os.WriteFile(dockerfilePath, []byte(dockerfile), 0644); err != nil {
				t.Fatal(err)
			}

			// Create WORKSPACE.yaml with proper formatting
			imageSection := ""
			if tt.hasImages {
				imageSection = `
          image:
            - test-leeway:latest`
			}

			workspaceYAML := fmt.Sprintf(`defaultTarget: ":app"
components:
  - name: "."
    packages:
      - name: app
        type: docker
        config:
          dockerfile: Dockerfile
          exportToCache: %t%s`, tt.exportToCache, imageSection)

			workspacePath := filepath.Join(tmpDir, "WORKSPACE.yaml")
			if err := os.WriteFile(workspacePath, []byte(workspaceYAML), 0644); err != nil {
				t.Fatal(err)
			}

			// Load workspace
			workspace, err := FindWorkspace(tmpDir, Arguments{}, "", "")
			if err != nil {
				t.Fatalf("Failed to load workspace: %v", err)
			}

			// Get package
			pkg, ok := workspace.Packages[":app"]
			if !ok {
				t.Fatalf("Package :app not found in workspace")
			}

			// Create local cache
			cacheDir := filepath.Join(tmpDir, ".cache")
			if err := os.MkdirAll(cacheDir, 0755); err != nil {
				t.Fatal(err)
			}

			localCache, err := local.NewFilesystemCache(cacheDir)
			if err != nil {
				t.Fatalf("Failed to create local cache: %v", err)
			}

			// Build package using the Build function
			err = Build(pkg,
				WithLocalCache(localCache),
				WithDontTest(true),
			)
			if err != nil {
				t.Fatalf("Build failed: %v", err)
			}

			// Verify cache artifact exists
			cachePath, exists := localCache.Location(pkg)
			if !exists {
				t.Fatal("Package not found in cache after build")
			}

			t.Logf("Cache artifact created at: %s", cachePath)

			// Verify artifact contents
			foundFiles, err := listTarGzContents(cachePath)
			if err != nil {
				t.Fatalf("Failed to list tar contents: %v", err)
			}

			t.Logf("Files in cache artifact: %v", foundFiles)

			// Check expected files are present
			for _, expectedFile := range tt.expectFiles {
				found := false
				for _, actualFile := range foundFiles {
					if filepath.Base(actualFile) == expectedFile || actualFile == expectedFile {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected file %s not found in cache artifact", expectedFile)
				}
			}

			// Verify artifact contents based on export mode
			if tt.exportToCache && tt.hasImages {
				// Should contain image.tar and metadata
				metadata, err := extractDockerMetadataFromCache(cachePath)
				if err != nil {
					t.Errorf("Failed to extract metadata: %v", err)
				} else {
					if len(metadata.ImageNames) == 0 {
						t.Error("Expected image names in metadata")
					}
					if metadata.ImageNames[0] != "test-leeway:latest" {
						t.Errorf("Unexpected image name: %s", metadata.ImageNames[0])
					}
					t.Logf("Metadata: %+v", metadata)
				}
			}

			// Cleanup
			if tt.hasImages && !tt.exportToCache {
				exec.Command("docker", "rmi", "test-leeway:latest").Run()
			}
		})
	}
}

// listTarGzContents lists all files in a tar.gz archive
func listTarGzContents(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	gzr, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)
	var files []string

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		files = append(files, hdr.Name)
	}

	return files, nil
}

func TestDockerPackage_CacheRoundTrip_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Ensure Docker is available
	if err := exec.Command("docker", "version").Run(); err != nil {
		t.Skip("Docker not available, skipping integration test")
	}

	// This test verifies that a Docker image can be:
	// 1. Built and exported to cache
	// 2. Extracted from cache
	// 3. Loaded back into Docker
	// 4. Still works correctly

	tmpDir := t.TempDir()
	testImage := "test-leeway-roundtrip:latest"

	// Create a simple Dockerfile with identifiable content
	dockerfile := `FROM alpine:latest
RUN echo "test-content-12345" > /test-file.txt
CMD ["cat", "/test-file.txt"]`

	dockerfilePath := filepath.Join(tmpDir, "Dockerfile")
	if err := os.WriteFile(dockerfilePath, []byte(dockerfile), 0644); err != nil {
		t.Fatal(err)
	}

	// Create WORKSPACE.yaml with exportToCache enabled
	workspaceYAML := fmt.Sprintf(`defaultTarget: ":app"
components:
  - name: "."
    packages:
      - name: app
        type: docker
        config:
          dockerfile: Dockerfile
          exportToCache: true
          image:
            - %s`, testImage)

	workspacePath := filepath.Join(tmpDir, "WORKSPACE.yaml")
	if err := os.WriteFile(workspacePath, []byte(workspaceYAML), 0644); err != nil {
		t.Fatal(err)
	}

	// Step 1: Build with export mode
	t.Log("Step 1: Building Docker image with export mode")
	workspace, err := FindWorkspace(tmpDir, Arguments{}, "", "")
	if err != nil {
		t.Fatalf("Failed to load workspace: %v", err)
	}

	pkg, ok := workspace.Packages[":app"]
	if !ok {
		t.Fatal("Package :app not found in workspace")
	}

	cacheDir := filepath.Join(tmpDir, ".cache")
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		t.Fatal(err)
	}

	localCache, err := local.NewFilesystemCache(cacheDir)
	if err != nil {
		t.Fatalf("Failed to create local cache: %v", err)
	}

	err = Build(pkg,
		WithLocalCache(localCache),
		WithDontTest(true),
	)
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	// Step 2: Verify cache artifact exists and contains image.tar
	t.Log("Step 2: Verifying cache artifact")
	cachePath, exists := localCache.Location(pkg)
	if !exists {
		t.Fatal("Package not found in cache after build")
	}

	files, err := listTarGzContents(cachePath)
	if err != nil {
		t.Fatalf("Failed to list cache contents: %v", err)
	}

	hasImageTar := false
	hasMetadata := false
	for _, file := range files {
		if filepath.Base(file) == "image.tar" {
			hasImageTar = true
		}
		if filepath.Base(file) == "docker-export-metadata.json" {
			hasMetadata = true
		}
	}

	if !hasImageTar {
		t.Error("Cache artifact missing image.tar")
	}
	if !hasMetadata {
		t.Error("Cache artifact missing docker-export-metadata.json")
	}

	// Step 3: Extract metadata and verify
	t.Log("Step 3: Extracting and verifying metadata")
	metadata, err := extractDockerMetadataFromCache(cachePath)
	if err != nil {
		t.Fatalf("Failed to extract metadata: %v", err)
	}

	if len(metadata.ImageNames) == 0 {
		t.Error("Metadata has no image names")
	}
	if metadata.ImageNames[0] != testImage {
		t.Errorf("Metadata image name = %s, want %s", metadata.ImageNames[0], testImage)
	}
	if metadata.Digest == "" {
		t.Error("Metadata missing digest")
	}

	t.Logf("Metadata: ImageNames=%v, Digest=%s, BuildTime=%v",
		metadata.ImageNames, metadata.Digest, metadata.BuildTime)

	// Step 4: Extract image.tar from cache and load into Docker
	t.Log("Step 4: Extracting image.tar and loading into Docker")
	
	// First, remove the image if it exists
	exec.Command("docker", "rmi", "-f", testImage).Run()

	// Extract image.tar from the cache bundle
	extractDir := filepath.Join(tmpDir, "extracted")
	if err := os.MkdirAll(extractDir, 0755); err != nil {
		t.Fatal(err)
	}

	// Extract the tar.gz
	extractCmd := exec.Command("tar", "-xzf", cachePath, "-C", extractDir)
	if output, err := extractCmd.CombinedOutput(); err != nil {
		t.Fatalf("Failed to extract cache: %v\nOutput: %s", err, string(output))
	}

	imageTarPath := filepath.Join(extractDir, "image.tar")
	if _, err := os.Stat(imageTarPath); err != nil {
		t.Fatalf("image.tar not found after extraction: %v", err)
	}

	// Load the image back into Docker
	loadCmd := exec.Command("docker", "load", "-i", imageTarPath)
	if output, err := loadCmd.CombinedOutput(); err != nil {
		t.Fatalf("Failed to load image: %v\nOutput: %s", err, string(output))
	}

	// Step 5: Verify the loaded image works
	t.Log("Step 5: Verifying loaded image works")
	
	// Get the digest of the loaded image
	inspectCmd := exec.Command("docker", "inspect", "--format={{index .Id}}", testImage)
	inspectOutput, err := inspectCmd.Output()
	if err != nil {
		t.Fatalf("Failed to inspect loaded image: %v", err)
	}
	loadedDigest := strings.TrimSpace(string(inspectOutput))
	
	t.Logf("Loaded image digest: %s", loadedDigest)
	t.Logf("Original metadata digest: %s", metadata.Digest)

	// Run the container to verify it works
	runCmd := exec.Command("docker", "run", "--rm", testImage)
	runOutput, err := runCmd.Output()
	if err != nil {
		t.Fatalf("Failed to run container: %v", err)
	}

	expectedOutput := "test-content-12345\n"
	if string(runOutput) != expectedOutput {
		t.Errorf("Container output = %q, want %q", string(runOutput), expectedOutput)
	}

	// Cleanup
	exec.Command("docker", "rmi", "-f", testImage).Run()

	t.Log("✅ Round-trip test passed: image exported, cached, extracted, loaded, and executed successfully")
}
