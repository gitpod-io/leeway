//go:build integration
// +build integration

package leeway

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
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
		name             string
		exportToCache    bool
		hasImages        bool
		expectFiles      []string
		skipReason       string
		expectError      bool
		expectErrorMatch string // Regex pattern to match expected error
	}{
		{
			name:             "legacy push behavior",
			exportToCache:    false,
			hasImages:        true,
			expectFiles:      []string{"imgnames.txt", "metadata.yaml"},
			expectError:      true,
			expectErrorMatch: "(?i)build failed", // Build fails at push step without credentials
		},
		{
			name:             "new export behavior",
			exportToCache:    true,
			hasImages:        true,
			expectFiles:      []string{"image.tar", "imgnames.txt", "docker-export-metadata.json"},
			expectError:      false,
			expectErrorMatch: "",
		},
		{
			name:             "export without image config",
			exportToCache:    true,
			hasImages:        false,
			expectFiles:      []string{"content"},
			expectError:      true,                     // OCI layout export requires an image tag
			expectErrorMatch: "(?i)(not found|failed)", // Build fails without image config in OCI mode
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Skip if test has a skip reason
			if tt.skipReason != "" {
				t.Skip(tt.skipReason)
			}

			// Create temporary workspace
			tmpDir := t.TempDir()

			// Create WORKSPACE.yaml
			workspaceYAML := `defaultTarget: "app:docker"`
			workspacePath := filepath.Join(tmpDir, "WORKSPACE.yaml")
			if err := os.WriteFile(workspacePath, []byte(workspaceYAML), 0644); err != nil {
				t.Fatal(err)
			}

			// Create component directory
			appDir := filepath.Join(tmpDir, "app")
			if err := os.MkdirAll(appDir, 0755); err != nil {
				t.Fatal(err)
			}

			// Create a simple Dockerfile
			dockerfile := `FROM alpine:latest
LABEL test="true"
CMD ["echo", "test"]`

			dockerfilePath := filepath.Join(appDir, "Dockerfile")
			if err := os.WriteFile(dockerfilePath, []byte(dockerfile), 0644); err != nil {
				t.Fatal(err)
			}

			// Create BUILD.yaml with proper formatting
			imageSection := ""
			if tt.hasImages {
				imageSection = `
    image:
      - test-leeway:latest`
			}

			buildYAML := fmt.Sprintf(`packages:
- name: docker
  type: docker
  config:
    dockerfile: Dockerfile
    exportToCache: %t%s`, tt.exportToCache, imageSection)

			buildPath := filepath.Join(appDir, "BUILD.yaml")
			if err := os.WriteFile(buildPath, []byte(buildYAML), 0644); err != nil {
				t.Fatal(err)
			}

			// Load workspace
			workspace, err := FindWorkspace(tmpDir, Arguments{}, "", "")
			if err != nil {
				t.Fatalf("Failed to load workspace: %v", err)
			}

			// Get package
			pkg, ok := workspace.Packages["app:docker"]
			if !ok {
				t.Fatalf("Package app:docker not found in workspace")
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

			// Handle expected errors (e.g., push failures without credentials)
			if tt.expectError {
				if err == nil {
					t.Fatal("Expected build to fail but it succeeded")
				}

				// Validate error matches expected pattern
				if tt.expectErrorMatch != "" {
					matched, regexErr := regexp.MatchString(tt.expectErrorMatch, err.Error())
					if regexErr != nil {
						t.Fatalf("Invalid error regex pattern: %v", regexErr)
					}
					if !matched {
						t.Fatalf("Error doesn't match expected pattern.\nExpected pattern: %s\nActual error: %v",
							tt.expectErrorMatch, err)
					}
					t.Logf("Build failed as expected with error matching pattern '%s': %v",
						tt.expectErrorMatch, err)
				} else {
					t.Logf("Build failed as expected: %v", err)
				}

				// For legacy push test, we expect it to fail at push step
				// The detailed Docker error (e.g., "push access denied", "authorization failed")
				// is logged but wrapped in a generic "build failed" error.
				// The test validates that the legacy push workflow executes and fails as expected
				// without Docker Hub credentials.
				// Skip further validation for this test case
				return
			}

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
					// Normalize paths for comparison (remove leading ./)
					normalizedActual := strings.TrimPrefix(actualFile, "./")
					normalizedExpected := strings.TrimPrefix(expectedFile, "./")

					if filepath.Base(normalizedActual) == normalizedExpected ||
						normalizedActual == normalizedExpected ||
						strings.HasPrefix(normalizedActual, normalizedExpected+"/") {
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

	// Create WORKSPACE.yaml
	workspaceYAML := `defaultTarget: "app:docker"`
	workspacePath := filepath.Join(tmpDir, "WORKSPACE.yaml")
	if err := os.WriteFile(workspacePath, []byte(workspaceYAML), 0644); err != nil {
		t.Fatal(err)
	}

	// Create component directory
	appDir := filepath.Join(tmpDir, "app")
	if err := os.MkdirAll(appDir, 0755); err != nil {
		t.Fatal(err)
	}

	// Create a simple Dockerfile with identifiable content
	dockerfile := `FROM alpine:latest
RUN echo "test-content-12345" > /test-file.txt
CMD ["cat", "/test-file.txt"]`

	dockerfilePath := filepath.Join(appDir, "Dockerfile")
	if err := os.WriteFile(dockerfilePath, []byte(dockerfile), 0644); err != nil {
		t.Fatal(err)
	}

	// Create BUILD.yaml with exportToCache enabled
	buildYAML := fmt.Sprintf(`packages:
- name: docker
  type: docker
  config:
    dockerfile: Dockerfile
    exportToCache: true
    image:
      - %s`, testImage)

	buildPath := filepath.Join(appDir, "BUILD.yaml")
	if err := os.WriteFile(buildPath, []byte(buildYAML), 0644); err != nil {
		t.Fatal(err)
	}

	// Step 1: Build with export mode
	t.Log("Step 1: Building Docker image with export mode")
	workspace, err := FindWorkspace(tmpDir, Arguments{}, "", "")
	if err != nil {
		t.Fatalf("Failed to load workspace: %v", err)
	}

	pkg, ok := workspace.Packages["app:docker"]
	if !ok {
		t.Fatal("Package app:docker not found in workspace")
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
	// Note: Digest is optional with OCI layout export (image not loaded into daemon)
	if metadata.Digest == "" {
		t.Log("Metadata digest is empty (expected with OCI layout export)")
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

	// Load the OCI layout image into Docker
	// OCI layout requires skopeo or crane, docker load doesn't support it
	// First extract the OCI layout from the tar file
	ociDir := filepath.Join(tmpDir, "oci-layout")
	if err := os.MkdirAll(ociDir, 0755); err != nil {
		t.Fatal(err)
	}

	extractOCICmd := exec.Command("tar", "-xf", imageTarPath, "-C", ociDir)
	if output, err := extractOCICmd.CombinedOutput(); err != nil {
		t.Fatalf("Failed to extract OCI layout: %v\nOutput: %s", err, string(output))
	}

	// Try skopeo first, fall back to crane, then fail with helpful message
	var loadCmd *exec.Cmd
	var toolUsed string

	if _, err := exec.LookPath("skopeo"); err == nil {
		// Use skopeo to load OCI layout directory
		loadCmd = exec.Command("skopeo", "copy",
			fmt.Sprintf("oci:%s", ociDir),
			fmt.Sprintf("docker-daemon:%s", testImage))
		toolUsed = "skopeo"
	} else if _, err := exec.LookPath("crane"); err == nil {
		// Use crane to load OCI layout directory
		loadCmd = exec.Command("crane", "push", ociDir, testImage)
		toolUsed = "crane"
	} else {
		t.Skip("Skipping test: OCI layout loading requires skopeo or crane.\n" +
			"Install with:\n" +
			"  apt-get install skopeo  # or\n" +
			"  go install github.com/google/go-containerregistry/cmd/crane@latest")
	}

	loadOutput, err := loadCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Failed to load OCI image using %s: %v\nOutput: %s", toolUsed, err, string(loadOutput))
	}
	t.Logf("Loaded OCI image using %s: %s", toolUsed, string(loadOutput))

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

func TestDockerPackage_OCILayout_Determinism_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Ensure Docker is available
	if err := exec.Command("docker", "version").Run(); err != nil {
		t.Skip("Docker not available, skipping integration test")
	}

	// Ensure buildx is available
	if err := exec.Command("docker", "buildx", "version").Run(); err != nil {
		t.Skip("Docker buildx not available, skipping integration test")
	}

	// Create test workspace
	tmpDir := t.TempDir()
	wsDir := filepath.Join(tmpDir, "workspace")
	if err := os.MkdirAll(wsDir, 0755); err != nil {
		t.Fatal(err)
	}

	// Create WORKSPACE.yaml
	workspaceYAML := `defaultTarget: ":test-image"`
	if err := os.WriteFile(filepath.Join(wsDir, "WORKSPACE.yaml"), []byte(workspaceYAML), 0644); err != nil {
		t.Fatal(err)
	}

	// Create Dockerfile with ARG SOURCE_DATE_EPOCH
	dockerfile := `FROM alpine:3.18
ARG SOURCE_DATE_EPOCH
RUN echo "Build time: $SOURCE_DATE_EPOCH" > /build-time.txt
CMD ["cat", "/build-time.txt"]
`
	if err := os.WriteFile(filepath.Join(wsDir, "Dockerfile"), []byte(dockerfile), 0644); err != nil {
		t.Fatal(err)
	}

	// Create BUILD.yaml
	buildYAML := `packages:
  - name: test-image
    type: docker
    config:
      dockerfile: Dockerfile
      image:
        - localhost/leeway-determinism-test:latest
      exportToCache: true
`
	if err := os.WriteFile(filepath.Join(wsDir, "BUILD.yaml"), []byte(buildYAML), 0644); err != nil {
		t.Fatal(err)
	}

	// Initialize git repo (required for deterministic mtime)
	gitInit := exec.Command("git", "init")
	gitInit.Dir = wsDir
	if err := gitInit.Run(); err != nil {
		t.Fatal(err)
	}

	gitConfigName := exec.Command("git", "config", "user.name", "Test User")
	gitConfigName.Dir = wsDir
	if err := gitConfigName.Run(); err != nil {
		t.Fatal(err)
	}

	gitConfigEmail := exec.Command("git", "config", "user.email", "test@example.com")
	gitConfigEmail.Dir = wsDir
	if err := gitConfigEmail.Run(); err != nil {
		t.Fatal(err)
	}

	gitAdd := exec.Command("git", "add", ".")
	gitAdd.Dir = wsDir
	if err := gitAdd.Run(); err != nil {
		t.Fatal(err)
	}

	// Use fixed timestamp for deterministic git commit
	// This ensures the commit timestamp is the same across test runs
	gitCommit := exec.Command("git", "commit", "-m", "initial")
	gitCommit.Dir = wsDir
	gitCommit.Env = append(os.Environ(),
		"GIT_AUTHOR_DATE=2021-01-01T00:00:00Z",
		"GIT_COMMITTER_DATE=2021-01-01T00:00:00Z",
	)
	if err := gitCommit.Run(); err != nil {
		t.Fatal(err)
	}

	// Build first time
	cacheDir1 := filepath.Join(tmpDir, "cache1")
	cache1, err := local.NewFilesystemCache(cacheDir1)
	if err != nil {
		t.Fatal(err)
	}

	buildCtx1, err := newBuildContext(buildOptions{
		LocalCache:          cache1,
		DockerExportToCache: true,
		DockerExportSet:     true,
		Reporter:            NewConsoleReporter(),
	})
	if err != nil {
		t.Fatalf("Failed to create build context: %v", err)
	}

	ws1, err := FindWorkspace(wsDir, Arguments{}, "", "")
	if err != nil {
		t.Fatalf("Failed to load workspace: %v", err)
	}

	pkg1, exists := ws1.Packages["//:test-image"]
	if !exists {
		t.Fatal("Package //:test-image not found")
	}

	if err := pkg1.build(buildCtx1); err != nil {
		t.Fatalf("First build failed: %v", err)
	}

	// Get checksum of first build
	cacheFiles1, err := filepath.Glob(filepath.Join(cacheDir1, "*.tar.gz"))
	if err != nil || len(cacheFiles1) == 0 {
		t.Fatal("No cache file found after first build")
	}
	checksum1, err := checksumFile(cacheFiles1[0])
	if err != nil {
		t.Fatalf("Failed to checksum first build: %v", err)
	}

	// Build second time (clean cache)
	cacheDir2 := filepath.Join(tmpDir, "cache2")
	cache2, err := local.NewFilesystemCache(cacheDir2)
	if err != nil {
		t.Fatal(err)
	}

	buildCtx2, err := newBuildContext(buildOptions{
		LocalCache:          cache2,
		DockerExportToCache: true,
		DockerExportSet:     true,
		Reporter:            NewConsoleReporter(),
	})
	if err != nil {
		t.Fatalf("Failed to create build context: %v", err)
	}

	ws2, err := FindWorkspace(wsDir, Arguments{}, "", "")
	if err != nil {
		t.Fatalf("Failed to load workspace: %v", err)
	}

	pkg2, exists := ws2.Packages["//:test-image"]
	if !exists {
		t.Fatal("Package //:test-image not found")
	}

	if err := pkg2.build(buildCtx2); err != nil {
		t.Fatalf("Second build failed: %v", err)
	}

	// Get checksum of second build
	cacheFiles2, err := filepath.Glob(filepath.Join(cacheDir2, "*.tar.gz"))
	if err != nil || len(cacheFiles2) == 0 {
		t.Fatal("No cache file found after second build")
	}
	checksum2, err := checksumFile(cacheFiles2[0])
	if err != nil {
		t.Fatalf("Failed to checksum second build: %v", err)
	}

	// Compare checksums
	if checksum1 != checksum2 {
		t.Errorf("Builds are not deterministic!\nBuild 1: %s\nBuild 2: %s", checksum1, checksum2)
		t.Log("This indicates the OCI layout export is not fully deterministic")
	} else {
		t.Logf("✅ Deterministic builds verified: %s", checksum1)
	}
}

// checksumFile computes SHA256 checksum of a file
func checksumFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", h.Sum(nil)), nil
}
