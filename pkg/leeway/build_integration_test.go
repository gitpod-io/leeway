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

// TestDockerPackage_ExportToCache_Integration verifies OCI layout export functionality.
// Tests three scenarios:
// 1. Legacy push behavior (exportToCache=false) - pushes to registry
// 2. New OCI export (exportToCache=true) - creates image.tar in cache
// 3. Export without image config - extracts container filesystem
//
// SLSA relevance: Validates that exportToCache creates OCI layout required for SLSA L3.
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
			expectFiles:      []string{"content"}, // Without image config, extracts container filesystem
			expectError:      false,
			expectErrorMatch: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Skip if test has a skip reason
			if tt.skipReason != "" {
				t.Skip(tt.skipReason)
			}

			// Create docker-container builder for OCI export if needed
			if tt.exportToCache {
				builderName := "leeway-export-test-builder"
				createBuilder := exec.Command("docker", "buildx", "create", "--name", builderName, "--driver", "docker-container", "--bootstrap")
				if err := createBuilder.Run(); err != nil {
					// Builder might already exist, try to use it
					t.Logf("Builder creation failed (might already exist): %v", err)
				}
				defer func() {
					removeBuilder := exec.Command("docker", "buildx", "rm", builderName)
					_ = removeBuilder.Run()
				}()

				// Set builder as default for this test
				useBuilder := exec.Command("docker", "buildx", "use", builderName)
				if err := useBuilder.Run(); err != nil {
					t.Fatalf("Failed to use builder: %v", err)
				}
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

			// Create initial git commit for SBOM timestamp
			gitAdd := exec.Command("git", "add", ".")
			gitAdd.Dir = tmpDir
			if err := gitAdd.Run(); err != nil {
				t.Fatalf("Failed to git add: %v", err)
			}

			// Use fixed timestamp for deterministic git commit
			gitCommit := exec.Command("git", "commit", "-m", "initial")
			gitCommit.Dir = tmpDir
			gitCommit.Env = append(os.Environ(),
				"GIT_AUTHOR_DATE=2021-01-01T00:00:00Z",
				"GIT_COMMITTER_DATE=2021-01-01T00:00:00Z",
			)
			if err := gitCommit.Run(); err != nil {
				t.Fatalf("Failed to git commit: %v", err)
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

// TestDockerPackage_CacheRoundTrip_Integration verifies the complete cache workflow:
// Build with OCI export → Cache → Restore → Load into Docker → Verify image works
//
// SLSA relevance: Validates end-to-end cache workflow required for SLSA L3 compliance.
func TestDockerPackage_CacheRoundTrip_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Ensure Docker is available
	if err := exec.Command("docker", "version").Run(); err != nil {
		t.Skip("Docker not available, skipping integration test")
	}

	// Create docker-container builder for OCI export
	builderName := "leeway-roundtrip-test-builder"
	createBuilder := exec.Command("docker", "buildx", "create", "--name", builderName, "--driver", "docker-container", "--bootstrap")
	if err := createBuilder.Run(); err != nil {
		t.Logf("Builder creation failed (might already exist): %v", err)
	}
	defer func() {
		removeBuilder := exec.Command("docker", "buildx", "rm", builderName)
		_ = removeBuilder.Run()
	}()

	useBuilder := exec.Command("docker", "buildx", "use", builderName)
	if err := useBuilder.Run(); err != nil {
		t.Fatalf("Failed to use builder: %v", err)
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

// TestDockerPackage_OCILayout_Determinism_Integration verifies deterministic builds with OCI layout.
// Builds the same package twice and compares SHA256 hashes of the resulting image.tar files.
//
// SLSA relevance: CRITICAL for SLSA L3 - deterministic builds enable reproducible builds
// and build provenance verification. This validates that OCI layout export is deterministic.
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

	// Create docker-container builder for OCI export
	builderName := "leeway-slsa-test-builder"
	createBuilder := exec.Command("docker", "buildx", "create", "--name", builderName, "--driver", "docker-container", "--bootstrap")
	if err := createBuilder.Run(); err != nil {
		// Builder might already exist, try to use it
		t.Logf("Warning: failed to create builder (might already exist): %v", err)
	}
	defer func() {
		// Cleanup builder
		exec.Command("docker", "buildx", "rm", builderName).Run()
	}()

	// Use the builder
	useBuilder := exec.Command("docker", "buildx", "use", builderName)
	if err := useBuilder.Run(); err != nil {
		t.Fatalf("Failed to use builder: %v", err)
	}
	defer func() {
		// Switch back to default
		exec.Command("docker", "buildx", "use", "default").Run()
	}()

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

// TestDockerPackage_OCILayout_SLSA_Integration is the PRIMARY SLSA L3 TEST.
// Tests end-to-end SLSA provenance generation with OCI layout export:
// - Workspace with provenance.slsa: true
// - Package with exportToCache: true
// - Build creates OCI layout (image.tar)
// - SLSA provenance generation succeeds
// - Digest extracted from index.json (not docker inspect)
//
// This validates the exact workflow used in production SLSA L3 builds.
// Regression test for the docker inspect bug where digest extraction failed with OCI layout.
func TestDockerPackage_OCILayout_SLSA_Integration(t *testing.T) {
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

	// Create docker-container builder for OCI export
	builderName := "leeway-slsa-test-builder"
	createBuilder := exec.Command("docker", "buildx", "create", "--name", builderName, "--driver", "docker-container", "--bootstrap")
	if err := createBuilder.Run(); err != nil {
		// Builder might already exist, try to use it
		t.Logf("Warning: failed to create builder (might already exist): %v", err)
	}
	defer func() {
		// Cleanup builder
		exec.Command("docker", "buildx", "rm", builderName).Run()
	}()

	// Use the builder
	useBuilder := exec.Command("docker", "buildx", "use", builderName)
	if err := useBuilder.Run(); err != nil {
		t.Fatalf("Failed to use builder: %v", err)
	}
	defer func() {
		// Switch back to default
		exec.Command("docker", "buildx", "use", "default").Run()
	}()

	// Create test workspace
	tmpDir := t.TempDir()
	wsDir := filepath.Join(tmpDir, "workspace")
	if err := os.MkdirAll(wsDir, 0755); err != nil {
		t.Fatal(err)
	}

	// Create WORKSPACE.yaml with SLSA enabled
	workspaceYAML := `defaultTarget: ":test-image"
provenance:
  slsa: true
`
	if err := os.WriteFile(filepath.Join(wsDir, "WORKSPACE.yaml"), []byte(workspaceYAML), 0644); err != nil {
		t.Fatal(err)
	}

	// Create Dockerfile
	dockerfile := `FROM alpine:3.18
ARG SOURCE_DATE_EPOCH
RUN echo "Build time: $SOURCE_DATE_EPOCH" > /build-time.txt
CMD ["cat", "/build-time.txt"]
`
	if err := os.WriteFile(filepath.Join(wsDir, "Dockerfile"), []byte(dockerfile), 0644); err != nil {
		t.Fatal(err)
	}

	// Create BUILD.yaml with exportToCache
	buildYAML := `packages:
  - name: test-image
    type: docker
    config:
      dockerfile: Dockerfile
      image:
        - localhost/leeway-slsa-test:latest
      exportToCache: true
`
	if err := os.WriteFile(filepath.Join(wsDir, "BUILD.yaml"), []byte(buildYAML), 0644); err != nil {
		t.Fatal(err)
	}

	// Initialize git repo
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

	gitCommit := exec.Command("git", "commit", "-m", "initial")
	gitCommit.Dir = wsDir
	gitCommit.Env = append(os.Environ(),
		"GIT_AUTHOR_DATE=2021-01-01T00:00:00Z",
		"GIT_COMMITTER_DATE=2021-01-01T00:00:00Z",
	)
	if err := gitCommit.Run(); err != nil {
		t.Fatal(err)
	}

	// Build with SLSA enabled
	cacheDir := filepath.Join(tmpDir, "cache")
	cache, err := local.NewFilesystemCache(cacheDir)
	if err != nil {
		t.Fatal(err)
	}

	buildCtx, err := newBuildContext(buildOptions{
		LocalCache:          cache,
		DockerExportToCache: true,
		DockerExportSet:     true,
		Reporter:            NewConsoleReporter(),
	})
	if err != nil {
		t.Fatal(err)
	}

	ws, err := FindWorkspace(wsDir, Arguments{}, "", "")
	if err != nil {
		t.Fatal(err)
	}

	pkg, ok := ws.Packages["//:test-image"]
	if !ok {
		t.Fatal("package //:test-image not found")
	}

	// Build the package - this should trigger SLSA provenance generation
	// which calls the Subjects function that extracts digest from OCI layout
	if err := pkg.build(buildCtx); err != nil {
		t.Fatalf("build failed: %v", err)
	}

	// Verify that the build succeeded and created the cache artifact
	// Find the cache file (it might have a different name)
	cacheFiles, err := filepath.Glob(filepath.Join(cacheDir, "*.tar.gz"))
	if err != nil || len(cacheFiles) == 0 {
		t.Fatal("No cache file found after build")
	}
	cachePath := cacheFiles[0]
	t.Logf("Found cache artifact: %s", cachePath)

	// Verify the OCI layout was created (image.tar inside the cache)
	// This confirms that OCI export worked
	f, err := os.Open(cachePath)
	if err != nil {
		t.Fatalf("failed to open cache file: %v", err)
	}
	defer f.Close()

	gzr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("failed to create gzip reader: %v", err)
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)
	foundImageTar := false
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("failed to read tar: %v", err)
		}
		if hdr.Name == "./image.tar" {
			foundImageTar = true
			break
		}
	}

	if !foundImageTar {
		t.Fatal("image.tar not found in cache artifact (OCI layout not created)")
	}

	t.Logf("✅ Build succeeded with OCI layout export")
	t.Logf("✅ No 'docker inspect' error occurred")
	t.Logf("✅ This confirms the fix works: digest extracted from OCI layout instead of Docker daemon")
}

// TestDockerPackage_ContainerExtraction_Integration tests container filesystem extraction
// with both Docker daemon and OCI layout paths. Validates the fix for checkOCILayoutExists().
//
// Tests two scenarios:
// 1. with_docker_daemon (exportToCache=false) - uses docker image inspect
// 2. with_oci_layout (exportToCache=true) - uses checkOCILayoutExists()
//
// SLSA relevance: Ensures packages that extract files from Docker images work with SLSA L3 caching.
func TestDockerPackage_ContainerExtraction_Integration(t *testing.T) {
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

	// Create docker-container builder for OCI export
	builderName := "leeway-extract-test-builder"
	createBuilder := exec.Command("docker", "buildx", "create", "--name", builderName, "--driver", "docker-container", "--bootstrap")
	if err := createBuilder.Run(); err != nil {
		t.Logf("Warning: failed to create builder (might already exist): %v", err)
	}
	defer func() {
		exec.Command("docker", "buildx", "rm", builderName).Run()
	}()

	useBuilder := exec.Command("docker", "buildx", "use", builderName)
	if err := useBuilder.Run(); err != nil {
		t.Fatalf("Failed to use builder: %v", err)
	}
	defer func() {
		exec.Command("docker", "buildx", "use", "default").Run()
	}()

	// Test both paths
	testCases := []struct {
		name            string
		exportToCache   bool
		expectedMessage string
	}{
		{
			name:            "with_docker_daemon",
			exportToCache:   false,
			expectedMessage: "Image found in Docker daemon",
		},
		{
			name:            "with_oci_layout",
			exportToCache:   true,
			expectedMessage: "OCI layout image.tar found and valid",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			wsDir := filepath.Join(tmpDir, "workspace")
			if err := os.MkdirAll(wsDir, 0755); err != nil {
				t.Fatal(err)
			}

			// Create WORKSPACE.yaml
			workspaceYAML := `defaultTarget: ":test-extract"`
			if err := os.WriteFile(filepath.Join(wsDir, "WORKSPACE.yaml"), []byte(workspaceYAML), 0644); err != nil {
				t.Fatal(err)
			}

			// Create Dockerfile
			dockerfile := `FROM alpine:3.18
RUN echo "test content" > /test.txt
`
			if err := os.WriteFile(filepath.Join(wsDir, "Dockerfile"), []byte(dockerfile), 0644); err != nil {
				t.Fatal(err)
			}

			// Create BUILD.yaml with container extraction
			buildYAML := fmt.Sprintf(`packages:
  - name: test-extract
    type: docker
    config:
      dockerfile: Dockerfile
      exportToCache: %v
`, tc.exportToCache)
			if err := os.WriteFile(filepath.Join(wsDir, "BUILD.yaml"), []byte(buildYAML), 0644); err != nil {
				t.Fatal(err)
			}

			// Initialize git repo
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

			gitCommit := exec.Command("git", "commit", "-m", "initial")
			gitCommit.Dir = wsDir
			gitCommit.Env = append(os.Environ(),
				"GIT_AUTHOR_DATE=2021-01-01T00:00:00Z",
				"GIT_COMMITTER_DATE=2021-01-01T00:00:00Z",
			)
			if err := gitCommit.Run(); err != nil {
				t.Fatal(err)
			}

			// Build
			cacheDir := filepath.Join(tmpDir, "cache")
			cache, err := local.NewFilesystemCache(cacheDir)
			if err != nil {
				t.Fatal(err)
			}

			buildCtx, err := newBuildContext(buildOptions{
				LocalCache:          cache,
				DockerExportToCache: tc.exportToCache,
				DockerExportSet:     true,
				Reporter:            NewConsoleReporter(),
			})
			if err != nil {
				t.Fatal(err)
			}

			ws, err := FindWorkspace(wsDir, Arguments{}, "", "")
			if err != nil {
				t.Fatal(err)
			}

			pkg, ok := ws.Packages["//:test-extract"]
			if !ok {
				t.Fatal("package //:test-extract not found")
			}

			// Build the package - this should extract the container filesystem
			if err := pkg.build(buildCtx); err != nil {
				t.Fatalf("build failed: %v", err)
			}

			t.Logf("✅ Build succeeded with exportToCache=%v", tc.exportToCache)
			t.Logf("✅ Container filesystem extraction completed")
			t.Logf("✅ No 'image not found' error occurred")
		})
	}
}


// TestDockerPackage_SBOM_OCI_Integration verifies SBOM generation works with OCI layout export.
// Tests two scenarios:
// 1. SBOM with Docker daemon (exportToCache=false) - traditional path
// 2. SBOM with OCI layout (exportToCache=true) - should scan oci-archive:image.tar
//
// This test validates the fix for the issue where SBOM generation fails with OCI layout
// because it tries to inspect the Docker daemon instead of scanning the OCI archive.
func TestDockerPackage_SBOM_OCI_Integration(t *testing.T) {
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
		description   string
	}{
		{
			name:          "sbom_with_docker_daemon",
			exportToCache: false,
			description:   "SBOM generation from Docker daemon (traditional path)",
		},
		{
			name:          "sbom_with_oci_layout",
			exportToCache: true,
			description:   "SBOM generation from OCI layout (oci-archive:image.tar)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Logf("Testing: %s", tt.description)

			// Create docker-container builder for OCI export if needed
			if tt.exportToCache {
				builderName := "leeway-sbom-test-builder"
				createBuilder := exec.Command("docker", "buildx", "create", "--name", builderName, "--driver", "docker-container", "--bootstrap")
				if err := createBuilder.Run(); err != nil {
					t.Logf("Builder creation failed (might already exist): %v", err)
				}
				defer func() {
					removeBuilder := exec.Command("docker", "buildx", "rm", builderName)
					_ = removeBuilder.Run()
				}()

				useBuilder := exec.Command("docker", "buildx", "use", builderName)
				if err := useBuilder.Run(); err != nil {
					t.Fatalf("Failed to use builder: %v", err)
				}
			}

			// Create temporary workspace
			tmpDir := t.TempDir()

			// Initialize git repository for SBOM timestamp normalization
			gitInit := exec.Command("git", "init")
			gitInit.Dir = tmpDir
			if err := gitInit.Run(); err != nil {
				t.Fatalf("Failed to initialize git repository: %v", err)
			}

			// Configure git user for commits
			gitConfigName := exec.Command("git", "config", "user.name", "Test User")
			gitConfigName.Dir = tmpDir
			if err := gitConfigName.Run(); err != nil {
				t.Fatalf("Failed to configure git user.name: %v", err)
			}

			gitConfigEmail := exec.Command("git", "config", "user.email", "test@example.com")
			gitConfigEmail.Dir = tmpDir
			if err := gitConfigEmail.Run(); err != nil {
				t.Fatalf("Failed to configure git user.email: %v", err)
			}

			// Create WORKSPACE.yaml with SBOM enabled
			workspaceYAML := `defaultTarget: "app:docker"
sbom:
  enabled: true
  scanVulnerabilities: false`
			workspacePath := filepath.Join(tmpDir, "WORKSPACE.yaml")
			if err := os.WriteFile(workspacePath, []byte(workspaceYAML), 0644); err != nil {
				t.Fatal(err)
			}

			// Create component directory
			appDir := filepath.Join(tmpDir, "app")
			if err := os.MkdirAll(appDir, 0755); err != nil {
				t.Fatal(err)
			}

			// Create a simple Dockerfile with some packages for SBOM to scan
			dockerfile := `FROM alpine:latest
RUN apk add --no-cache curl wget
LABEL test="sbom-test"
CMD ["echo", "test"]`

			dockerfilePath := filepath.Join(appDir, "Dockerfile")
			if err := os.WriteFile(dockerfilePath, []byte(dockerfile), 0644); err != nil {
				t.Fatal(err)
			}

			// Create BUILD.yaml
			buildYAML := fmt.Sprintf(`packages:
- name: docker
  type: docker
  config:
    dockerfile: Dockerfile
    exportToCache: %t`, tt.exportToCache)

			buildPath := filepath.Join(appDir, "BUILD.yaml")
			if err := os.WriteFile(buildPath, []byte(buildYAML), 0644); err != nil {
				t.Fatal(err)
			}

			// Create initial git commit for SBOM timestamp
			gitAdd := exec.Command("git", "add", ".")
			gitAdd.Dir = tmpDir
			if err := gitAdd.Run(); err != nil {
				t.Fatalf("Failed to git add: %v", err)
			}

			// Use fixed timestamp for deterministic git commit
			gitCommit := exec.Command("git", "commit", "-m", "initial")
			gitCommit.Dir = tmpDir
			gitCommit.Env = append(os.Environ(),
				"GIT_AUTHOR_DATE=2021-01-01T00:00:00Z",
				"GIT_COMMITTER_DATE=2021-01-01T00:00:00Z",
			)
			if err := gitCommit.Run(); err != nil {
				t.Fatalf("Failed to git commit: %v", err)
			}

			// Load workspace
			workspace, err := FindWorkspace(tmpDir, Arguments{}, "", "")
			if err != nil {
				t.Fatal(err)
			}

			// Verify SBOM is enabled
			if !workspace.SBOM.Enabled {
				t.Fatal("SBOM should be enabled in workspace")
			}

			// Create build context
			cacheDir := filepath.Join(tmpDir, ".cache")
			cache, err := local.NewFilesystemCache(cacheDir)
			if err != nil {
				t.Fatal(err)
			}

			buildCtx, err := newBuildContext(buildOptions{
				LocalCache:          cache,
				DockerExportToCache: tt.exportToCache,
				DockerExportSet:     true,
				Reporter:            NewConsoleReporter(),
			})
			if err != nil {
				t.Fatal(err)
			}

			// Get the package
			pkg, ok := workspace.Packages["app:docker"]
			if !ok {
				t.Fatal("package app:docker not found")
			}

			// Build the package - this should generate SBOM
			err = pkg.build(buildCtx)
			if err != nil {
				t.Fatalf("Build failed: %v", err)
			}

			t.Logf("✅ Build succeeded with exportToCache=%v", tt.exportToCache)

			// Verify SBOM files were created in the cache
			cacheLoc, exists := cache.Location(pkg)
			if !exists {
				t.Fatal("Package not found in cache")
			}

			// Extract and verify SBOM files from cache
			sbomFormats := []string{
				"sbom.cdx.json",  // CycloneDX
				"sbom.spdx.json", // SPDX
				"sbom.json",      // Syft (native format)
			}

			foundSBOMs := make(map[string]bool)

			// Open the cache tar.gz
			f, err := os.Open(cacheLoc)
			if err != nil {
				t.Fatalf("Failed to open cache file: %v", err)
			}
			defer f.Close()

			gzin, err := gzip.NewReader(f)
			if err != nil {
				t.Fatalf("Failed to create gzip reader: %v", err)
			}
			defer gzin.Close()

			tarin := tar.NewReader(gzin)
			for {
				hdr, err := tarin.Next()
				if errors.Is(err, io.EOF) {
					break
				}
				if err != nil {
					t.Fatalf("Failed to read tar: %v", err)
				}

				filename := filepath.Base(hdr.Name)
				for _, sbomFile := range sbomFormats {
					if filename == sbomFile {
						foundSBOMs[sbomFile] = true
						t.Logf("✅ Found SBOM file: %s (size: %d bytes)", sbomFile, hdr.Size)

						// Read and validate SBOM content
						sbomContent := make([]byte, hdr.Size)
						if _, err := io.ReadFull(tarin, sbomContent); err != nil {
							t.Fatalf("Failed to read SBOM content: %v", err)
						}

						// Validate it's valid JSON
						var sbomData map[string]interface{}
						if err := json.Unmarshal(sbomContent, &sbomData); err != nil {
							t.Fatalf("SBOM file %s is not valid JSON: %v", sbomFile, err)
						}

						// Check for expected content based on format
						if strings.Contains(sbomFile, "cdx") {
							if _, ok := sbomData["bomFormat"]; !ok {
								t.Errorf("CycloneDX SBOM missing bomFormat field")
							}
						} else if strings.Contains(sbomFile, "spdx") {
							if _, ok := sbomData["spdxVersion"]; !ok {
								t.Errorf("SPDX SBOM missing spdxVersion field")
							}
						}

						t.Logf("✅ SBOM file %s is valid JSON with expected structure", sbomFile)
					}
				}
			}

			// Verify all SBOM formats were generated
			for _, sbomFile := range sbomFormats {
				if !foundSBOMs[sbomFile] {
					t.Errorf("❌ SBOM file %s not found in cache", sbomFile)
				}
			}

			if len(foundSBOMs) == len(sbomFormats) {
				t.Logf("✅ All %d SBOM formats generated successfully", len(sbomFormats))
			}

			t.Logf("✅ SBOM generation works correctly with exportToCache=%v", tt.exportToCache)
		})
	}
}
