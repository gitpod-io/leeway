package leeway

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestParseGoCoverOutput(t *testing.T) {
	type Expectation struct {
		Error            string
		Coverage         int
		FuncsWithoutTest int
		FuncsWithTest    int
	}
	tests := []struct {
		Name        string
		Input       string
		Expectation Expectation
	}{
		{
			Name: "empty",
		},
		{
			Name: "valid",
			Input: `github.com/gitpod-io/leeway/store.go:165:                    Get                             100.0%
			github.com/gitpod-io/leeway/store.go:173:                    Set                             100.0%
			github.com/gitpod-io/leeway/store.go:178:                    Delete                          100.0%
			github.com/gitpod-io/leeway/store.go:183:                    Scan                            80.0%
			github.com/gitpod-io/leeway/store.go:194:                    Close                           0.0%
			github.com/gitpod-io/leeway/store.go:206:                    Upsert                          0.0%`,
			Expectation: Expectation{
				Coverage:         63,
				FuncsWithoutTest: 2,
				FuncsWithTest:    4,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			var act Expectation

			var err error
			act.Coverage, act.FuncsWithoutTest, act.FuncsWithTest, err = parseGoCoverOutput(test.Input)
			if err != nil {
				act.Error = err.Error()
			}

			if diff := cmp.Diff(test.Expectation, act); diff != "" {
				t.Errorf("parseGoCoverOutput() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// createTestTarball creates a gzipped tarball with the given files for testing.
// files is a map of path -> content.
func createTestTarball(t *testing.T, files map[string]string) string {
	t.Helper()

	tmpFile, err := os.CreateTemp(t.TempDir(), "test-*.tar.gz")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer tmpFile.Close()

	gzw := gzip.NewWriter(tmpFile)
	defer gzw.Close()

	tw := tar.NewWriter(gzw)
	defer tw.Close()

	for path, content := range files {
		hdr := &tar.Header{
			Name: path,
			Mode: 0644,
			Size: int64(len(content)),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("failed to write tar header for %s: %v", path, err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatalf("failed to write tar content for %s: %v", path, err)
		}
	}

	return tmpFile.Name()
}

func TestExtractNpmPackageNames(t *testing.T) {
	tests := []struct {
		name     string
		files    map[string]string
		expected map[string]bool
		wantErr  bool
	}{
		{
			name: "YarnLibrary tarball (yarn pack format)",
			files: map[string]string{
				"package/package.json": `{"name": "my-library", "version": "1.0.0"}`,
				"package/index.js":     "module.exports = {}",
			},
			expected: map[string]bool{"my-library": true},
		},
		{
			name: "YarnApp tarball with single package",
			files: map[string]string{
				"./node_modules/my-app/package.json": `{"name": "my-app", "version": "2.0.0"}`,
				"./node_modules/my-app/index.js":     "module.exports = {}",
			},
			expected: map[string]bool{"my-app": true},
		},
		{
			name: "YarnApp tarball with multiple packages",
			files: map[string]string{
				"./node_modules/pkg-a/package.json": `{"name": "pkg-a", "version": "1.0.0"}`,
				"./node_modules/pkg-b/package.json": `{"name": "pkg-b", "version": "1.0.0"}`,
			},
			expected: map[string]bool{"pkg-a": true, "pkg-b": true},
		},
		{
			name: "YarnApp tarball with scoped package",
			files: map[string]string{
				"./node_modules/@scope/my-pkg/package.json": `{"name": "@scope/my-pkg", "version": "1.0.0"}`,
			},
			expected: map[string]bool{"@scope/my-pkg": true},
		},
		{
			name: "ignores nested node_modules",
			files: map[string]string{
				"./node_modules/pkg-a/package.json":                     `{"name": "pkg-a", "version": "1.0.0"}`,
				"./node_modules/pkg-a/node_modules/nested/package.json": `{"name": "nested", "version": "1.0.0"}`,
			},
			expected: map[string]bool{"pkg-a": true},
		},
		{
			name: "ignores packages named 'local'",
			files: map[string]string{
				"package/package.json": `{"name": "local", "version": "1.0.0"}`,
			},
			expected: map[string]bool{},
		},
		{
			name: "ignores packages without name",
			files: map[string]string{
				"package/package.json": `{"version": "1.0.0"}`,
			},
			expected: map[string]bool{},
		},
		{
			name: "handles malformed JSON gracefully",
			files: map[string]string{
				"package/package.json": `{not valid json`,
			},
			expected: map[string]bool{},
		},
		{
			name: "node_modules without ./ prefix",
			files: map[string]string{
				"node_modules/my-pkg/package.json": `{"name": "my-pkg", "version": "1.0.0"}`,
			},
			expected: map[string]bool{"my-pkg": true},
		},
		{
			name:     "empty tarball",
			files:    map[string]string{},
			expected: map[string]bool{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tarball := createTestTarball(t, tt.files)

			got, err := extractNpmPackageNames(tarball)
			if (err != nil) != tt.wantErr {
				t.Errorf("extractNpmPackageNames() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if diff := cmp.Diff(tt.expected, got); diff != "" {
				t.Errorf("extractNpmPackageNames() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestExtractNpmPackageNames_FileNotFound(t *testing.T) {
	_, err := extractNpmPackageNames("/nonexistent/path/to/tarball.tar.gz")
	if err == nil {
		t.Error("extractNpmPackageNames() expected error for nonexistent file, got nil")
	}
}

func TestExtractNpmPackageNames_InvalidGzip(t *testing.T) {
	// Create a file that's not gzipped
	tmpFile := filepath.Join(t.TempDir(), "not-gzipped.tar.gz")
	if err := os.WriteFile(tmpFile, []byte("not gzipped content"), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	_, err := extractNpmPackageNames(tmpFile)
	if err == nil {
		t.Error("extractNpmPackageNames() expected error for non-gzipped file, got nil")
	}
}

func TestYarnAppExtraction_ScopedPackage(t *testing.T) {
	// This test verifies that scoped packages are correctly extracted from YarnApp tarballs.
	// YarnApp tarballs have structure: ./node_modules/@scope/pkg-name/...
	// For scoped packages, we need --strip-components=4 (not 3) to correctly extract.
	//
	// Path components for scoped package:
	// ./node_modules/@scope/pkg-name/package.json
	// ^  ^            ^      ^        ^
	// 1  2            3      4        file
	//
	// Path components for non-scoped package:
	// ./node_modules/pkg-name/package.json
	// ^  ^            ^        ^
	// 1  2            3        file

	tests := []struct {
		name    string
		npmName string
	}{
		{
			name:    "non-scoped package",
			npmName: "my-pkg",
		},
		{
			name:    "scoped package",
			npmName: "@test/utils",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()

			// Create tarball with the package structure (simulating YarnApp output)
			tarballDir := filepath.Join(tmpDir, "tarball-content")
			var pkgDir string
			if strings.HasPrefix(tt.npmName, "@") {
				parts := strings.SplitN(tt.npmName, "/", 2)
				pkgDir = filepath.Join(tarballDir, "node_modules", parts[0], parts[1])
			} else {
				pkgDir = filepath.Join(tarballDir, "node_modules", tt.npmName)
			}
			if err := os.MkdirAll(pkgDir, 0755); err != nil {
				t.Fatal(err)
			}

			// Create package.json
			pkgJSON := fmt.Sprintf(`{"name":"%s","version":"1.0.0"}`, tt.npmName)
			if err := os.WriteFile(filepath.Join(pkgDir, "package.json"), []byte(pkgJSON), 0644); err != nil {
				t.Fatal(err)
			}

			// Create tarball
			tarballPath := filepath.Join(tmpDir, "test.tar.gz")
			tarCmd := exec.Command("tar", "-czf", tarballPath, "-C", tarballDir, ".")
			if err := tarCmd.Run(); err != nil {
				t.Fatalf("failed to create tarball: %v", err)
			}

			// Calculate strip components based on package type:
			// - Non-scoped packages (e.g., "utils"): 3 components (., node_modules, utils)
			// - Scoped packages (e.g., "@test/utils"): 4 components (., node_modules, @test, utils)
			stripComponents := 3
			if strings.HasPrefix(tt.npmName, "@") {
				stripComponents = 4
			}

			// Extract to _link_deps/<npmName>/ using the production logic
			extractDir := filepath.Join(tmpDir, "_link_deps", tt.npmName)
			if err := os.MkdirAll(extractDir, 0755); err != nil {
				t.Fatal(err)
			}

			tarballFilter := fmt.Sprintf("./node_modules/%s/", tt.npmName)
			extractCmd := exec.Command("tar", "-xzf", tarballPath, "-C", extractDir,
				fmt.Sprintf("--strip-components=%d", stripComponents), tarballFilter)
			if err := extractCmd.Run(); err != nil {
				t.Fatalf("extraction failed: %v", err)
			}

			// Check if package.json is at the correct location
			correctPath := filepath.Join(extractDir, "package.json")
			if _, err := os.Stat(correctPath); err != nil {
				// List what was actually extracted for debugging
				files, _ := filepath.Glob(filepath.Join(extractDir, "*"))
				t.Errorf("package.json should be at %s but wasn't found. Extracted files: %v", correctPath, files)
			}
		})
	}
}
