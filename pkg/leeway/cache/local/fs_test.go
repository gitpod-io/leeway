package local

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gitpod-io/leeway/pkg/leeway/cache"
	"github.com/google/go-cmp/cmp"
)

type mockPackage struct {
	version string
	err     error
}

func (m mockPackage) Version() (string, error) {
	return m.version, m.err
}

func (m mockPackage) FullName() string {
	return "mock-package"
}

func TestNewFilesystemCache(t *testing.T) {
	t.Parallel()

	type Expectation struct {
		Error string
	}

	tests := []struct {
		Name        string
		Location    string
		Expectation Expectation
	}{
		{
			Name:     "valid location",
			Location: "testdata/cache",
			Expectation: Expectation{
				Error: "",
			},
		},
		{
			Name:     "invalid location",
			Location: "/proc/invalid/location",
			Expectation: Expectation{
				Error: "failed to create cache directory:",
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()
			var act Expectation

			_, err := NewFilesystemCache(test.Location)
			if err != nil {
				act.Error = err.Error()[:len(test.Expectation.Error)]
			}

			if diff := cmp.Diff(test.Expectation, act); diff != "" {
				t.Errorf("NewFilesystemCache() mismatch (-want +got):\n%s", diff)
			}

			if test.Expectation.Error == "" {
				// Cleanup created directory
				if err := os.RemoveAll(test.Location); err != nil {
					t.Logf("Failed to clean up test directory: %v", err)
				}
			}
		})
	}
}

func TestLocation(t *testing.T) {
	t.Parallel()

	type Expectation struct {
		Path   string
		Exists bool
		Error  string
	}

	tmpDir := t.TempDir()

	// Create test files
	err := os.WriteFile(filepath.Join(tmpDir, "test1.tar.gz"), []byte("test"), 0644)
	if err != nil {
		t.Fatal(err)
	}
	err = os.WriteFile(filepath.Join(tmpDir, "test2.tar"), []byte("test"), 0644)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		Name        string
		Cache       *FilesystemCache
		Package     cache.Package
		Expectation Expectation
	}{
		{
			Name:  "package version error",
			Cache: &FilesystemCache{Origin: tmpDir},
			Package: mockPackage{
				version: "",
				err:     os.ErrNotExist,
			},
			Expectation: Expectation{
				Path:   "",
				Exists: false,
			},
		},
		{
			Name:  "existing tar.gz file",
			Cache: &FilesystemCache{Origin: tmpDir},
			Package: mockPackage{
				version: "test1",
				err:     nil,
			},
			Expectation: Expectation{
				Path:   filepath.Join(tmpDir, "test1.tar.gz"),
				Exists: true,
			},
		},
		{
			Name:  "existing tar file",
			Cache: &FilesystemCache{Origin: tmpDir},
			Package: mockPackage{
				version: "test2",
				err:     nil,
			},
			Expectation: Expectation{
				Path:   filepath.Join(tmpDir, "test2.tar"),
				Exists: true,
			},
		},
		{
			Name:  "non-existing file",
			Cache: &FilesystemCache{Origin: tmpDir},
			Package: mockPackage{
				version: "nonexistent",
				err:     nil,
			},
			Expectation: Expectation{
				Path:   filepath.Join(tmpDir, "nonexistent.tar"),
				Exists: false,
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()
			var act Expectation

			path, exists := test.Cache.Location(test.Package)
			act.Path = path
			act.Exists = exists

			if diff := cmp.Diff(test.Expectation, act); diff != "" {
				t.Errorf("Location() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestFileExists(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()

	// Create a test file
	testFile := filepath.Join(tmpDir, "test.txt")
	err := os.WriteFile(testFile, []byte("test"), 0644)
	if err != nil {
		t.Fatal(err)
	}

	// Create a test directory
	testDir := filepath.Join(tmpDir, "testdir")
	err = os.Mkdir(testDir, 0755)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		Name        string
		Path        string
		Expectation bool
	}{
		{
			Name:        "existing file",
			Path:        testFile,
			Expectation: true,
		},
		{
			Name:        "directory",
			Path:        testDir,
			Expectation: false,
		},
		{
			Name:        "non-existing file",
			Path:        filepath.Join(tmpDir, "nonexistent.txt"),
			Expectation: false,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()

			result := fileExists(test.Path)
			if result != test.Expectation {
				t.Errorf("fileExists() = %v, want %v", result, test.Expectation)
			}
		})
	}
}
