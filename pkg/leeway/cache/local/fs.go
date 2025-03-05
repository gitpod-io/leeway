package local

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/gitpod-io/leeway/pkg/leeway/cache"
)

// FilesystemCache implements a flat folder cache
type FilesystemCache struct {
	Origin string
}

// NewFilesystemCache creates a new filesystem cache
func NewFilesystemCache(location string) (*FilesystemCache, error) {
	err := os.MkdirAll(location, 0755)
	if err != nil {
		return nil, fmt.Errorf("failed to create cache directory: %w", err)
	}

	return &FilesystemCache{location}, nil
}

// Location computes the name of a packages build result artifact.
// Returns ok == true if that build artifact actually exists.
func (fsc *FilesystemCache) Location(pkg cache.Package) (path string, exists bool) {
	version, err := pkg.Version()
	if err != nil {
		return "", false
	}

	// Check for .tar.gz file first
	gzPath := filepath.Join(fsc.Origin, fmt.Sprintf("%s.tar.gz", version))
	if fileExists(gzPath) {
		return gzPath, true
	}

	// Fall back to .tar file
	tarPath := filepath.Join(fsc.Origin, fmt.Sprintf("%s.tar", version))
	exists = fileExists(tarPath)

	return tarPath, exists
}

// fileExists checks if a file exists and is not a directory
func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if err != nil {
		return false
	}
	return !info.IsDir()
}
