package local

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/gitpod-io/leeway/pkg/leeway/cache"
	log "github.com/sirupsen/logrus"
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
		log.WithError(err).WithField("package", pkg.FullName()).Warn("Failed to get package version")
		return "", false
	}

	// Ensure the cache directory exists first - do this unconditionally
	if err := os.MkdirAll(fsc.Origin, 0755); err != nil {
		log.WithError(err).WithField("dir", fsc.Origin).Warn("Failed to create cache directory")
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

	// Always ensure the parent directory exists for this path
	// This is critical for download operations to succeed
	if err := os.MkdirAll(filepath.Dir(tarPath), 0755); err != nil {
		log.WithError(err).WithField("dir", filepath.Dir(tarPath)).Warn("Failed to create directory for package")
	}

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
