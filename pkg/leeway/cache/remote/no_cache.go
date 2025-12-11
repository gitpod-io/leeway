package remote

import (
	"context"

	"github.com/gitpod-io/leeway/pkg/leeway/cache"
)

// NoRemoteCache implements the default no-remote cache behavior
type NoRemoteCache struct{}

// NewNoRemoteCache creates a new NoRemoteCache instance
func NewNoRemoteCache() *NoRemoteCache {
	return &NoRemoteCache{}
}

// ExistingPackages returns existing cached build artifacts in the remote cache
func (NoRemoteCache) ExistingPackages(ctx context.Context, pkgs []cache.Package) (map[cache.Package]struct{}, error) {
	return map[cache.Package]struct{}{}, nil
}

// Download makes a best-effort attempt at downloading previously cached build artifacts.
// NoRemoteCache always returns NotFound for all packages since there is no remote cache.
func (NoRemoteCache) Download(ctx context.Context, dst cache.LocalCache, pkgs []cache.Package) map[string]cache.DownloadResult {
	results := make(map[string]cache.DownloadResult)
	for _, pkg := range pkgs {
		results[pkg.FullName()] = cache.DownloadResult{Status: cache.DownloadStatusNotFound}
	}
	return results
}

// Upload makes a best effort to upload the build artifacts to a remote cache
func (NoRemoteCache) Upload(ctx context.Context, src cache.LocalCache, pkgs []cache.Package) error {
	return nil
}

// UploadFile uploads a single file to the remote cache with the given key
func (NoRemoteCache) UploadFile(ctx context.Context, filePath string, key string) error {
	return nil
}

// HasFile checks if a file exists in the remote cache with the given key
func (NoRemoteCache) HasFile(ctx context.Context, key string) (bool, error) {
	return false, nil
}
