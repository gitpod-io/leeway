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

// Download makes a best-effort attempt at downloading previously cached build artifacts
func (NoRemoteCache) Download(ctx context.Context, dst cache.LocalCache, pkgs []cache.Package) error {
	return nil
}

// Upload makes a best effort to upload the build artifacts to a remote cache
func (NoRemoteCache) Upload(ctx context.Context, src cache.LocalCache, pkgs []cache.Package) error {
	return nil
}

// UploadFile uploads a single file to the remote cache with the given key
func (NoRemoteCache) UploadFile(ctx context.Context, filePath string, key string) error {
	return nil
}
