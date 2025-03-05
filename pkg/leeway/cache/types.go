package cache

import (
	"context"
)

// Package represents a build package that can be cached
type Package interface {
	// Version returns a unique identifier for the package
	Version() (string, error)
	// FullName returns the full name of the package
	FullName() string
}

// LocalCache provides filesystem locations for package build artifacts
type LocalCache interface {
	// Location returns the absolute filesystem path for a package build artifact
	Location(pkg Package) (path string, exists bool)
}

// RemoteCache can download and upload build artifacts into a local cache
type RemoteCache interface {
	// ExistingPackages returns existing cached build artifacts in the remote cache
	ExistingPackages(ctx context.Context, pkgs []Package) (map[Package]struct{}, error)

	// Download makes a best-effort attempt at downloading previously cached build artifacts
	// A cache miss does not constitute an error
	Download(ctx context.Context, dst LocalCache, pkgs []Package) error

	// Upload makes a best effort to upload the build artifacts to a remote cache
	Upload(ctx context.Context, src LocalCache, pkgs []Package) error
}

// ObjectStorage represents a generic object storage interface
// This allows us to abstract S3, GCS, or other storage backends
type ObjectStorage interface {
	// HasObject checks if an object exists
	HasObject(ctx context.Context, key string) (bool, error)

	// GetObject downloads an object to a local file
	GetObject(ctx context.Context, key string, dest string) (int64, error)

	// UploadObject uploads a local file to remote storage
	UploadObject(ctx context.Context, key string, src string) error

	// ListObjects lists objects with the given prefix
	ListObjects(ctx context.Context, prefix string) ([]string, error)
}

// Config holds configuration for cache implementations
type Config struct {
	// Location is the base path for local cache
	Location string

	// RemoteConfig holds remote cache specific configuration
	RemoteConfig RemoteConfig
}

// RemoteConfig holds configuration for remote cache implementations
type RemoteConfig struct {
	// BucketName for object storage
	BucketName string

	// Region for services that require it (e.g. S3)
	Region string

	// Endpoint for the remote service
	Endpoint string
}
