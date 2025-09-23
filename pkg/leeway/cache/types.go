// Package cache provides local and remote caching capabilities for build artifacts.
//
// SLSA Verification Behavior:
// The cache system supports SLSA (Supply-chain Levels for Software Artifacts) verification
// for enhanced security. The behavior is controlled by the SLSAConfig.RequireAttestation field:
//
//   - RequireAttestation=false (default): Missing attestation → download without verification
//     This provides graceful degradation and backward compatibility.
//
//   - RequireAttestation=true: Missing attestation → skip download, allow local build fallback
//     This enforces strict security but may impact build performance.
//
// The cache system is designed to never fail builds due to cache issues. When artifacts
// cannot be downloaded (missing, verification failed, network issues), the system gracefully
// falls back to local builds.
//
// Future Evolution:
// A CLI flag like --slsa-require-attestation could be added to set RequireAttestation=true
// for environments that require strict SLSA compliance.
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

// SLSAConfig holds configuration for SLSA verification
type SLSAConfig struct {
	// Verification enables SLSA verification for cached artifacts
	Verification bool `yaml:"verification" json:"verification"`

	// SourceURI is the expected source URI for SLSA verification
	SourceURI string `yaml:"source_uri" json:"source_uri"`

	// TrustedRoots contains the trusted root certificates for SLSA verification
	TrustedRoots []string `yaml:"trusted_roots" json:"trusted_roots"`

	// RequireAttestation determines behavior when SLSA attestations are missing.
	// When true: missing attestation → skip download, allow local build fallback
	// When false: missing attestation → download without verification (with warning)
	// Default: false (for backward compatibility and graceful degradation)
	RequireAttestation bool `yaml:"require_attestation" json:"require_attestation"`
}

// RemoteConfig holds configuration for remote cache implementations
type RemoteConfig struct {
	// BucketName for object storage
	BucketName string

	// Region for services that require it (e.g. S3)
	Region string

	// Endpoint for the remote service
	Endpoint string

	// SLSA holds SLSA verification configuration
	SLSA *SLSAConfig `yaml:"slsa,omitempty" json:"slsa,omitempty"`
}
