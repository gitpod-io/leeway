// Package cache provides local and remote caching capabilities for build artifacts.
//
// SBOM Sidecar Files:
// SBOM (Software Bill of Materials) files are stored alongside artifacts as sidecar files.
// The naming convention is: <artifact>.<extension> where extension is one of:
//   - .sbom.cdx.json  (CycloneDX format)
//   - .sbom.spdx.json (SPDX format)
//   - .sbom.json      (Syft native format)
//
// SLSA Verification Behavior:
// The cache system supports SLSA (Supply-chain Levels for Software Artifacts) verification
// for enhanced security. The behavior is controlled by the SLSAConfig.RequireAttestation field:
//
//   - RequireAttestation=false (default): Missing/invalid attestation → download without verification
//     This provides graceful degradation and backward compatibility. The artifact is downloaded
//     and used, but a warning is logged about the missing or invalid attestation.
//
//   - RequireAttestation=true: Missing/invalid attestation → skip download, allow local build fallback
//     This enforces strict security but may impact build performance. When verification fails,
//     the artifact is not downloaded, forcing a local rebuild with proper attestation.
//
// The cache system is designed to never fail builds due to cache issues. When artifacts
// cannot be downloaded (missing, verification failed, network issues), the system gracefully
// falls back to local builds.
//
// Configuration:
// RequireAttestation can be controlled via:
// - Environment variable: LEEWAY_SLSA_REQUIRE_ATTESTATION=true
// - CLI flag: --slsa-require-attestation
// - Workspace SLSA config: Automatically enabled when provenance.slsa=true in WORKSPACE.yaml
package cache

import (
	"context"
)

// SBOM file format constants
const (
	// SBOMBaseFilename is the base filename for SBOM files (e.g., "sbom" in "artifact.sbom.cdx.json")
	SBOMBaseFilename = "sbom"

	// SBOMCycloneDXFileExtension is the extension of the CycloneDX SBOM file
	SBOMCycloneDXFileExtension = ".cdx.json"

	// SBOMSPDXFileExtension is the extension of the SPDX SBOM file
	SBOMSPDXFileExtension = ".spdx.json"

	// SBOMSyftFileExtension is the extension of the Syft SBOM file
	SBOMSyftFileExtension = ".json"
)

// SBOMSidecarExtensions returns all SBOM sidecar file extensions.
// These are the extensions used for SBOM files stored alongside artifacts.
func SBOMSidecarExtensions() []string {
	return []string{
		"." + SBOMBaseFilename + SBOMCycloneDXFileExtension, // .sbom.cdx.json
		"." + SBOMBaseFilename + SBOMSPDXFileExtension,      // .sbom.spdx.json
		"." + SBOMBaseFilename + SBOMSyftFileExtension,      // .sbom.json
	}
}

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

// DownloadStatus indicates the outcome of a package download attempt
type DownloadStatus int

const (
	// DownloadStatusSuccess indicates the package was downloaded successfully
	DownloadStatusSuccess DownloadStatus = iota
	// DownloadStatusNotFound indicates the package does not exist in remote cache
	DownloadStatusNotFound
	// DownloadStatusFailed indicates a transient failure (network, timeout, etc.)
	DownloadStatusFailed
	// DownloadStatusVerificationFailed indicates SLSA verification failed
	DownloadStatusVerificationFailed
	// DownloadStatusSkipped indicates the package was already in local cache
	DownloadStatusSkipped
)

// String returns a string representation of the download status
func (s DownloadStatus) String() string {
	switch s {
	case DownloadStatusSuccess:
		return "success"
	case DownloadStatusNotFound:
		return "not_found"
	case DownloadStatusFailed:
		return "failed"
	case DownloadStatusVerificationFailed:
		return "verification_failed"
	case DownloadStatusSkipped:
		return "skipped"
	default:
		return "unknown"
	}
}

// DownloadResult contains the outcome of a single package download attempt.
// This enables callers to make informed decisions about retry strategies
// and avoid unnecessary rebuilds when transient failures occur.
type DownloadResult struct {
	// Status indicates the outcome of the download attempt
	Status DownloadStatus
	// Err contains the error if Status is Failed or VerificationFailed
	Err error
	// Bytes is the size of the downloaded artifact in bytes (0 if not downloaded)
	Bytes int64
}

// RemoteCache can download and upload build artifacts into a local cache
type RemoteCache interface {
	// ExistingPackages returns existing cached build artifacts in the remote cache
	ExistingPackages(ctx context.Context, pkgs []Package) (map[Package]struct{}, error)

	// Download makes a best-effort attempt at downloading previously cached build artifacts.
	// Returns a map of package full names to their download results, enabling callers to
	// distinguish between "not found" (rebuild required) and "failed" (retry may help).
	// A cache miss does not constitute an error.
	Download(ctx context.Context, dst LocalCache, pkgs []Package) map[string]DownloadResult

	// Upload makes a best effort to upload the build artifacts to a remote cache
	Upload(ctx context.Context, src LocalCache, pkgs []Package) error

	// UploadFile uploads a single file to the remote cache with the given key
	// This is useful for uploading individual files like attestations without Package abstraction
	UploadFile(ctx context.Context, filePath string, key string) error

	// HasFile checks if a file exists in the remote cache with the given key
	// This is useful for checking if artifacts need to be uploaded
	HasFile(ctx context.Context, key string) (bool, error)
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
