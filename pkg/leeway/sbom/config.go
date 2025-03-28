package sbom

// SBOMOptions contains configuration for SBOM generation
type SBOMOptions struct {
	// Format specifies the SBOM format (CycloneDX, SPDX)
	// Default: CycloneDX
	Format string

	// OutputPath specifies where to store the SBOM
	// Default: alongside build artifacts
	OutputPath string
}

// DefaultSBOMOptions returns the default SBOM options
func DefaultSBOMOptions() *SBOMOptions {
	return &SBOMOptions{
		Format: "cyclonedx",
	}
}

// CVEOptions contains configuration for CVE scanning
type CVEOptions struct {
	// FailOn specifies severity levels to fail the build on
	// Default: ["CRITICAL"]
	FailOn []string

	// IgnoreRules specifies CVE ignore rules with documentation
	IgnoreRules []IgnoreRule

	// OutputPath specifies where to store the CVE report
	// Default: alongside build artifacts
	OutputPath string

	// IncludeMetadata specifies whether to include metadata in the report
	// Default: true
	IncludeMetadata bool
}

// DefaultCVEOptions returns the default CVE options
func DefaultCVEOptions() *CVEOptions {
	return &CVEOptions{
		FailOn:          []string{"CRITICAL"},
		IncludeMetadata: true,
	}
}

// IgnoreRule represents a rule to ignore a specific CVE with documentation
type IgnoreRule struct {
	// ID is the CVE ID to ignore
	ID string `yaml:"id" json:"id"`

	// Reason is the documented reason for ignoring this CVE
	Reason string `yaml:"reason" json:"reason"`

	// Expiration is an optional expiration date for this ignore rule
	Expiration string `yaml:"expiration,omitempty" json:"expiration,omitempty"`

	// Packages is an optional list of packages this rule applies to
	Packages []string `yaml:"packages,omitempty" json:"packages,omitempty"`
}

// ScanMetadata contains metadata about a CVE scan
type ScanMetadata struct {
	// Timestamp is the time the scan was performed
	Timestamp string `json:"timestamp"`

	// Package is the package that was scanned
	Package string `json:"package"`

	// Version is the version of the package that was scanned
	Version string `json:"version"`

	// SBOMFormat is the format of the SBOM that was used
	SBOMFormat string `json:"sbomFormat"`

	// FailOn is the list of severity levels that would fail the build
	FailOn []string `json:"failOn"`

	// IgnoreFilePath is the path to the ignore file that was used
	IgnoreFilePath string `json:"ignoreFilePath,omitempty"`
}
