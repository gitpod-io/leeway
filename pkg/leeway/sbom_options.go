package leeway

import (
	"github.com/gitpod-io/leeway/pkg/leeway/common"
	"github.com/gitpod-io/leeway/pkg/leeway/sbom"
	"golang.org/x/xerrors"
)

// SBOMOptions contains configuration for SBOM generation
type SBOMOptions struct {
	// Format specifies the SBOM format (CycloneDX, SPDX)
	// Default: CycloneDX
	Format string

	// OutputPath specifies where to store the SBOM
	// Default: alongside build artifacts
	OutputPath string
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

// Add SBOM and CVE scanning options to buildOptions
func init() {
	// Add SBOM and CVE scanning options to buildOptions
	type sbomBuildOptions struct {
		GenerateSBOM bool
		SBOMOptions  *SBOMOptions
		ScanCVE      bool
		CVEOptions   *CVEOptions
	}
}

// WithSBOMGeneration enables SBOM generation
func WithSBOMGeneration(options *SBOMOptions) BuildOption {
	return func(opts *buildOptions) error {
		opts.GenerateSBOM = true
		opts.SBOMOptions = options
		return nil
	}
}

// WithCVEScanning enables CVE scanning
func WithCVEScanning(options *CVEOptions) BuildOption {
	return func(opts *buildOptions) error {
		opts.ScanCVE = true
		opts.CVEOptions = options
		return nil
	}
}

// GetPackageInfo returns a common.PackageInfo for a package
func (p *Package) GetPackageInfo() (*common.PackageInfo, error) {
	version, err := p.Version()
	if err != nil {
		return nil, xerrors.Errorf("failed to get package version: %w", err)
	}

	return &common.PackageInfo{
		FullName:          p.FullName(),
		Version:           version,
		FilesystemSafeName: p.FilesystemSafeName(),
	}, nil
}

// ReadIgnoreRulesFromFile reads CVE ignore rules from a YAML file
func ReadIgnoreRulesFromFile(path string) ([]IgnoreRule, error) {
	sbomRules, err := sbom.ReadIgnoreRulesFromFile(path)
	if err != nil {
		return nil, xerrors.Errorf("failed to read ignore rules: %w", err)
	}

	// Convert sbom.IgnoreRule to leeway.IgnoreRule
	rules := make([]IgnoreRule, len(sbomRules))
	for i, rule := range sbomRules {
		rules[i] = IgnoreRule{
			ID:         rule.ID,
			Reason:     rule.Reason,
			Expiration: rule.Expiration,
			Packages:   rule.Packages,
		}
	}

	return rules, nil
}
