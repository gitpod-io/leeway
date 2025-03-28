package sbom

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/gitpod-io/leeway/pkg/leeway"
	log "github.com/sirupsen/logrus"
	"golang.org/x/xerrors"
	"gopkg.in/yaml.v3"
)

// ReadIgnoreRulesFromFile reads CVE ignore rules from a YAML file
func ReadIgnoreRulesFromFile(path string) ([]IgnoreRule, error) {
	// Read file
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, xerrors.Errorf("failed to read ignore file: %w", err)
	}

	// Parse YAML
	var ignoreFile struct {
		IgnoreRules []IgnoreRule `yaml:"ignoreRules"`
	}
	if err := yaml.Unmarshal(data, &ignoreFile); err != nil {
		return nil, xerrors.Errorf("failed to parse ignore file: %w", err)
	}

	// Validate rules
	for i, rule := range ignoreFile.IgnoreRules {
		if rule.ID == "" {
			return nil, xerrors.Errorf("rule %d is missing ID", i)
		}
		if rule.Reason == "" {
			return nil, xerrors.Errorf("rule %d (%s) is missing reason", i, rule.ID)
		}
	}

	return ignoreFile.IgnoreRules, nil
}

// GenerateSBOMForPackage generates an SBOM for a package
func GenerateSBOMForPackage(pkg *leeway.Package, buildDir string, options *SBOMOptions) error {
	if options == nil {
		options = DefaultSBOMOptions()
	}

	// Determine output path if not specified
	outputPath := options.OutputPath
	if outputPath == "" {
		// Use default path in build directory
		version, err := pkg.Version()
		if err != nil {
			return xerrors.Errorf("failed to get package version: %w", err)
		}
		outputPath = filepath.Join(buildDir, fmt.Sprintf("%s-sbom.json", pkg.FilesystemSafeName()))
	}

	// Generate SBOM
	sbomDoc, err := GenerateSBOM(pkg, buildDir, options)
	if err != nil {
		return xerrors.Errorf("failed to generate SBOM: %w", err)
	}

	// Write SBOM to file
	if err := WriteSBOMToFile(sbomDoc, outputPath, options.Format); err != nil {
		return xerrors.Errorf("failed to write SBOM to file: %w", err)
	}

	log.WithFields(log.Fields{
		"package": pkg.FullName(),
		"path":    outputPath,
	}).Info("Generated SBOM")

	return nil
}

// ScanPackageForVulnerabilities scans a package for vulnerabilities
func ScanPackageForVulnerabilities(pkg *leeway.Package, buildDir string, sbomOptions *SBOMOptions, cveOptions *CVEOptions) error {
	if sbomOptions == nil {
		sbomOptions = DefaultSBOMOptions()
	}
	if cveOptions == nil {
		cveOptions = DefaultCVEOptions()
	}

	// Generate SBOM
	sbomDoc, err := GenerateSBOM(pkg, buildDir, sbomOptions)
	if err != nil {
		return xerrors.Errorf("failed to generate SBOM: %w", err)
	}

	// Scan for vulnerabilities
	report, err := ScanForVulnerabilities(sbomDoc, cveOptions)
	if err != nil {
		return xerrors.Errorf("failed to scan for vulnerabilities: %w", err)
	}

	// Determine output path if not specified
	outputPath := cveOptions.OutputPath
	if outputPath == "" {
		// Use default path in build directory
		version, err := pkg.Version()
		if err != nil {
			return xerrors.Errorf("failed to get package version: %w", err)
		}
		outputPath = filepath.Join(buildDir, fmt.Sprintf("%s-vulnerabilities.json", pkg.FilesystemSafeName()))
	}

	// Write report to file
	if err := report.WriteToFile(outputPath); err != nil {
		return xerrors.Errorf("failed to write vulnerability report: %w", err)
	}

	// Generate metadata
	metadata, err := GenerateScanMetadata(pkg, sbomOptions, cveOptions)
	if err != nil {
		return xerrors.Errorf("failed to generate scan metadata: %w", err)
	}

	// Write metadata to file
	metadataPath := filepath.Join(filepath.Dir(outputPath), fmt.Sprintf("%s-metadata.json", filepath.Base(outputPath[:len(outputPath)-5])))
	if err := WriteMetadataFile(metadataPath, metadata); err != nil {
		return xerrors.Errorf("failed to write metadata: %w", err)
	}

	// Write ignore file if there are ignore rules
	if len(cveOptions.IgnoreRules) > 0 {
		ignoreFilePath := filepath.Join(filepath.Dir(outputPath), fmt.Sprintf("%s-ignore.yaml", filepath.Base(outputPath[:len(outputPath)-5])))
		if err := WriteIgnoreFile(ignoreFilePath, cveOptions.IgnoreRules, metadata); err != nil {
			return xerrors.Errorf("failed to write ignore file: %w", err)
		}
		metadata.IgnoreFilePath = ignoreFilePath
	}

	// Check if there are vulnerabilities that should fail the build
	if report.HasFailureLevelVulnerabilities(cveOptions.FailOn) {
		// Format the report for display
		formattedReport := FormatVulnerabilityReport(report)
		log.Error(formattedReport)
		return xerrors.Errorf("vulnerabilities found with severity levels: %v", cveOptions.FailOn)
	}

	log.WithFields(log.Fields{
		"package": pkg.FullName(),
		"path":    outputPath,
	}).Info("Scanned for vulnerabilities")

	return nil
}
