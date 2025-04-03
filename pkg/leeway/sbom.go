package leeway

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"slices"

	"github.com/anchore/clio"
	"github.com/anchore/grype/grype"
	"github.com/anchore/grype/grype/db/v6/distribution"
	"github.com/anchore/grype/grype/db/v6/installation"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/matcher"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/presenter/cyclonedx"
	grypeJSON "github.com/anchore/grype/grype/presenter/json"
	"github.com/anchore/grype/grype/presenter/models"
	"github.com/anchore/grype/grype/presenter/sarif"
	"github.com/anchore/grype/grype/presenter/table"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/format/cyclonedxjson"
	"github.com/anchore/syft/syft/format/spdxjson"
	"github.com/anchore/syft/syft/format/syftjson"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
	log "github.com/sirupsen/logrus"
	"golang.org/x/xerrors"
)

// Constants for SBOM and vulnerability scanning
const (
	// EnvvarVulnReportsDir names the environment variable we take the vulnerability reports directory location from
	EnvvarVulnReportsDir = "LEEWAY_VULN_REPORTS_DIR"

	// SBOM file format constants
	// sbomCycloneDXFilename is the name of the CycloneDX SBOM file we store in the archived build artifacts
	sbomCycloneDXFilename = "sbom.cdx.json"
	// sbomSPDXFilename is the name of the SPDX SBOM file we store in the archived build artifacts
	sbomSPDXFilename = "sbom.spdx.json"
	// sbomSyftFilename is the name of the Syft SBOM file we store in the archived build artifacts
	sbomSyftFilename = "sbom.json"
)

// IgnoreRulePackage is an alias for match.IgnoreRulePackage
// It describes package-specific fields for ignore rules:
// - name: Package name (supports regex)
// - version: Package version
// - language: Package language
// - type: Package type
// - location: Package location (supports glob patterns)
// - upstream-name: Upstream package name (supports regex)
type IgnoreRulePackage = match.IgnoreRulePackage

// IgnoreRule is an alias for match.IgnoreRule
// It allows specifying criteria for ignoring vulnerabilities during SBOM scanning.
// Available fields:
// - vulnerability: The vulnerability ID to ignore (e.g., "CVE-2023-1234")
// - reason: The reason for ignoring this vulnerability
// - namespace: The vulnerability namespace (e.g., "github:golang")
// - fix-state: The fix state to match (e.g., "fixed", "not-fixed", "unknown")
// - package: Package-specific criteria (see IgnoreRulePackage)
// - vex-status: VEX status (e.g., "affected", "fixed", "not_affected")
// - vex-justification: Justification for the VEX status
// - match-type: The type of match to ignore (e.g., "exact-direct-dependency")
type IgnoreRule = match.IgnoreRule

// WorkspaceSBOM configures SBOM generation for a workspace
type WorkspaceSBOM struct {
	Enabled               bool         `yaml:"enabled"`
	ScanVulnerabilities   bool         `yaml:"scanVulnerabilities"`
	FailOn                []string     `yaml:"failOn,omitempty"`                // e.g., ["CRITICAL", "HIGH"]
	IgnoreVulnerabilities []IgnoreRule `yaml:"ignoreVulnerabilities,omitempty"` // Workspace-level ignore rules
}

// PackageSBOM configures SBOM generation for a package
type PackageSBOM struct {
	IgnoreVulnerabilities []IgnoreRule `yaml:"ignoreVulnerabilities,omitempty"` // Package-level ignore rules
}

// writeSBOM produces SBOMs for a package in all supported formats and writes them to the build directory.
func writeSBOM(p *Package, buildctx *buildContext, builddir string) (err error) {
	// Skip if SBOM generation is disabled
	if !p.C.W.SBOM.Enabled {
		return nil
	}

	// Create SBOM configuration
	cfg := syft.DefaultCreateSBOMConfig()

	// Get the source for SBOM generation based on package type
	var src source.Source
	if p.Type == DockerPackage {
		// For Docker images, analyze the image directly
		buildctx.Reporter.PackageBuildLog(p, false, []byte("Generating SBOM from Docker image\n"))

		// Get the version which is used as the image tag during build
		version, err := p.Version()
		if err != nil {
			return xerrors.Errorf("failed to get package version: %w", err)
		}

		// Use the daemon source to analyze the Docker image directly
		src, err = syft.GetSource(context.Background(), version, nil)
		if err != nil {
			return xerrors.Errorf("failed to get Docker image source for SBOM generation: %w", err)
		}
	} else {
		// For non-Docker packages, scan filesystem
		buildctx.Reporter.PackageBuildLog(p, false, []byte("Generating SBOM from filesystem\n"))

		src, err = syft.GetSource(context.Background(), builddir, nil)
		if err != nil {
			errMsg := fmt.Sprintf("failed to get source for SBOM generation: %s", err)
			buildctx.Reporter.PackageBuildLog(p, true, []byte(errMsg+"\n"))
			return xerrors.Errorf(errMsg)
		}
	}

	// Generate the SBOM
	s, err := syft.CreateSBOM(context.Background(), src, cfg)
	if err != nil {
		errMsg := fmt.Sprintf("failed to create SBOM: %s", err)
		buildctx.Reporter.PackageBuildLog(p, true, []byte(errMsg+"\n"))
		return xerrors.Errorf(errMsg)
	}

	if err != nil {
		errMsg := fmt.Sprintf("failed to create SBOM: %s", err)
		buildctx.Reporter.PackageBuildLog(p, true, []byte(errMsg+"\n"))
		return xerrors.Errorf(errMsg)
	}

	// Supported formats
	formats := []string{"cyclonedx", "spdx", "syft"}

	// Generate SBOM in all formats
	for _, format := range formats {
		// Get the encoder and file extension for the current format
		encoder, fileExtension, err := getSBOMEncoder(format)
		if err != nil {
			errMsg := fmt.Sprintf("failed to get SBOM encoder for format %s: %s", format, err)
			buildctx.Reporter.PackageBuildLog(p, true, []byte(errMsg+"\n"))
			return xerrors.Errorf(errMsg)
		}

		// Create a buffer to hold the encoded SBOM
		var buf bytes.Buffer
		if err := encoder.Encode(&buf, *s); err != nil {
			errMsg := fmt.Sprintf("failed to encode SBOM in format %s: %s", format, err)
			buildctx.Reporter.PackageBuildLog(p, true, []byte(errMsg+"\n"))
			return xerrors.Errorf(errMsg)
		}
		data := buf.Bytes()

		// Write the SBOM to file
		fn := filepath.Join(builddir, "sbom"+"."+fileExtension)
		err = os.WriteFile(fn, data, 0644)
		if err != nil {
			errMsg := fmt.Sprintf("failed to write SBOM to file %s: %s", fn, err)
			buildctx.Reporter.PackageBuildLog(p, true, []byte(errMsg+"\n"))
			return xerrors.Errorf(errMsg)
		}

		buildctx.Reporter.PackageBuildLog(p, false, fmt.Appendf(nil, "SBOM generated successfully (format: %s, file: %s)\n", format, fn))
	}

	return nil
}

// getSBOMEncoder returns the appropriate encoder and file extension for the given SBOM format
func getSBOMEncoder(format string) (encoder sbom.FormatEncoder, fileExtension string, err error) {
	switch format {
	case "cyclonedx":
		encoder, err = cyclonedxjson.NewFormatEncoderWithConfig(cyclonedxjson.DefaultEncoderConfig())
		if err != nil {
			return nil, "", xerrors.Errorf("failed to create CycloneDX encoder: %w", err)
		}
		fileExtension = "cdx.json"
	case "spdx":
		encoder, err = spdxjson.NewFormatEncoderWithConfig(spdxjson.DefaultEncoderConfig())
		if err != nil {
			return nil, "", xerrors.Errorf("failed to create SPDX encoder: %w", err)
		}
		fileExtension = "spdx.json"
	case "syft":
		encoder = syftjson.NewFormatEncoder()
		fileExtension = "json"
	default:
		return nil, "", xerrors.Errorf("unsupported SBOM format: %s", format)
	}

	return encoder, fileExtension, nil
}

// VulnerabilityReportLocation represents the location of vulnerability reports
type VulnerabilityReportLocation struct {
	// Directory is the base directory for all vulnerability reports
	Directory string
	// Timestamp is the timestamp for this scan run
	Timestamp string
	// PackageDir is the directory for a specific package's vulnerability reports
	PackageDir string
}

// GetVulnerabilityReportsDir returns the directory where vulnerability reports should be stored
func GetVulnerabilityReportsDir() string {
	reportsDir := os.Getenv(EnvvarVulnReportsDir)
	if reportsDir == "" {
		buildDir := os.Getenv(EnvvarBuildDir)
		if buildDir == "" {
			buildDir = filepath.Join(os.TempDir(), "leeway", "build")
		}
		reportsDir = filepath.Join(buildDir, "vulnerability-reports")
	}
	return reportsDir
}

// GetVulnerabilityReportLocation returns the location for vulnerability reports for a specific package
func GetVulnerabilityReportLocation(p *Package, timestamp string) VulnerabilityReportLocation {
	baseDir := GetVulnerabilityReportsDir()
	timestampDir := filepath.Join(baseDir, timestamp)
	packageDir := filepath.Join(timestampDir, p.FilesystemSafeName())

	return VulnerabilityReportLocation{
		Directory:  baseDir,
		Timestamp:  timestamp,
		PackageDir: packageDir,
	}
}

// ScanPackageForVulnerabilities scans an SBOM for vulnerabilities and writes the results to the specified output directory
// This function can be called independently of the build process
func ScanPackageForVulnerabilities(p *Package, buildctx *buildContext, sbomFile string, outputDir string) (err error) {
	// Skip if SBOM scanning is disabled at the workspace level
	if !p.C.W.SBOM.Enabled || !p.C.W.SBOM.ScanVulnerabilities {
		return nil
	}

	buildctx.Reporter.PackageBuildLog(p, false, []byte("Scanning SBOM for vulnerabilities\n"))

	if _, err := os.Stat(sbomFile); os.IsNotExist(err) {
		errMsg := fmt.Sprintf("SBOM file not found: %s", sbomFile)
		buildctx.Reporter.PackageBuildLog(p, true, []byte(errMsg+"\n"))
		return xerrors.Errorf(errMsg)
	}

	// Load the vulnerability database
	vulnProvider, vulnProviderStatus, err := loadVulnerabilityDB(p, buildctx)
	if err != nil {
		errMsg := fmt.Sprintf("failed to load vulnerability database: %s", err)
		buildctx.Reporter.PackageBuildLog(p, true, []byte(errMsg+"\n"))
		return xerrors.Errorf(errMsg)
	}
	defer func() {
		if closeErr := vulnProvider.Close(); closeErr != nil {
			buildctx.Reporter.PackageBuildLog(p, true, []byte("failed to close vulnerability provider: "+closeErr.Error()+"\n"))
		}
	}()

	buildctx.Reporter.PackageBuildLog(p, false, fmt.Appendf(nil, "Using vulnerability database (path: %s, built on: %s)\n",
		vulnProviderStatus.Path, vulnProviderStatus.Built.Format("2006-01-02")))

	// Parse the SBOM file to get packages
	packages, context, err := parseSBOMFile(sbomFile)
	if err != nil {
		errMsg := fmt.Sprintf("failed to parse SBOM: %s", err)
		buildctx.Reporter.PackageBuildLog(p, true, []byte(errMsg+"\n"))
		return xerrors.Errorf(errMsg)
	}

	buildctx.Reporter.PackageBuildLog(p, false, fmt.Appendf(nil, "Found packages in SBOM (count: %d)\n", len(packages)))

	// Combine workspace-level and package-level ignore rules
	ignoreRules := slices.Clone(p.C.W.SBOM.IgnoreVulnerabilities)
	ignoreRules = append(ignoreRules, p.SBOM.IgnoreVulnerabilities...)

	// Find vulnerability matches
	matches, ignoredMatches, err := findVulnerabilities(packages, context, vulnProvider, ignoreRules)
	if err != nil {
		errMsg := fmt.Sprintf("failed to find vulnerabilities: %s", err)
		buildctx.Reporter.PackageBuildLog(p, true, []byte(errMsg+"\n"))
		return xerrors.Errorf(errMsg)
	}

	// Count vulnerabilities by severity
	severityCounts := make(map[string]int)

	// Process matches to count by severity
	for _, m := range matches.Sorted() {
		metadata, err := vulnProvider.VulnerabilityMetadata(m.Vulnerability.Reference)
		if err != nil {
			errMsg := fmt.Sprintf("failed to get vulnerability metadata: %s", err)
			buildctx.Reporter.PackageBuildLog(p, true, []byte(errMsg+"\n"))
			return xerrors.Errorf(errMsg)
		}

		severity := strings.ToUpper(metadata.Severity)
		severityCounts[severity]++
	}

	// Build severity counts string for logging
	var severityDetails []string
	for _, severity := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE", "UNKNOWN"} {
		if count, exists := severityCounts[severity]; exists && count > 0 {
			severityDetails = append(severityDetails, fmt.Sprintf("%s: %d", strings.ToLower(severity), count))
		}
	}

	severityInfo := ""
	if len(severityDetails) > 0 {
		severityInfo = ", " + strings.Join(severityDetails, ", ")
	}
	buildctx.Reporter.PackageBuildLog(p, true, fmt.Appendf(nil, "Vulnerability scan completed (total: %d, ignored: %d%s)\n",
		matches.Count(), len(ignoredMatches), severityInfo))

	// Ensure the output directory exists
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		errMsg := fmt.Sprintf("failed to create output directory: %s", err)
		buildctx.Reporter.PackageBuildLog(p, true, []byte(errMsg+"\n"))
		return xerrors.Errorf(errMsg)
	}

	// Write vulnerability results to files
	err = writeVulnerabilityResults(p, buildctx, outputDir, packages, context, matches, ignoredMatches, vulnProvider, vulnProviderStatus, ignoreRules)
	if err != nil {
		errMsg := fmt.Sprintf("failed to write vulnerability results: %s", err)
		buildctx.Reporter.PackageBuildLog(p, true, []byte(errMsg+"\n"))
		return xerrors.Errorf(errMsg)
	}

	// Let build fail when vulnerabilities are found
	if len(p.C.W.SBOM.FailOn) > 0 {
		var failedSeverities []string

		// Check if any severity level in FailOn has vulnerabilities
		for _, failOnSeverity := range p.C.W.SBOM.FailOn {
			failOnSeverity = strings.ToUpper(failOnSeverity)
			if count, exists := severityCounts[failOnSeverity]; exists && count > 0 {
				failedSeverities = append(failedSeverities, fmt.Sprintf("%s (%d)", failOnSeverity, count))
			}
		}

		// If we have any failing severities, return an error
		if len(failedSeverities) > 0 {
			errorMsg := fmt.Sprintf("build failed due to vulnerabilities with severity levels [%s] - see vulnerability reports for details",
				strings.Join(failedSeverities, ", "))
			buildctx.Reporter.PackageBuildLog(p, false, []byte(errorMsg+"\n"))
			return xerrors.Errorf(errorMsg)
		}

		// Log that we checked but found no vulnerabilities at the specified severity levels
		buildctx.Reporter.PackageBuildLog(p, false, fmt.Appendf(nil, "No vulnerabilities found at severity levels: %s\n",
			strings.Join(p.C.W.SBOM.FailOn, ", ")))
	}

	return nil
}

// ScanAllPackagesForVulnerabilities scans all packages for vulnerabilities
// This function is called after the build process completes
func ScanAllPackagesForVulnerabilities(buildctx *buildContext, packages []*Package) error {
	// Skip if no packages to scan
	if len(packages) == 0 {
		return nil
	}

	// Create a timestamp for this scan run
	timestamp := time.Now().Format("20060102-150405")

	// Track failed packages
	var failedPackages []string

	// Scan each package
	for _, p := range packages {
		// Skip if SBOM is disabled for this package
		if !p.C.W.SBOM.Enabled || !p.C.W.SBOM.ScanVulnerabilities {
			continue
		}

		// Get the location for this package's vulnerability reports
		reportLocation := GetVulnerabilityReportLocation(p, timestamp)

		// Create the directory for this package's vulnerability reports
		if err := os.MkdirAll(reportLocation.PackageDir, 0755); err != nil {
			errMsg := fmt.Sprintf("failed to create vulnerability reports directory for package %s: %s", p.FullName(), err)
			buildctx.Reporter.PackageBuildLog(p, true, []byte(errMsg+"\n"))
			return xerrors.Errorf(errMsg)
		}

		// Find the SBOM file for this package
		sbomFile := ""

		// Check if the package is in the local cache
		if location, exists := buildctx.LocalCache.Location(p); exists {
			// Create a temporary file to store the SBOM content
			tempFile, err := os.CreateTemp("", "leeway-sbom-*.cdx.json")
			if err != nil {
				errMsg := fmt.Sprintf("failed to create temporary file for SBOM: %s", err)
				buildctx.Reporter.PackageBuildLog(p, true, []byte(errMsg+"\n"))
				return xerrors.Errorf(errMsg)
			}
			tempFileName := tempFile.Name()
			if err := tempFile.Close(); err != nil { // Close it now, we'll reopen it for writing
				buildctx.Reporter.PackageBuildLog(p, true, []byte("failed to close temporary file: "+err.Error()+"\n"))
			}
			defer func() {
				if err := os.Remove(tempFileName); err != nil {
					buildctx.Reporter.PackageBuildLog(p, true, []byte("failed to remove temporary file: "+err.Error()+"\n"))
				}
			}()

			// Extract the SBOM file directly from the package archive
			err = AccessSBOMInCachedArchive(location, func(sbomReader io.Reader) error {
				// Copy the SBOM content to the temporary file
				sbomFile, err := os.OpenFile(tempFileName, os.O_WRONLY, 0644)
				if err != nil {
					return xerrors.Errorf("failed to open temporary file for writing: %w", err)
				}
				defer func() {
					if err := sbomFile.Close(); err != nil {
						buildctx.Reporter.PackageBuildLog(p, false, []byte("failed to close SBOM file: "+err.Error()+"\n"))
					}
				}()

				_, err = io.Copy(sbomFile, sbomReader)
				if err != nil {
					return xerrors.Errorf("failed to write SBOM content to temporary file: %w", err)
				}
				return nil
			})

			if err != nil {
				if err == ErrNoSBOMFile {
					errMsg := fmt.Sprintf("SBOM file not found in package archive for package %s", p.FullName())
					buildctx.Reporter.PackageBuildLog(p, true, []byte(errMsg+"\n"))
					return xerrors.Errorf(errMsg)
				}
				errMsg := fmt.Sprintf("Failed to extract SBOM from package archive, skipping vulnerability scan for package %s: %s\n", p.FullName(), err.Error())
				buildctx.Reporter.PackageBuildLog(p, true, []byte(errMsg+"\n"))
				return xerrors.Errorf(errMsg)
			}

			// Set the SBOM file path to the temporary file
			sbomFile = tempFileName
		} else {
			buildctx.Reporter.PackageBuildLog(p, false, fmt.Appendf(nil, "Package %s not found in local cache, skipping vulnerability scan\n", p.FullName()))
			continue
		}

		// Scan the package for vulnerabilities
		if err := ScanPackageForVulnerabilities(p, buildctx, sbomFile, reportLocation.PackageDir); err != nil {
			buildctx.Reporter.PackageBuildLog(p, false, fmt.Appendf(nil, "Failed to scan package %s for vulnerabilities: %s\n", p.FullName(), err.Error()))
			// Add to failed packages
			failedPackages = append(failedPackages, p.FullName())
			continue
		}

		buildctx.Reporter.PackageBuildLog(p, false, fmt.Appendf(nil, "Vulnerability scan completed for package %s (reports: %s)\n", p.FullName(), reportLocation.PackageDir))
	}

	// Return error if any packages failed due to vulnerabilities
	if len(failedPackages) > 0 {
		errMsg := fmt.Sprintf("vulnerability scan failed for packages: %s", strings.Join(failedPackages, ", "))
		// We don't have a specific package to log to, so we'll use the first failed package
		if len(failedPackages) > 0 {
			for _, pkg := range packages {
				if pkg.FullName() == failedPackages[0] {
					buildctx.Reporter.PackageBuildLog(pkg, true, []byte(errMsg+"\n"))
					break
				}
			}
		}
		return xerrors.Errorf(errMsg)
	}

	return nil
}

// parseSBOMFile parses an SBOM file and returns the packages and context
func parseSBOMFile(sbomFile string) ([]pkg.Package, pkg.Context, error) {
	// Create provider config
	providerConfig := pkg.ProviderConfig{
		SynthesisConfig: pkg.SynthesisConfig{
			GenerateMissingCPEs: true,
		},
	}

	// Parse the SBOM file to get packages
	sbomInput := "sbom:" + sbomFile
	packages, context, _, err := pkg.Provide(sbomInput, providerConfig)
	if err != nil {
		return nil, pkg.Context{}, xerrors.Errorf("failed to parse SBOM: %w", err)
	}

	return packages, context, nil
}

// findVulnerabilities finds vulnerabilities in the given packages
func findVulnerabilities(packages []pkg.Package, context pkg.Context, vulnProvider vulnerability.Provider, ignoreRules []IgnoreRule) (*match.Matches, []match.IgnoredMatch, error) {
	// Create a vulnerability matcher with the ignore rules
	matchers := matcher.NewDefaultMatchers(matcher.Config{})
	vulnMatcher := grype.VulnerabilityMatcher{
		VulnerabilityProvider: vulnProvider,
		Matchers:              matchers,
		IgnoreRules:           ignoreRules,
	}

	// Find vulnerability matches
	matches, ignoredMatches, err := vulnMatcher.FindMatches(packages, context)
	if err != nil {
		return nil, nil, xerrors.Errorf("failed to find vulnerabilities: %w", err)
	}

	return matches, ignoredMatches, nil
}

// writeVulnerabilityResults writes vulnerability results in multiple formats to separate files
func writeVulnerabilityResults(
	p *Package,
	buildctx *buildContext,
	builddir string,
	packages []pkg.Package,
	context pkg.Context,
	matches *match.Matches,
	ignoredMatches []match.IgnoredMatch,
	vulnProvider vulnerability.Provider,
	dbStatus *vulnerability.ProviderStatus,
	ignoreRules []IgnoreRule,
) error {
	// Create a document model
	model, err := models.NewDocument(
		clio.Identification{Name: "leeway", Version: Version},
		packages,
		context,
		*matches,
		ignoredMatches,
		vulnProvider,
		struct {
			Ignore []IgnoreRule `json:"ignore"`
		}{Ignore: ignoreRules},
		dbStatus,
		models.SortByPackage,
	)
	if err != nil {
		return xerrors.Errorf("failed to create document model: %w", err)
	}

	// Create a minimal SBOM object for the presenters that require it
	sbomObj := &sbom.SBOM{
		Artifacts: sbom.Artifacts{
			// We don't need to populate the Packages field for our use case
			Packages: nil,
		},
		Relationships: []artifact.Relationship{},
		Source: source.Description{
			Name: "leeway",
		},
		Descriptor: sbom.Descriptor{
			Name:    "leeway",
			Version: Version,
		},
	}

	// Common presenter config
	presenterConfig := models.PresenterConfig{
		ID:       clio.Identification{Name: "leeway", Version: Version},
		Document: model,
		SBOM:     sbomObj,
		Pretty:   true,
	}

	// Define the formats and their corresponding file names
	formats := []struct {
		name      string
		fileName  string
		presenter func(file *os.File) error
	}{
		{
			name:     "JSON",
			fileName: "vulnerabilities.json",
			presenter: func(file *os.File) error {
				presenter := grypeJSON.NewPresenter(presenterConfig)
				return presenter.Present(file)
			},
		},
		{
			name:     "Table",
			fileName: "vulnerabilities.txt",
			presenter: func(file *os.File) error {
				presenter := table.NewPresenter(presenterConfig, false) // false = don't show suppressed
				return presenter.Present(file)
			},
		},
		{
			name:     "CycloneDX",
			fileName: "vulnerabilities.cdx.json",
			presenter: func(file *os.File) error {
				presenter := cyclonedx.NewJSONPresenter(presenterConfig)
				return presenter.Present(file)
			},
		},
		{
			name:     "SARIF",
			fileName: "vulnerabilities.sarif",
			presenter: func(file *os.File) error {
				presenter := sarif.NewPresenter(presenterConfig)
				return presenter.Present(file)
			},
		},
	}

	// Write each format to its file
	for _, format := range formats {
		outputPath := filepath.Join(builddir, format.fileName)

		// Create the output file
		file, err := os.Create(outputPath)
		if err != nil {
			return xerrors.Errorf("failed to create %s output file: %w", format.name, err)
		}

		// Write the results using the appropriate presenter
		if err := format.presenter(file); err != nil {
			closeErr := file.Close() // Close the file before returning error
			if closeErr != nil {
				buildctx.Reporter.PackageBuildLog(p, true, []byte("failed to close file after presenter error: "+closeErr.Error()+"\n"))
			}
			return xerrors.Errorf("failed to write %s results: %w", format.name, err)
		}

		// Close the file
		if err := file.Close(); err != nil {
			return xerrors.Errorf("failed to close %s output file: %w", format.name, err)
		}

		// Log the output path
		buildctx.Reporter.PackageBuildLog(p, false, fmt.Appendf(nil, "Wrote %s vulnerability results to %s\n", format.name, outputPath))
	}

	return nil
}

// loadVulnerabilityDB loads the vulnerability database
func loadVulnerabilityDB(p *Package, buildctx *buildContext) (vulnerability.Provider, *vulnerability.ProviderStatus, error) {
	// Configure the vulnerability database
	distConfig := distribution.DefaultConfig()

	// Create a simple identification for the installation config
	id := clio.Identification{
		Name:    "leeway",
		Version: Version,
	}

	installConfig := installation.DefaultConfig(id)

	buildctx.Reporter.PackageBuildLog(p, false, []byte("Loading vulnerability database (this may take a moment on first run) ...\n"))

	// Load the vulnerability database with auto-update enabled
	// This will download the database if it doesn't exist
	provider, status, err := grype.LoadVulnerabilityDB(distConfig, installConfig, true)
	if err != nil {
		return nil, nil, xerrors.Errorf("failed to load vulnerability database: %w", err)
	}

	return provider, status, nil
}

// ErrNoSBOMFile is returned when no SBOM file is found in a cached archive
var ErrNoSBOMFile = fmt.Errorf("no SBOM file found")

// AccessSBOMInCachedArchive provides access to the SBOM file in a cached build artifact.
// If no such file exists, ErrNoSBOMFile is returned.
func AccessSBOMInCachedArchive(fn string, handler func(sbomFile io.Reader) error) (err error) {
	defer func() {
		if err != nil && err != ErrNoSBOMFile {
			err = fmt.Errorf("error extracting SBOM from %s: %w", fn, err)
		}
	}()

	f, err := os.Open(fn)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := f.Close(); closeErr != nil {
			log.WithError(closeErr).Warn("failed to close file during SBOM extraction")
		}
	}()

	g, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := g.Close(); closeErr != nil {
			log.WithError(closeErr).Warn("failed to close gzip reader")
		}
	}()

	var sbomFound bool
	a := tar.NewReader(g)
	var hdr *tar.Header
	for {
		hdr, err = a.Next()
		if err == io.EOF {
			err = nil
			break
		}
		if err != nil {
			break
		}

		if !strings.HasSuffix(hdr.Name, sbomCycloneDXFilename) {
			continue
		}

		err = handler(io.LimitReader(a, hdr.Size))
		if err != nil {
			return err
		}
		sbomFound = true
		break
	}
	if err != nil {
		return
	}

	if !sbomFound {
		return ErrNoSBOMFile
	}

	return nil
}
