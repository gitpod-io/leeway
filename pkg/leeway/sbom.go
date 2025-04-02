package leeway

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

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
	var s *sbom.SBOM
	if p.Type == DockerPackage {
		s, err = generateDockerSBOM(p, buildctx, builddir, cfg)
	} else {
		// For non-Docker packages, use the standard approach
		src, err := syft.GetSource(context.Background(), builddir, nil)
		if err != nil {
			return xerrors.Errorf("failed to get source for SBOM generation: %w", err)
		}

		// Generate the SBOM
		s, err = syft.CreateSBOM(context.Background(), src, cfg)
		if err != nil {
			return xerrors.Errorf("failed to create SBOM: %w", err)
		}
	}

	if err != nil {
		return xerrors.Errorf("failed to create SBOM: %w", err)
	}

	// Supported formats
	formats := []string{"cyclonedx", "spdx", "syft"}

	// Generate SBOM in all formats
	for _, format := range formats {
		// Get the encoder and file extension for the current format
		encoder, fileExtension, err := getSBOMEncoder(format)
		if err != nil {
			return xerrors.Errorf("failed to get SBOM encoder for format %s: %w", format, err)
		}

		// Create a buffer to hold the encoded SBOM
		var buf bytes.Buffer
		if err := encoder.Encode(&buf, *s); err != nil {
			return xerrors.Errorf("failed to encode SBOM in format %s: %w", format, err)
		}
		data := buf.Bytes()

		// Write the SBOM to file
		fn := filepath.Join(builddir, "sbom"+"."+fileExtension)
		err = os.WriteFile(fn, data, 0644)
		if err != nil {
			return xerrors.Errorf("failed to write SBOM to file %s: %w", fn, err)
		}

		buildctx.Reporter.PackageBuildLog(p, false, fmt.Appendf(nil, "SBOM generated successfully (format: %s, file: %s)\n", format, fn))
	}

	return nil
}

// generateDockerSBOM generates an SBOM specifically for Docker packages
func generateDockerSBOM(p *Package, buildctx *buildContext, builddir string, cfg *syft.CreateSBOMConfig) (*sbom.SBOM, error) {
	// Check if this is a Docker package with specified image names (pushed to registry)
	dockerCfg, ok := p.Config.(DockerPkgConfig)
	if !ok {
		return nil, xerrors.Errorf("package should have Docker config")
	}

	// Get the version which is used as the image tag during build
	version, err := p.Version()
	if err != nil {
		return nil, xerrors.Errorf("failed to get package version: %w", err)
	}

	if len(dockerCfg.Image) > 0 {
		// For pushed Docker images, analyze the image directly before it's pushed
		buildctx.Reporter.PackageBuildLog(p, false, []byte("Generating SBOM from Docker image\n"))

		// Use the daemon source to analyze the Docker image directly
		src, err := syft.GetSource(context.Background(), "docker:"+version, nil)
		if err != nil {
			return nil, xerrors.Errorf("failed to get Docker image source for SBOM generation: %w", err)
		}

		// Generate the SBOM from the Docker image
		return syft.CreateSBOM(context.Background(), src, cfg)
	} else {
		// For non-pushed Docker images, use the extracted container filesystem
		containerDir := filepath.Join(builddir, "container", "content")

		// Check if the container directory exists
		if _, err := os.Stat(containerDir); os.IsNotExist(err) {
			return nil, xerrors.Errorf("container directory not found at %s: %w", containerDir, err)
		}

		buildctx.Reporter.PackageBuildLog(p, false, []byte(fmt.Sprintf("Generating SBOM from extracted container filesystem at %s\n", containerDir)))

		// Use the directory source to analyze the extracted container filesystem
		src, err := syft.GetSource(context.Background(), containerDir, nil)
		if err != nil {
			return nil, xerrors.Errorf("failed to get container filesystem source for SBOM generation: %w", err)
		}

		// Generate the SBOM from the extracted container filesystem
		return syft.CreateSBOM(context.Background(), src, cfg)
	}
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

// scanSBOMForVulnerabilities scans an SBOM for vulnerabilities using Grype
// and fails the build if vulnerabilities matching the FailOn configuration are found
func scanSBOMForVulnerabilities(p *Package, buildctx *buildContext, builddir string) (err error) {
	// Skip if SBOM scanning is disabled
	if !p.C.W.SBOM.Enabled || !p.C.W.SBOM.ScanVulnerabilities {
		return nil
	}

	buildctx.Reporter.PackageBuildLog(p, false, []byte("Scanning SBOM for vulnerabilities\n"))

	// Always use CycloneDX format for vulnerability scanning
	fileExtension := "cdx.json"
	sbomFile := filepath.Join(builddir, "sbom"+"."+fileExtension)

	if _, err := os.Stat(sbomFile); os.IsNotExist(err) {
		return xerrors.Errorf("SBOM file not found: %s", sbomFile)
	}

	// Load the vulnerability database
	vulnProvider, vulnProviderStatus, err := loadVulnerabilityDB(p, buildctx)
	if err != nil {
		return xerrors.Errorf("failed to load vulnerability database: %w", err)
	}
	defer func() {
		if closeErr := vulnProvider.Close(); closeErr != nil {
			log.WithError(closeErr).Warn("failed to close vulnerability provider")
		}
	}()

	// Use the reporter to log the message with consistent formatting
	buildctx.Reporter.PackageBuildLog(p, false, fmt.Appendf(nil, "Using vulnerability database (path: %s, built on: %s)\n",
		vulnProviderStatus.Path, vulnProviderStatus.Built.Format("2006-01-02")))

	// Parse the SBOM file to get packages
	packages, context, err := parseSBOMFile(sbomFile)
	if err != nil {
		return xerrors.Errorf("failed to parse SBOM: %w", err)
	}

	// Use the reporter to log the message with consistent formatting
	buildctx.Reporter.PackageBuildLog(p, false, fmt.Appendf(nil, "Found packages in SBOM (count: %d)\n", len(packages)))

	// Combine workspace-level and package-level ignore rules
	ignoreRules := slices.Clone(p.C.W.SBOM.IgnoreVulnerabilities)
	ignoreRules = append(ignoreRules, p.SBOM.IgnoreVulnerabilities...)

	// Find vulnerability matches
	matches, ignoredMatches, err := findVulnerabilities(packages, context, vulnProvider, ignoreRules)
	if err != nil {
		return xerrors.Errorf("failed to find vulnerabilities: %w", err)
	}

	// Count vulnerabilities by severity
	severityCounts := make(map[string]int)

	// Process matches to count by severity
	for _, m := range matches.Sorted() {
		metadata, err := vulnProvider.VulnerabilityMetadata(m.Vulnerability.Reference)
		if err != nil {
			return xerrors.Errorf("failed to get vulnerability metadata: %w", err)
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

	// Use the reporter to log the message with consistent formatting
	severityInfo := ""
	if len(severityDetails) > 0 {
		severityInfo = ", " + strings.Join(severityDetails, ", ")
	}
	buildctx.Reporter.PackageBuildLog(p, true, fmt.Appendf(nil, "Vulnerability scan completed (total: %d, ignored: %d%s)\n",
		matches.Count(), len(ignoredMatches), severityInfo))

	// Write vulnerability results to files
	err = writeVulnerabilityResults(p, buildctx, builddir, packages, context, matches, ignoredMatches, vulnProvider, vulnProviderStatus, ignoreRules)
	if err != nil {
		return xerrors.Errorf("failed to write vulnerability results: %w", err)
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
				log.WithError(closeErr).Warn("failed to close file after presenter error")
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
