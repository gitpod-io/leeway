package leeway

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"slices"

	"github.com/gitpod-io/leeway/pkg/leeway/cache"

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
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
	log "github.com/sirupsen/logrus"
	"golang.org/x/xerrors"
)

// PackageVulnerabilityStats represents vulnerability statistics for a package
type PackageVulnerabilityStats struct {
	Name       string `json:"name"`
	Critical   int    `json:"critical"`
	High       int    `json:"high"`
	Medium     int    `json:"medium"`
	Low        int    `json:"low"`
	Negligible int    `json:"negligible"`
	Unknown    int    `json:"unknown"`
	Total      int    `json:"total"`
	Ignored    int    `json:"ignored"`
}

// scanAllPackagesForVulnerabilities scans all packages for vulnerabilities.
// This function is called after the build process completes to identify security issues
// in all built packages, including those loaded from cache. It generates comprehensive
// vulnerability reports in multiple formats and collects statistics across all packages.
func scanAllPackagesForVulnerabilities(buildctx *buildContext, packages []*Package, customOutputDir ...string) error {
	if len(packages) == 0 {
		return nil
	}

	var failedPackages []string
	var allStats []*PackageVulnerabilityStats

	// Determine output directory - use custom dir if provided, otherwise create timestamped dir
	var outputDir string
	if len(customOutputDir) > 0 && customOutputDir[0] != "" {
		outputDir = customOutputDir[0]
	} else {
		timestamp := time.Now().Format("20060102-150405")
		outputDir = filepath.Join(GetDefaultVulnerabilityReportsDir(buildctx), timestamp)
	}

	if err := os.MkdirAll(outputDir, 0755); err != nil {
		errMsg := fmt.Sprintf("failed to create output directory %s: %s", outputDir, err)
		buildctx.Reporter.PackageBuildLog(nil, true, []byte(errMsg+"\n"))
		return xerrors.Errorf(errMsg)
	}

	// Process each package
	for _, p := range packages {
		if !p.C.W.SBOM.Enabled {
			errMsg := fmt.Append(nil, "SBOM feature is disabled, cannot scan for vulnerabilities")
			buildctx.Reporter.PackageBuildLog(p, false, errMsg)
			return xerrors.Errorf(string(errMsg))
		}

		location, exists := buildctx.LocalCache.Location(p)
		if !exists {
			errMsg := fmt.Appendf(nil, "Package %s not found in local cache, cannot scan for vulnerabilities\n", p.FullName())
			buildctx.Reporter.PackageBuildLog(p, false, errMsg)
			return xerrors.Errorf(string(errMsg))
		}

		// Create temporary file for SBOM content
		sbomFile, err := os.CreateTemp("", "leeway-sbom-*.cdx.json")
		if err != nil {
			errMsg := fmt.Sprintf("failed to create temporary file for SBOM: %s", err)
			buildctx.Reporter.PackageBuildLog(p, true, []byte(errMsg+"\n"))
			return xerrors.Errorf(errMsg)
		}
		sbomFilename := sbomFile.Name()
		if err := sbomFile.Close(); err != nil {
			buildctx.Reporter.PackageBuildLog(p, true, []byte("failed to close temporary file: "+err.Error()+"\n"))
		}
		defer func() {
			if err := os.Remove(sbomFilename); err != nil {
				buildctx.Reporter.PackageBuildLog(p, true, []byte("failed to remove temporary file: "+err.Error()+"\n"))
			}
		}()

		// Extract SBOM from package archive in CycloneDX format
		err = AccessSBOMInCachedArchive(location, "cyclonedx", writeFileHandler(sbomFilename))

		if err != nil {
			if err == ErrNoSBOMFile {
				errMsg := fmt.Sprintf("SBOM file not found in package archive for package %s", p.FullName())
				buildctx.Reporter.PackageBuildLog(p, true, []byte(errMsg+"\n"))
				return xerrors.Errorf(errMsg)
			}
			errMsg := fmt.Sprintf("Failed to extract SBOM from package archive for package %s: %s\n", p.FullName(), err.Error())
			buildctx.Reporter.PackageBuildLog(p, true, []byte(errMsg+"\n"))
			return xerrors.Errorf(errMsg)
		}

		// Scan for vulnerabilities
		stats, err := scanSBOMForVulnerabilities(buildctx, p, sbomFilename, outputDir)
		if err != nil {
			buildctx.Reporter.PackageBuildLog(p, false, fmt.Appendf(nil, "Failed to scan package %s for vulnerabilities: %s\n", p.FullName(), err.Error()))
			failedPackages = append(failedPackages, p.FullName())
			continue
		}

		if stats != nil {
			allStats = append(allStats, stats)
		}

		buildctx.Reporter.PackageBuildLog(p, false, fmt.Appendf(nil, "Vulnerability scan completed for package %s (reports: %s)\n", p.FullName(), outputDir))
	}

	// Report failures if any packages failed scanning
	if len(failedPackages) > 0 {
		errMsg := fmt.Sprintf("vulnerability scan failed for packages: %s", strings.Join(failedPackages, ", "))
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

	// Generate summary reports if we have statistics
	if len(allStats) > 0 {
		// Sort by severity (most severe first)
		slices.SortFunc(allStats, func(a, b *PackageVulnerabilityStats) int {
			if a.Critical != b.Critical {
				return b.Critical - a.Critical
			}
			if a.High != b.High {
				return b.High - a.High
			}
			if a.Medium != b.Medium {
				return b.Medium - a.Medium
			}
			if a.Low != b.Low {
				return b.Low - a.Low
			}
			if a.Negligible != b.Negligible {
				return b.Negligible - a.Negligible
			}
			if a.Unknown != b.Unknown {
				return b.Unknown - a.Unknown
			}
			return strings.Compare(a.Name, b.Name)
		})

		// Write summary reports
		if err := WritePackageVulnerabilityStats(outputDir, allStats); err != nil {
			log.WithError(err).Error("Failed to write vulnerability statistics to JSON file")
		}

		if err := WritePackageVulnerabilityMarkdown(outputDir, allStats); err != nil {
			log.WithError(err).Error("Failed to write vulnerability summary to Markdown file")
		}
	}

	return nil
}

// ScanAllPackagesForVulnerabilities provides a public API for scanning packages for vulnerabilities.
// It creates a build context with the provided local cache and reporter, then calls the internal
// scanAllPackagesForVulnerabilities function to perform the actual scanning.
func ScanAllPackagesForVulnerabilities(localCache cache.LocalCache, packages []*Package, customOutputDir ...string) error {
	buildctx := &buildContext{
		buildOptions: buildOptions{
			Reporter:   NewConsoleReporter(),
			LocalCache: localCache,
		},
	}

	return scanAllPackagesForVulnerabilities(buildctx, packages, customOutputDir...)
}

// scanSBOMForVulnerabilities scans an SBOM file for vulnerabilities and generates reports.
// This function can be called independently of the build process to analyze a specific SBOM file.
// It returns vulnerability statistics for the package and an error if the scan fails.
// The function handles loading the vulnerability database, parsing the SBOM, finding matches,
// and generating reports in multiple formats.
func scanSBOMForVulnerabilities(buildctx *buildContext, p *Package, sbomFile string, outputDir string) (stats *PackageVulnerabilityStats, err error) {
	if !p.C.W.SBOM.Enabled {
		return nil, xerrors.Errorf("SBOM feature is disabled, cannot scan for vulnerabilities")
	}

	buildctx.Reporter.PackageBuildLog(p, false, []byte("Scanning SBOM for vulnerabilities\n"))

	if _, err := os.Stat(sbomFile); os.IsNotExist(err) {
		errMsg := fmt.Sprintf("SBOM file not found: %s", sbomFile)
		buildctx.Reporter.PackageBuildLog(p, true, []byte(errMsg+"\n"))
		return nil, xerrors.Errorf(errMsg)
	}

	// Load vulnerability database
	vulnProvider, vulnProviderStatus, err := loadVulnerabilityDB(buildctx, p)
	if err != nil {
		errMsg := fmt.Sprintf("failed to load vulnerability database: %s", err)
		buildctx.Reporter.PackageBuildLog(p, true, []byte(errMsg+"\n"))
		return nil, xerrors.Errorf(errMsg)
	}
	defer func() {
		if closeErr := vulnProvider.Close(); closeErr != nil {
			buildctx.Reporter.PackageBuildLog(p, true, []byte("failed to close vulnerability provider: "+closeErr.Error()+"\n"))
		}
	}()

	buildctx.Reporter.PackageBuildLog(p, false, fmt.Appendf(nil, "Using vulnerability database (path: %s, built on: %s)\n",
		vulnProviderStatus.Path, vulnProviderStatus.Built.Format("2006-01-02")))

	// Parse SBOM file
	packages, context, err := parseSBOMFile(sbomFile)
	if err != nil {
		errMsg := fmt.Sprintf("failed to parse SBOM: %s", err)
		buildctx.Reporter.PackageBuildLog(p, true, []byte(errMsg+"\n"))
		return nil, xerrors.Errorf(errMsg)
	}

	buildctx.Reporter.PackageBuildLog(p, false, fmt.Appendf(nil, "Found packages in SBOM (count: %d)\n", len(packages)))

	// Combine workspace and package ignore rules
	ignoreRules := slices.Clone(p.C.W.SBOM.IgnoreVulnerabilities)
	ignoreRules = append(ignoreRules, p.SBOM.IgnoreVulnerabilities...)

	// Find vulnerabilities
	matches, ignoredMatches, err := findVulnerabilities(packages, context, vulnProvider, ignoreRules)
	if err != nil {
		errMsg := fmt.Sprintf("failed to find vulnerabilities: %s", err)
		buildctx.Reporter.PackageBuildLog(p, true, []byte(errMsg+"\n"))
		return nil, xerrors.Errorf(errMsg)
	}

	// Count vulnerabilities by severity
	severityCounts := make(map[string]int)
	for _, m := range matches.Sorted() {
		metadata, err := vulnProvider.VulnerabilityMetadata(m.Vulnerability.Reference)
		if err != nil {
			errMsg := fmt.Sprintf("failed to get vulnerability metadata: %s", err)
			buildctx.Reporter.PackageBuildLog(p, true, []byte(errMsg+"\n"))
			return nil, xerrors.Errorf(errMsg)
		}

		severity := strings.ToUpper(metadata.Severity)
		severityCounts[severity]++
	}

	// Create statistics object
	stats = &PackageVulnerabilityStats{
		Name:       p.FullName(),
		Critical:   severityCounts["CRITICAL"],
		High:       severityCounts["HIGH"],
		Medium:     severityCounts["MEDIUM"],
		Low:        severityCounts["LOW"],
		Negligible: severityCounts["NEGLIGIBLE"],
		Unknown:    severityCounts["UNKNOWN"],
		Total:      matches.Count(),
		Ignored:    len(ignoredMatches),
	}

	// Format severity details for logging
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

	// Create output directory
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		errMsg := fmt.Sprintf("failed to create output directory: %s", err)
		buildctx.Reporter.PackageBuildLog(p, true, []byte(errMsg+"\n"))
		return nil, xerrors.Errorf(errMsg)
	}

	baseFilename := p.FilesystemSafeName()

	// Generate vulnerability reports
	err = writeVulnerabilityResults(p, buildctx, outputDir, baseFilename, packages, context, matches, ignoredMatches, vulnProvider, vulnProviderStatus, ignoreRules)
	if err != nil {
		errMsg := fmt.Sprintf("failed to write vulnerability results: %s", err)
		buildctx.Reporter.PackageBuildLog(p, true, []byte(errMsg+"\n"))
		return nil, xerrors.Errorf(errMsg)
	}

	// Check if build should fail based on vulnerability severity
	if len(p.C.W.SBOM.FailOn) > 0 {
		var failedSeverities []string

		for _, failOnSeverity := range p.C.W.SBOM.FailOn {
			failOnSeverity = strings.ToUpper(failOnSeverity)
			if count, exists := severityCounts[failOnSeverity]; exists && count > 0 {
				failedSeverities = append(failedSeverities, fmt.Sprintf("%s (%d)", failOnSeverity, count))
			}
		}

		if len(failedSeverities) > 0 {
			errorMsg := fmt.Sprintf("build failed due to vulnerabilities with severity levels [%s] - see vulnerability reports for details",
				strings.Join(failedSeverities, ", "))
			buildctx.Reporter.PackageBuildLog(p, false, []byte(errorMsg+"\n"))
			return stats, xerrors.Errorf(errorMsg)
		}

		buildctx.Reporter.PackageBuildLog(p, false, fmt.Appendf(nil, "No vulnerabilities found at severity levels: %s\n",
			strings.Join(p.C.W.SBOM.FailOn, ", ")))
	}

	return stats, nil
}

// parseSBOMFile parses an SBOM file and returns the packages and context.
// It configures the provider to generate missing CPEs for better vulnerability matching.
func parseSBOMFile(sbomFile string) ([]pkg.Package, pkg.Context, error) {
	providerConfig := pkg.ProviderConfig{
		SynthesisConfig: pkg.SynthesisConfig{
			GenerateMissingCPEs: true,
		},
	}

	sbomInput := "sbom:" + sbomFile
	packages, context, _, err := pkg.Provide(sbomInput, providerConfig)
	if err != nil {
		return nil, pkg.Context{}, xerrors.Errorf("failed to parse SBOM: %w", err)
	}

	return packages, context, nil
}

// findVulnerabilities identifies vulnerabilities in the given packages using the provided
// vulnerability database and ignore rules. It returns matches, ignored matches, and any error.
func findVulnerabilities(packages []pkg.Package, context pkg.Context, vulnProvider vulnerability.Provider, ignoreRules []IgnoreRule) (*match.Matches, []match.IgnoredMatch, error) {
	matchers := matcher.NewDefaultMatchers(matcher.Config{})
	vulnMatcher := grype.VulnerabilityMatcher{
		VulnerabilityProvider: vulnProvider,
		Matchers:              matchers,
		IgnoreRules:           ignoreRules,
	}

	matches, ignoredMatches, err := vulnMatcher.FindMatches(packages, context)
	if err != nil {
		return nil, nil, xerrors.Errorf("failed to find vulnerabilities: %w", err)
	}

	return matches, ignoredMatches, nil
}

// writeVulnerabilityResults generates vulnerability reports in multiple formats.
// It creates a document model from the scan results and writes it to files in different formats:
// - JSON: Detailed vulnerability data
// - Table: Human-readable text format
// - CycloneDX: Standard SBOM format with vulnerabilities
// - SARIF: Static analysis format for integration with code analysis tools
func writeVulnerabilityResults(
	p *Package,
	buildctx *buildContext,
	dir string,
	baseFilename string,
	packages []pkg.Package,
	context pkg.Context,
	matches *match.Matches,
	ignoredMatches []match.IgnoredMatch,
	vulnProvider vulnerability.Provider,
	dbStatus *vulnerability.ProviderStatus,
	ignoreRules []IgnoreRule,
) error {
	// Create document model
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

	// Create minimal SBOM object
	sbomObj := &sbom.SBOM{
		Artifacts: sbom.Artifacts{
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

	// Common presenter configuration
	presenterConfig := models.PresenterConfig{
		ID:       clio.Identification{Name: "leeway", Version: Version},
		Document: model,
		SBOM:     sbomObj,
		Pretty:   true,
	}

	// Define output formats
	formats := []struct {
		name      string
		fileName  string
		presenter func(file *os.File) error
	}{
		{
			name:     "JSON",
			fileName: baseFilename + ".json",
			presenter: func(file *os.File) error {
				presenter := grypeJSON.NewPresenter(presenterConfig)
				return presenter.Present(file)
			},
		},
		{
			name:     "Table",
			fileName: baseFilename + ".txt",
			presenter: func(file *os.File) error {
				presenter := table.NewPresenter(presenterConfig, false)
				return presenter.Present(file)
			},
		},
		{
			name:     "CycloneDX",
			fileName: baseFilename + ".cdx.json",
			presenter: func(file *os.File) error {
				presenter := cyclonedx.NewJSONPresenter(presenterConfig)
				return presenter.Present(file)
			},
		},
		{
			name:     "SARIF",
			fileName: baseFilename + ".sarif",
			presenter: func(file *os.File) error {
				presenter := sarif.NewPresenter(presenterConfig)
				return presenter.Present(file)
			},
		},
	}

	// Generate each format
	for _, format := range formats {
		outputPath := filepath.Join(dir, format.fileName)

		file, err := os.Create(outputPath)
		if err != nil {
			return xerrors.Errorf("failed to create %s output file: %w", format.name, err)
		}

		if err := format.presenter(file); err != nil {
			closeErr := file.Close()
			if closeErr != nil {
				buildctx.Reporter.PackageBuildLog(p, true, []byte("failed to close file after presenter error: "+closeErr.Error()+"\n"))
			}
			return xerrors.Errorf("failed to write %s results: %w", format.name, err)
		}

		if err := file.Close(); err != nil {
			return xerrors.Errorf("failed to close %s output file: %w", format.name, err)
		}

		buildctx.Reporter.PackageBuildLog(p, false, fmt.Appendf(nil, "Wrote %s vulnerability results to %s\n", format.name, outputPath))
	}

	return nil
}

// GetDefaultVulnerabilityReportsDir returns the default directory for vulnerability reports.
// It checks the EnvvarVulnReportsDir environment variable first, and if not set,
// uses a directory in the build context's build directory.
func GetDefaultVulnerabilityReportsDir(ctx *buildContext) string {
	reportsDir := os.Getenv(EnvvarVulnReportsDir)
	if reportsDir == "" {
		reportsDir = filepath.Join(ctx.buildDir, "vulnerability-reports")
	}
	return reportsDir
}

// WritePackageVulnerabilityStats generates a JSON file with vulnerability statistics.
// This provides a machine-readable summary of vulnerabilities across all packages.
func WritePackageVulnerabilityStats(outputDir string, stats []*PackageVulnerabilityStats) error {
	outputPath := filepath.Join(outputDir, "vulnerability-stats.json")

	data, err := json.MarshalIndent(stats, "", "  ")
	if err != nil {
		return xerrors.Errorf("failed to marshal vulnerability statistics to JSON: %w", err)
	}

	if err := os.WriteFile(outputPath, data, 0644); err != nil {
		return xerrors.Errorf("failed to write vulnerability statistics to file: %w", err)
	}

	log.Infof("Wrote vulnerability statistics to %s", outputPath)
	return nil
}

// WritePackageVulnerabilityMarkdown generates a Markdown report with vulnerability statistics.
// This provides a human-readable summary with tables and emoji indicators for severity levels.
func WritePackageVulnerabilityMarkdown(outputDir string, stats []*PackageVulnerabilityStats) error {
	outputPath := filepath.Join(outputDir, "vulnerability-summary.md")

	// Calculate totals
	totalCritical := 0
	totalHigh := 0
	totalMedium := 0
	totalLow := 0
	totalNegligible := 0
	totalUnknown := 0
	totalVulnerabilities := 0
	totalIgnored := 0
	packagesWithVulnerabilities := 0

	for _, stat := range stats {
		totalCritical += stat.Critical
		totalHigh += stat.High
		totalMedium += stat.Medium
		totalLow += stat.Low
		totalNegligible += stat.Negligible
		totalUnknown += stat.Unknown
		totalVulnerabilities += stat.Total
		totalIgnored += stat.Ignored

		if stat.Total > 0 {
			packagesWithVulnerabilities++
		}
	}

	// Build Markdown content
	var md strings.Builder

	md.WriteString("# Vulnerability Scan Summary\n\n")
	md.WriteString(fmt.Sprintf("Scan completed on: %s\n\n", time.Now().Format("2006-01-02 15:04:05")))

	md.WriteString("## Overview\n\n")
	md.WriteString(fmt.Sprintf("Total packages scanned: %d\n", len(stats)))
	md.WriteString(fmt.Sprintf("Packages with vulnerabilities: %d\n\n", packagesWithVulnerabilities))

	md.WriteString("| Severity  | Count |\n")
	md.WriteString("|-----------|-------|\n")
	md.WriteString(fmt.Sprintf("| Critical  | %d     |\n", totalCritical))
	md.WriteString(fmt.Sprintf("| High      | %d     |\n", totalHigh))
	md.WriteString(fmt.Sprintf("| Medium    | %d     |\n", totalMedium))
	md.WriteString(fmt.Sprintf("| Low       | %d     |\n", totalLow))
	md.WriteString(fmt.Sprintf("| Negligible| %d     |\n", totalNegligible))
	md.WriteString(fmt.Sprintf("| Unknown   | %d     |\n", totalUnknown))
	md.WriteString(fmt.Sprintf("| **Total** | %d     |\n", totalVulnerabilities))
	md.WriteString("|-----------|-------|\n")
	md.WriteString(fmt.Sprintf("| *Ignored* | %d     |\n\n", totalIgnored))

	md.WriteString("## Package Details\n\n")
	md.WriteString("| Package | Critical | High | Medium | Low | Negligible | Unknown | Total | *Ignored* |\n")
	md.WriteString("|---------|----------|------|--------|-----|------------|---------|-------|-----------|\n")

	for _, stat := range stats {
		// Add emoji indicators for severity levels
		criticalStr := "⚪ 0"
		if stat.Critical > 0 {
			criticalStr = fmt.Sprintf("🔴 %d", stat.Critical)
		}

		highStr := "⚪ 0"
		if stat.High > 0 {
			highStr = fmt.Sprintf("🟠 %d", stat.High)
		}

		mediumStr := "⚪ 0"
		if stat.Medium > 0 {
			mediumStr = fmt.Sprintf("🟡 %d", stat.Medium)
		}

		lowStr := "⚪ 0"
		if stat.Low > 0 {
			lowStr = fmt.Sprintf("🟢 %d", stat.Low)
		}

		negligibleStr := fmt.Sprintf("⚪ %d", stat.Negligible)
		unknownStr := fmt.Sprintf("⚪ %d", stat.Unknown)

		ignoredStr := "⚪ 0"
		if stat.Ignored > 0 {
			ignoredStr = fmt.Sprintf("🔕 %d", stat.Ignored)
		}

		md.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s | %s | %s | %d | %s |\n",
			stat.Name, criticalStr, highStr, mediumStr, lowStr, negligibleStr, unknownStr, stat.Total, ignoredStr))
	}

	if err := os.WriteFile(outputPath, []byte(md.String()), 0644); err != nil {
		return xerrors.Errorf("failed to write vulnerability summary to file: %w", err)
	}

	log.Infof("Wrote vulnerability summary to %s", outputPath)
	return nil
}

// loadVulnerabilityDB initializes and loads the vulnerability database.
// It configures the database provider and handles downloading/updating the database if needed.
func loadVulnerabilityDB(buildctx *buildContext, p *Package) (vulnerability.Provider, *vulnerability.ProviderStatus, error) {
	distConfig := distribution.DefaultConfig()

	id := clio.Identification{
		Name:    "leeway",
		Version: Version,
	}

	installConfig := installation.DefaultConfig(id)

	buildctx.Reporter.PackageBuildLog(p, false, []byte("Loading vulnerability database (this may take a moment on first run) ...\n"))

	provider, status, err := grype.LoadVulnerabilityDB(distConfig, installConfig, true)
	if err != nil {
		return nil, nil, xerrors.Errorf("failed to load vulnerability database: %w", err)
	}

	return provider, status, nil
}
