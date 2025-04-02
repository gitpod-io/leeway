package leeway

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/anchore/clio"
	"github.com/anchore/grype/grype"
	"github.com/anchore/grype/grype/db/v6/distribution"
	"github.com/anchore/grype/grype/db/v6/installation"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/matcher"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/format/cyclonedxjson"
	"github.com/anchore/syft/syft/format/spdxjson"
	"github.com/anchore/syft/syft/format/syftjson"
	"github.com/anchore/syft/syft/sbom"
	log "github.com/sirupsen/logrus"
	"golang.org/x/xerrors"
)

// WorkspaceSBOM configures SBOM generation for a workspace
type WorkspaceSBOM struct {
	Enabled bool     `yaml:"enabled"`
	Format  string   `yaml:"format,omitempty"` // e.g., "cyclonedx", "spdx"
	ScanCVE bool     `yaml:"scanCVE"`
	FailOn  []string `yaml:"failOn,omitempty"` // e.g., ["CRITICAL", "HIGH"]
}

// writeSBOM produces an SBOM for a package and writes it to the build directory.
// It respects the SBOM configuration in the workspace and supports different SBOM formats.
func writeSBOM(p *Package, buildctx *buildContext, builddir string, buildStarted time.Time) (err error) {
	// Skip if SBOM generation is disabled
	if !p.C.W.SBOM.Enabled {
		return nil
	}

	logger := log.WithField("package", p.FullName())
	logger.Debug("Generating SBOM")

	// Get the source for SBOM generation
	src, err := syft.GetSource(context.Background(), builddir, nil)
	if err != nil {
		return xerrors.Errorf("failed to get source for SBOM generation: %w", err)
	}

	// Create SBOM configuration
	cfg := syft.DefaultCreateSBOMConfig()

	// Generate the SBOM
	s, err := syft.CreateSBOM(context.Background(), src, cfg)
	if err != nil {
		return xerrors.Errorf("failed to create SBOM: %w", err)
	}

	// Encode the SBOM
	// Get the requested format
	requestedFormat := strings.ToLower(p.C.W.SBOM.Format)
	if requestedFormat == "" {
		requestedFormat = "cyclonedx" // Default format - industry standard for security use cases
	}

	// Select the appropriate encoder
	var encoder sbom.FormatEncoder
	var fileExtension string
	switch requestedFormat {
	case "cyclonedx", "cyclonedx-json":
		encoder, err = cyclonedxjson.NewFormatEncoderWithConfig(cyclonedxjson.DefaultEncoderConfig())
		if err != nil {
			return xerrors.Errorf("failed to create CycloneDX encoder: %w", err)
		}
		fileExtension = "cdx.json"
	case "spdx", "spdx-json":
		encoder, err = spdxjson.NewFormatEncoderWithConfig(spdxjson.DefaultEncoderConfig())
		if err != nil {
			return xerrors.Errorf("failed to create SPDX encoder: %w", err)
		}
		fileExtension = "spdx.json"
	case "syft-json", "syft":
		encoder = syftjson.NewFormatEncoder()
		fileExtension = "json"
	default:
		logger.WithField("requested_format", requestedFormat).
			Debug("Requested SBOM format not supported, using cyclonedx format")
		requestedFormat = "cyclonedx"
		encoder, err = cyclonedxjson.NewFormatEncoderWithConfig(cyclonedxjson.DefaultEncoderConfig())
		if err != nil {
			return xerrors.Errorf("failed to create CycloneDX encoder: %w", err)
		}
		fileExtension = "cdx.json"
	}

	// Create a buffer to hold the encoded SBOM
	var buf bytes.Buffer
	if err := encoder.Encode(&buf, *s); err != nil {
		return xerrors.Errorf("failed to encode SBOM: %w", err)
	}
	data := buf.Bytes()

	// Write the SBOM to file
	fn := filepath.Join(builddir, "sbom."+fileExtension)
	err = os.WriteFile(fn, data, 0644)
	if err != nil {
		return xerrors.Errorf("failed to write SBOM to file: %w", err)
	}

	logger.WithField("format", requestedFormat).WithField("file", fn).Debug("SBOM generated successfully")
	return nil
}

// scanSBOMForVulnerabilities scans an SBOM for vulnerabilities using Grype
// and fails the build if vulnerabilities matching the FailOn configuration are found
func scanSBOMForVulnerabilities(p *Package, buildctx *buildContext, builddir string) (err error) {
	logger := log.WithField("package", p.FullName())
	logger.Debug("Scanning SBOM for vulnerabilities")

	// Skip if SBOM scanning is disabled
	if !p.C.W.SBOM.Enabled || !p.C.W.SBOM.ScanCVE {
		return nil
	}

	// Determine the SBOM file extension based on format
	fileExtension := getSBOMFileExtension(p.C.W.SBOM.Format)
	sbomFile := filepath.Join(builddir, "sbom."+fileExtension)

	if _, err := os.Stat(sbomFile); os.IsNotExist(err) {
		return xerrors.Errorf("SBOM file not found: %s", sbomFile)
	}

	// Load the vulnerability database
	vulnProvider, status, err := loadVulnerabilityDB()
	if err != nil {
		return fmt.Errorf("failed to load vulnerability database: %w", err)
	}
	defer vulnProvider.Close()

	fmt.Printf("Using vulnerability database at %s (built on %s)\n",
		status.Path, status.Built.Format("2006-01-02"))

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
		return fmt.Errorf("failed to parse SBOM: %w", err)
	}

	fmt.Printf("Found %d packages in SBOM\n", len(packages))

	// Create a vulnerability matcher
	matchers := matcher.NewDefaultMatchers(matcher.Config{})
	vulnMatcher := grype.VulnerabilityMatcher{
		VulnerabilityProvider: vulnProvider,
		Matchers:              matchers,
	}

	// Find vulnerability matches
	matches, ignoredMatches, err := vulnMatcher.FindMatches(packages, context)
	if err != nil {
		return fmt.Errorf("failed to find vulnerabilities: %w", err)
	}

	// Process the results
	fmt.Printf("Found %d vulnerabilities\n", matches.Count())
	if len(ignoredMatches) > 0 {
		fmt.Printf("Ignored %d vulnerabilities\n", len(ignoredMatches))
	}

	// Print vulnerability details
	printVulnerabilities(matches, vulnProvider)

	return nil
}

func loadVulnerabilityDB() (vulnerability.Provider, *vulnerability.ProviderStatus, error) {
	// Configure the vulnerability database
	distConfig := distribution.DefaultConfig()

	// Create a simple identification for the installation config
	id := clio.Identification{
		Name:    "leeway",
		Version: "0.1.0",
	}

	installConfig := installation.DefaultConfig(id)

	fmt.Println("Loading vulnerability database (this may take a moment on first run)...")

	// Load the vulnerability database with auto-update enabled
	// This will download the database if it doesn't exist
	return grype.LoadVulnerabilityDB(distConfig, installConfig, true)
}

// getSBOMFileExtension returns the file extension for the given SBOM format
func getSBOMFileExtension(format string) string {
	format = strings.ToLower(format)
	if format == "" {
		format = "cyclonedx" // Default format
	}

	switch format {
	case "cyclonedx", "cyclonedx-json":
		return "cdx.json"
	case "spdx", "spdx-json":
		return "spdx.json"
	case "syft-json", "syft":
		return "json"
	default:
		// Default to CycloneDX if format is unknown
		return "cdx.json"
	}
}

func printVulnerabilities(matches *match.Matches, provider vulnerability.Provider) {
	if matches.Count() == 0 {
		fmt.Println("No vulnerabilities found!")
		return
	}

	fmt.Println("\nVulnerability Report:")
	fmt.Println("=====================")

	for match := range matches.Enumerate() {
		metadata, err := provider.VulnerabilityMetadata(match.Vulnerability.Reference)
		if err != nil {
			fmt.Printf("Error getting metadata for %s: %v\n", match.Vulnerability.ID, err)
			continue
		}

		fmt.Printf("ID: %s\n", match.Vulnerability.ID)
		fmt.Printf("Package: %s@%s\n", match.Package.Name, match.Package.Version)
		fmt.Printf("Severity: %s\n", metadata.Severity)
		fmt.Printf("Description: %s\n", metadata.Description)

		if len(match.Vulnerability.Fix.Versions) > 0 {
			fmt.Printf("Fixed in: %v\n", match.Vulnerability.Fix.Versions)
		} else {
			fmt.Printf("Fix state: %s\n", match.Vulnerability.Fix.State)
		}

		fmt.Println("---------------------")
	}
}

// AccessSBOMInCachedArchive provides access to the SBOM in a cached build artifact.
// If no such SBOM exists, an error is returned.
func AccessSBOMInCachedArchive(fn string, handler func(sbom io.Reader) error) (err error) {
	// This is a placeholder for the actual implementation
	// We'll implement this function later

	return xerrors.Errorf("SBOM access is not yet implemented")
}
