package leeway

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
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

const (
	// sbomFilename is the base name of the SBOM file we store in the build artifacts
	sbomFilename = "sbom"

	// filePermissions is the permission used for writing SBOM files
	filePermissions = 0644
)

// WorkspaceSBOM configures SBOM generation for a workspace
type WorkspaceSBOM struct {
	Enabled bool     `yaml:"enabled"`
	ScanCVE bool     `yaml:"scanCVE"`
	FailOn  []string `yaml:"failOn,omitempty"` // e.g., ["CRITICAL", "HIGH"]
}

// writeSBOM produces SBOMs for a package in all supported formats and writes them to the build directory.
func writeSBOM(p *Package, buildctx *buildContext, builddir string, buildStarted time.Time) (err error) {
	// Skip if SBOM generation is disabled
	if !p.C.W.SBOM.Enabled {
		return nil
	}

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
		fn := filepath.Join(builddir, sbomFilename+"."+fileExtension)
		err = os.WriteFile(fn, data, filePermissions)
		if err != nil {
			return xerrors.Errorf("failed to write SBOM to file %s: %w", fn, err)
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

// scanSBOMForVulnerabilities scans an SBOM for vulnerabilities using Grype
// and fails the build if vulnerabilities matching the FailOn configuration are found
func scanSBOMForVulnerabilities(p *Package, buildctx *buildContext, builddir string) (err error) {
	// Skip if SBOM scanning is disabled
	if !p.C.W.SBOM.Enabled || !p.C.W.SBOM.ScanCVE {
		return nil
	}

	buildctx.Reporter.PackageBuildLog(p, false, []byte("Scanning SBOM for vulnerabilities\n"))

	// Always use CycloneDX format for vulnerability scanning
	fileExtension := "cdx.json"
	sbomFile := filepath.Join(builddir, sbomFilename+"."+fileExtension)

	if _, err := os.Stat(sbomFile); os.IsNotExist(err) {
		return xerrors.Errorf("SBOM file not found: %s", sbomFile)
	}

	// Load the vulnerability database
	vulnProvider, status, err := loadVulnerabilityDB(p, buildctx)
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
		status.Path, status.Built.Format("2006-01-02")))

	// Parse the SBOM file to get packages
	packages, context, err := parseSBOMFile(sbomFile)
	if err != nil {
		return xerrors.Errorf("failed to parse SBOM: %w", err)
	}

	// Use the reporter to log the message with consistent formatting
	buildctx.Reporter.PackageBuildLog(p, false, fmt.Appendf(nil, "Found packages in SBOM (count: %d)\n", len(packages)))

	// Find vulnerability matches
	matches, ignoredMatches, err := findVulnerabilities(packages, context, vulnProvider)
	if err != nil {
		return xerrors.Errorf("failed to find vulnerabilities: %w", err)
	}

	// Process the results
	// Use the reporter to log the message with consistent formatting
	buildctx.Reporter.PackageBuildLog(p, false, []byte(fmt.Sprintf("Vulnerability scan completed (vulnerabilities: %d, ignored: %d)\n",
		matches.Count(), len(ignoredMatches))))

	// Print vulnerability details
	printVulnerabilities(matches, vulnProvider)

	// TODO: Implement FailOn logic based on p.C.W.SBOM.FailOn

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
func findVulnerabilities(packages []pkg.Package, context pkg.Context, vulnProvider vulnerability.Provider) (*match.Matches, []match.IgnoredMatch, error) {
	// Create a vulnerability matcher
	matchers := matcher.NewDefaultMatchers(matcher.Config{})
	vulnMatcher := grype.VulnerabilityMatcher{
		VulnerabilityProvider: vulnProvider,
		Matchers:              matchers,
	}

	// Find vulnerability matches
	matches, ignoredMatches, err := vulnMatcher.FindMatches(packages, context)
	if err != nil {
		return nil, nil, xerrors.Errorf("failed to find vulnerabilities: %w", err)
	}

	return matches, ignoredMatches, nil
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

// printVulnerabilities prints vulnerability details to the console
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
			log.WithFields(log.Fields{
				"vulnerability_id": match.Vulnerability.ID,
				"error":            err,
			}).Warn("Error getting vulnerability metadata")
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

// ErrNoSBOM is returned when no SBOM is found in a cached archive
var ErrNoSBOM = xerrors.Errorf("no SBOM found")

// AccessSBOMInCachedArchive provides access to the SBOM in a cached build artifact.
// If no such SBOM exists, ErrNoSBOM is returned.
func AccessSBOMInCachedArchive(fn string, handler func(sbom io.Reader) error) (err error) {
	defer func() {
		if err != nil && !errors.Is(err, ErrNoSBOM) {
			err = xerrors.Errorf("error extracting SBOM from %s: %w", fn, err)
		}
	}()

	f, err := os.Open(fn)
	if err != nil {
		return xerrors.Errorf("cannot open file: %w", err)
	}
	defer func() {
		if closeErr := f.Close(); closeErr != nil {
			log.WithError(closeErr).Warn("failed to close file during SBOM extraction")
		}
	}()

	g, err := gzip.NewReader(f)
	if err != nil {
		return xerrors.Errorf("cannot create gzip reader: %w", err)
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
			return xerrors.Errorf("error reading tar: %w", err)
		}

		// Look for SBOM files with any extension
		if !strings.HasPrefix(hdr.Name, "./"+sbomFilename+".") &&
			!strings.HasPrefix(hdr.Name, "package/"+sbomFilename+".") {
			continue
		}

		err = handler(io.LimitReader(a, hdr.Size))
		if err != nil {
			return xerrors.Errorf("error handling SBOM: %w", err)
		}
		sbomFound = true
		break
	}

	if !sbomFound {
		return ErrNoSBOM
	}

	return nil
}
