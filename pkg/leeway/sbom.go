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

	"slices"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/syft/syft"
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
	// sbomProcessVersion is the version of the SBOM generating process.
	// If SBOM is enabled in a workspace, this version becomes part of the manifest,
	// hence changing it will invalidate previously built packages.
	sbomProcessVersion = 1

	// EnvvarVulnReportsDir names the environment variable we take the vulnerability reports directory location from
	EnvvarVulnReportsDir = "LEEWAY_VULN_REPORTS_DIR"

	// SBOM file format constants
	sbomBaseFilename = "sbom"

	// sbomCycloneDXFileExtension is the extension of the CycloneDX SBOM file we store in the archived build artifacts
	sbomCycloneDXFileExtension = ".cdx.json"

	// sbomSPDXFileExtension is the extension of the SPDX SBOM file we store in the archived build artifacts
	sbomSPDXFileExtension = "sbom.spdx.json"

	// sbomSyftFileExtension is the extension of the Syft SBOM file we store in the archived build artifacts
	sbomSyftFileExtension = "sbom.json"
)

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

// writeSBOM generates Software Bill of Materials (SBOM) for a package in multiple formats.
// This function is called during the build process to create SBOMs that are included in
// the package's build artifacts. It supports different source types based on the package type
// (Docker images vs. filesystem) and generates SBOMs in CycloneDX, SPDX, and Syft formats.
func writeSBOM(buildctx *buildContext, p *Package, builddir string) (err error) {
	if !p.C.W.SBOM.Enabled {
		return nil
	}

	cfg := syft.DefaultCreateSBOMConfig()

	// Get the appropriate source based on package type
	var src source.Source
	if p.Type == DockerPackage {
		buildctx.Reporter.PackageBuildLog(p, false, []byte("Generating SBOM from Docker image\n"))

		version, err := p.Version()
		if err != nil {
			return xerrors.Errorf("failed to get package version: %w", err)
		}

		src, err = syft.GetSource(context.Background(), version, nil)
		if err != nil {
			return xerrors.Errorf("failed to get Docker image source for SBOM generation: %w", err)
		}
	} else {
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

	// Generate SBOM in all supported formats
	formats := []string{"cyclonedx", "spdx", "syft"}
	for _, format := range formats {
		encoder, filename, err := getSBOMEncoder(format)
		if err != nil {
			errMsg := fmt.Sprintf("failed to get SBOM encoder for format %s: %s", format, err)
			buildctx.Reporter.PackageBuildLog(p, true, []byte(errMsg+"\n"))
			return xerrors.Errorf(errMsg)
		}

		var buf bytes.Buffer
		if err := encoder.Encode(&buf, *s); err != nil {
			errMsg := fmt.Sprintf("failed to encode SBOM in format %s: %s", format, err)
			buildctx.Reporter.PackageBuildLog(p, true, []byte(errMsg+"\n"))
			return xerrors.Errorf(errMsg)
		}
		data := buf.Bytes()

		fn := filepath.Join(builddir, filename)
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

// getSBOMEncoder returns the appropriate encoder and file name for the given SBOM format.
// It supports CycloneDX, SPDX, and Syft formats, each with its own encoder and file extension.
func getSBOMEncoder(format string) (encoder sbom.FormatEncoder, filename string, err error) {
	var fileExtension string
	switch format {
	case "cyclonedx":
		encoder, err = cyclonedxjson.NewFormatEncoderWithConfig(cyclonedxjson.DefaultEncoderConfig())
		if err != nil {
			return nil, "", xerrors.Errorf("failed to create CycloneDX encoder: %w", err)
		}
		fileExtension = sbomCycloneDXFileExtension
	case "spdx":
		encoder, err = spdxjson.NewFormatEncoderWithConfig(spdxjson.DefaultEncoderConfig())
		if err != nil {
			return nil, "", xerrors.Errorf("failed to create SPDX encoder: %w", err)
		}
		fileExtension = sbomSPDXFileExtension
	case "syft":
		encoder = syftjson.NewFormatEncoder()
		fileExtension = sbomSyftFileExtension
	default:
		return nil, "", xerrors.Errorf("unsupported SBOM format: %s", format)
	}

	return encoder, sbomBaseFilename + fileExtension, nil
}

// writeFileHandler returns a handler function for AccessSBOMInCachedArchive that writes to a file.
// This handler creates any necessary directories, opens the output file, and copies the SBOM content.
func writeFileHandler(outputPath string) func(io.Reader) error {
	return func(r io.Reader) error {
		if dir := filepath.Dir(outputPath); dir != "" {
			if err := os.MkdirAll(dir, 0755); err != nil {
				return fmt.Errorf("cannot create output directory %s: %w", dir, err)
			}
		}

		file, err := os.Create(outputPath)
		if err != nil {
			return fmt.Errorf("cannot create output file %s: %w", outputPath, err)
		}
		defer file.Close()

		_, err = io.Copy(file, r)
		return err
	}
}

// ValidateSBOMFormat checks if the provided format is supported.
// It returns a boolean indicating if the format is valid and a list of valid formats.
func ValidateSBOMFormat(format string) (bool, []string) {
	validFormats := []string{"cyclonedx", "spdx", "syft"}
	return slices.Contains(validFormats, format), validFormats
}

// GetSBOMFileExtension returns the file extension for the given SBOM format.
// This is used to construct filenames for SBOM files in different formats.
func GetSBOMFileExtension(format string) string {
	switch format {
	case "cyclonedx":
		return sbomCycloneDXFileExtension
	case "spdx":
		return sbomSPDXFileExtension
	case "syft":
		return sbomSyftFileExtension
	default:
		return ".json"
	}
}

// ErrNoSBOMFile is returned when no SBOM file is found in a cached archive
var ErrNoSBOMFile = fmt.Errorf("no SBOM file found")

// AccessSBOMInCachedArchive extracts an SBOM file from a cached build artifact.
// It supports different SBOM formats (cyclonedx, spdx, syft) and applies the provided
// handler function to the extracted SBOM content. If no SBOM file is found, it returns
// ErrNoSBOMFile. This function is used by the sbom export and scan commands.
func AccessSBOMInCachedArchive(fn string, format string, handler func(sbomFile io.Reader) error) (err error) {
	defer func() {
		if err != nil && err != ErrNoSBOMFile {
			err = fmt.Errorf("error extracting SBOM from %s (format: %s): %w", fn, format, err)
		}
	}()

	formatValid, validFormats := ValidateSBOMFormat(format)
	if !formatValid {
		return fmt.Errorf("Unsupported format: %s. Supported formats are: %s", format, strings.Join(validFormats, ", "))
	}
	sbomFilename := sbomBaseFilename + GetSBOMFileExtension(format)

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

		if !strings.HasSuffix(hdr.Name, sbomFilename) {
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
