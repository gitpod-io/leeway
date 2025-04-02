package leeway

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/anchore/syft/syft/format/cyclonedxjson"
	"github.com/anchore/syft/syft/format/spdxjson"
	"github.com/anchore/syft/syft/format/syftjson"
	"github.com/anchore/syft/syft/sbom"
	log "github.com/sirupsen/logrus"
	"golang.org/x/xerrors"

	_ "github.com/anchore/grype/grype"
	"github.com/anchore/syft/syft"
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

// scanSBOMForVulnerabilities scans an SBOM for vulnerabilities
func scanSBOMForVulnerabilities(p *Package, buildctx *buildContext, builddir string) (err error) {
	// This is a placeholder for the actual implementation
	// We'll implement this function later using Grype

	log.WithField("package", p.FullName()).Debug("SBOM vulnerability scanning is not yet implemented")
	return nil
}

// AccessSBOMInCachedArchive provides access to the SBOM in a cached build artifact.
// If no such SBOM exists, an error is returned.
func AccessSBOMInCachedArchive(fn string, handler func(sbom io.Reader) error) (err error) {
	// This is a placeholder for the actual implementation
	// We'll implement this function later

	return xerrors.Errorf("SBOM access is not yet implemented")
}
