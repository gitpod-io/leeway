package leeway

import (
	"io"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/xerrors"
)

const (
	// sbomFilename is the name of the SBOM file we store in the archived build artifacts.
	sbomFilename = "sbom.json"
)

// WorkspaceSBOM configures SBOM generation for a workspace
type WorkspaceSBOM struct {
	Enabled bool     `yaml:"enabled"`
	Format  string   `yaml:"format,omitempty"` // e.g., "cyclonedx", "spdx"
	ScanCVE bool     `yaml:"scanCVE"`
	FailOn  []string `yaml:"failOn,omitempty"` // e.g., ["CRITICAL", "HIGH"]
}

// writeSBOM produces an SBOM for a package and writes it to the build directory
func writeSBOM(p *Package, buildctx *buildContext, builddir string, buildStarted time.Time) (err error) {
	// This is a placeholder for the actual implementation
	// We'll implement this function later using Syft

	log.WithField("package", p.FullName()).Debug("SBOM generation is not yet implemented")
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
