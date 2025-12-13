package leeway

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"slices"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/format/cyclonedxjson"
	"github.com/anchore/syft/syft/format/spdxjson"
	"github.com/anchore/syft/syft/format/syftjson"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
	"github.com/gitpod-io/leeway/pkg/leeway/cache"
	"github.com/google/uuid"
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
)

// WorkspaceSBOM configures SBOM generation for a workspace
type WorkspaceSBOM struct {
	Enabled               bool         `yaml:"enabled"`
	ScanVulnerabilities   bool         `yaml:"scanVulnerabilities"`
	FailOn                []string     `yaml:"failOn,omitempty"`                // e.g., ["CRITICAL", "HIGH"]
	IgnoreVulnerabilities []IgnoreRule `yaml:"ignoreVulnerabilities,omitempty"` // Workspace-level ignore rules
	Parallelism           *int         `yaml:"parallelism,omitempty"`           // Number of parallel workers for SBOM generation (default: CPU cores)
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

// GetSBOMParallelism returns the effective parallelism setting for SBOM generation.
// If not explicitly configured or set to 0, defaults to the number of CPU cores for optimal performance.
func GetSBOMParallelism(sbomConfig WorkspaceSBOM) int {
	if sbomConfig.Parallelism != nil && *sbomConfig.Parallelism > 0 {
		return *sbomConfig.Parallelism
	}
	// Default to CPU core count for optimal performance based on benchmarking
	// This applies when parallelism is nil, 0, or negative
	return runtime.NumCPU()
}

// generateDeterministicUUID generates a UUIDv5 from content
func generateDeterministicUUID(content []byte) string {
	// Use UUIDv5 (SHA-1 based) with the standard DNS namespace UUID.
	// The DNS namespace (6ba7b810-9dad-11d1-80b4-00c04fd430c8) is defined in RFC 4122
	// and commonly used for generating deterministic UUIDs from content.
	namespace := uuid.MustParse("6ba7b810-9dad-11d1-80b4-00c04fd430c8")

	return uuid.NewSHA1(namespace, content).String()
}

// normalizeCycloneDX makes CycloneDX SBOM deterministic
func normalizeCycloneDX(sbomPath string, timestamp time.Time) error {
	data, err := os.ReadFile(sbomPath)
	if err != nil {
		return fmt.Errorf("failed to read SBOM: %w", err)
	}

	var sbom map[string]interface{}
	if err := json.Unmarshal(data, &sbom); err != nil {
		return fmt.Errorf("failed to parse SBOM: %w", err)
	}

	// Normalize timestamp
	metadata, ok := sbom["metadata"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("metadata field not found or invalid")
	}
	metadata["timestamp"] = timestamp.Format(time.RFC3339)

	// Generate deterministic UUID from normalized content (without timestamp and UUID)
	// Remove non-deterministic fields before hashing
	delete(sbom, "serialNumber")
	normalizedForHash, err := json.Marshal(sbom)
	if err != nil {
		return fmt.Errorf("failed to marshal SBOM for hashing: %w", err)
	}
	contentHash := sha256.Sum256(normalizedForHash)
	deterministicUUID := generateDeterministicUUID(contentHash[:])
	sbom["serialNumber"] = fmt.Sprintf("urn:uuid:%s", deterministicUUID)

	// Write back
	normalized, err := json.MarshalIndent(sbom, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal SBOM: %w", err)
	}

	return os.WriteFile(sbomPath, normalized, 0644)
}

// normalizeSPDX makes SPDX SBOM deterministic
func normalizeSPDX(sbomPath string, timestamp time.Time) error {
	data, err := os.ReadFile(sbomPath)
	if err != nil {
		return fmt.Errorf("failed to read SBOM: %w", err)
	}

	var sbom map[string]interface{}
	if err := json.Unmarshal(data, &sbom); err != nil {
		return fmt.Errorf("failed to parse SBOM: %w", err)
	}

	// Normalize timestamp
	creationInfo, ok := sbom["creationInfo"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("creationInfo field not found or invalid")
	}
	creationInfo["created"] = timestamp.Format(time.RFC3339)

	// Get and validate documentNamespace
	originalNamespace, ok := sbom["documentNamespace"].(string)
	if !ok {
		return fmt.Errorf("documentNamespace field is not a string (got type %T)", sbom["documentNamespace"])
	}
	if originalNamespace == "" {
		return fmt.Errorf("documentNamespace field is empty")
	}

	// Generate deterministic UUID from normalized content (without timestamp and UUID)
	delete(sbom, "documentNamespace")

	normalizedForHash, err := json.Marshal(sbom)
	if err != nil {
		return fmt.Errorf("failed to marshal SBOM for hashing: %w", err)
	}
	contentHash := sha256.Sum256(normalizedForHash)
	deterministicUUID := generateDeterministicUUID(contentHash[:])

	// Replace UUID in documentNamespace using regex for robust matching
	// UUID pattern: 8-4-4-4-12 hex digits
	uuidPattern := regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)

	matches := uuidPattern.FindAllString(originalNamespace, -1)
	if len(matches) == 0 {
		return fmt.Errorf("no UUID found in SPDX documentNamespace: %s. "+
			"This may indicate a format change in Syft. Please report this issue", originalNamespace)
	}
	if len(matches) > 1 {
		log.WithField("documentNamespace", originalNamespace).
			WithField("uuid_count", len(matches)).
			Warn("Multiple UUIDs found in documentNamespace, replacing all with same deterministic UUID")
	}

	// Replace the UUID(s) with our deterministic one
	originalNamespace = uuidPattern.ReplaceAllString(originalNamespace, deterministicUUID)
	sbom["documentNamespace"] = originalNamespace

	// Write back
	normalized, err := json.MarshalIndent(sbom, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal SBOM: %w", err)
	}

	return os.WriteFile(sbomPath, normalized, 0644)
}

// writeSBOM generates Software Bill of Materials (SBOM) for a package in multiple formats.
// This function is called during the build process to create SBOMs that are included in
// the package's build artifacts. It supports different source types based on the package type
// (Docker images vs. filesystem) and generates SBOMs in CycloneDX, SPDX, and Syft formats.
// writeSBOMToCache writes SBOM files alongside the artifact in the cache.
// SBOM files are stored outside the tar.gz to maintain artifact determinism.
// The SBOM files are named: <artifact>.sbom.cdx.json, <artifact>.sbom.spdx.json, <artifact>.sbom.json
func writeSBOMToCache(buildctx *buildContext, p *Package, builddir string) (err error) {
	if !p.C.W.SBOM.Enabled {
		return nil
	}

	// Get the artifact path in cache
	artifactPath, exists := buildctx.LocalCache.Location(p)
	if artifactPath == "" {
		return fmt.Errorf("cannot determine cache location for %s", p.FullName())
	}

	if !exists {
		log.WithField("package", p.FullName()).WithField("path", artifactPath).Warn("Writing SBOM before artifact exists")
	}

	// Ensure we use the .tar.gz extension
	if strings.HasSuffix(artifactPath, ".tar") && !strings.HasSuffix(artifactPath, ".tar.gz") {
		artifactPath = artifactPath + ".gz"
	} else if !strings.HasSuffix(artifactPath, ".tar.gz") && !strings.HasSuffix(artifactPath, ".tar") {
		artifactPath = artifactPath + ".tar.gz"
	}

	sbomCfg := syft.DefaultCreateSBOMConfig()

	// Configure parallelism - default to CPU core count for optimal performance
	parallelism := GetSBOMParallelism(p.C.W.SBOM)
	sbomCfg = sbomCfg.WithParallelism(parallelism)

	// Get the appropriate source based on package type
	var src source.Source
	if p.Type == DockerPackage {
		dockerCfg, ok := p.Config.(DockerPkgConfig)
		if !ok {
			return xerrors.Errorf("package should have Docker config")
		}

		// Use the same precedence logic as buildDocker to determine export mode
		// This ensures SBOM generation uses the same source (OCI vs Docker daemon) as the build
		determineDockerExportMode(p, &dockerCfg, buildctx)

		// Check if OCI layout export is enabled
		if dockerCfg.ExportToCache != nil && *dockerCfg.ExportToCache {
			// OCI layout path - scan from oci-archive
			buildctx.Reporter.PackageBuildLog(p, false, []byte("Generating SBOM from OCI layout\n"))

			ociLayoutPath := filepath.Join(builddir, "image.tar")
			if _, err := os.Stat(ociLayoutPath); err != nil {
				return xerrors.Errorf("OCI layout image.tar not found in %s: %w", builddir, err)
			}

			// Syft will auto-detect the OCI archive format from the file path
			// Use explicit source provider configuration to ensure oci-archive is tried
			srcCfg := syft.DefaultGetSourceConfig().WithSources("oci-archive")
			src, err = syft.GetSource(context.Background(), ociLayoutPath, srcCfg)
			if err != nil {
				return xerrors.Errorf("failed to get OCI archive source for SBOM generation: %w", err)
			}
		} else {
			// Traditional Docker daemon path
			buildctx.Reporter.PackageBuildLog(p, false, []byte("Generating SBOM from Docker image\n"))

			version, err := p.Version()
			if err != nil {
				return xerrors.Errorf("failed to get package version: %w", err)
			}

			// Use explicit source provider configuration to ensure docker daemon is used
			// The version is a content hash that exists as a tag in the local Docker daemon
			srcCfg := syft.DefaultGetSourceConfig().WithSources("docker")
			src, err = syft.GetSource(context.Background(), version, srcCfg)
			if err != nil {
				return xerrors.Errorf("failed to get Docker image source for SBOM generation: %w", err)
			}
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
	s, err := syft.CreateSBOM(context.Background(), src, sbomCfg)
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

		// Write SBOM alongside artifact: <artifact>.sbom.<ext>
		fn := artifactPath + "." + filename

		// Ensure directory exists
		dir := filepath.Dir(fn)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("cannot create SBOM directory for %s: %w", p.FullName(), err)
		}

		err = os.WriteFile(fn, data, 0644)
		if err != nil {
			errMsg := fmt.Sprintf("failed to write SBOM to file %s: %s", fn, err)
			buildctx.Reporter.PackageBuildLog(p, true, []byte(errMsg+"\n"))
			return xerrors.Errorf(errMsg)
		}

		buildctx.Reporter.PackageBuildLog(p, false, fmt.Appendf(nil, "SBOM generated successfully (format: %s, file: %s)\n", format, fn))
	}

	// Normalize SBOMs after generation
	timestamp, err := GetCommitTimestamp(context.Background(), p.C.Git())
	if err != nil {
		return fmt.Errorf("failed to get deterministic timestamp for SBOM normalization: %w. "+
			"Ensure git is available and the repository is not a shallow clone, or set SOURCE_DATE_EPOCH environment variable",
			err)
	}

	// Normalize CycloneDX
	cycloneDXPath := artifactPath + "." + cache.SBOMBaseFilename + cache.SBOMCycloneDXFileExtension
	if err := normalizeCycloneDX(cycloneDXPath, timestamp); err != nil {
		buildctx.Reporter.PackageBuildLog(p, true,
			[]byte(fmt.Sprintf("Warning: failed to normalize CycloneDX SBOM: %v\n", err)))
	}

	// Normalize SPDX
	spdxPath := artifactPath + "." + cache.SBOMBaseFilename + cache.SBOMSPDXFileExtension
	if err := normalizeSPDX(spdxPath, timestamp); err != nil {
		buildctx.Reporter.PackageBuildLog(p, true,
			[]byte(fmt.Sprintf("Warning: failed to normalize SPDX SBOM: %v\n", err)))
	}

	// Note: sbom.json (Syft JSON format) is already deterministic (no timestamp field, no random UUIDs).
	// CycloneDX and SPDX formats require normalization because Syft generates them with non-deterministic
	// timestamps and random UUIDs. See https://github.com/anchore/syft/issues/3931 for upstream support.

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
		fileExtension = cache.SBOMCycloneDXFileExtension
	case "spdx":
		encoder, err = spdxjson.NewFormatEncoderWithConfig(spdxjson.DefaultEncoderConfig())
		if err != nil {
			return nil, "", xerrors.Errorf("failed to create SPDX encoder: %w", err)
		}
		fileExtension = cache.SBOMSPDXFileExtension
	case "syft":
		encoder = syftjson.NewFormatEncoder()
		fileExtension = cache.SBOMSyftFileExtension
	default:
		return nil, "", xerrors.Errorf("unsupported SBOM format: %s", format)
	}

	return encoder, cache.SBOMBaseFilename + fileExtension, nil
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
		return cache.SBOMCycloneDXFileExtension
	case "spdx":
		return cache.SBOMSPDXFileExtension
	case "syft":
		return cache.SBOMSyftFileExtension
	default:
		return ".json"
	}
}

// ErrNoSBOMFile is returned when no SBOM file is found in a cached archive
var ErrNoSBOMFile = fmt.Errorf("no SBOM file found")

// AccessSBOMInCachedArchive reads an SBOM file for a cached build artifact.
// It first checks for separate SBOM files alongside the artifact (new format),
// then falls back to extracting from the tar.gz archive (legacy format).
// It supports different SBOM formats (cyclonedx, spdx, syft) and applies the provided
// handler function to the SBOM content. If no SBOM file is found, it returns
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

	// Try reading from separate SBOM file first (new format)
	sbomExt := "." + cache.SBOMBaseFilename + GetSBOMFileExtension(format)
	sbomPath := fn + sbomExt

	if _, statErr := os.Stat(sbomPath); statErr == nil {
		// Separate SBOM file exists - read from it
		sbomFile, openErr := os.Open(sbomPath)
		if openErr != nil {
			return openErr
		}
		defer func() {
			if closeErr := sbomFile.Close(); closeErr != nil {
				log.WithError(closeErr).Warn("failed to close SBOM file")
			}
		}()
		return handler(sbomFile)
	}

	// Fall back to extracting from tar.gz archive (legacy format)
	return accessSBOMInTarArchive(fn, format, handler)
}

// accessSBOMInTarArchive extracts an SBOM file from inside a tar.gz archive (legacy format).
func accessSBOMInTarArchive(fn string, format string, handler func(sbomFile io.Reader) error) error {
	sbomFilename := cache.SBOMBaseFilename + GetSBOMFileExtension(format)

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
		return err
	}

	if !sbomFound {
		return ErrNoSBOMFile
	}

	return nil
}
