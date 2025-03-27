package leeway

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/common"
	log "github.com/sirupsen/logrus"
	"golang.org/x/xerrors"
)

const (
	// SbomFilename is the name of the SBOM file in the build artifacts
	SbomFilename = "sbom.json"

	// securityProcessVersion is the version of the security scanning process.
	// If security scanning is enabled in a workspace, this version becomes part of the manifest,
	// hence changing it will invalidate previously built packages.
	securityProcessVersion = 1
)

// SecurityConfig defines the security scanning configuration for a workspace or package
type SecurityConfig struct {
	// Enabled determines if security scanning is enabled
	Enabled bool `yaml:"enabled"`

	// SBOMGeneration enables SBOM generation
	SBOMGeneration bool `yaml:"sbomGeneration"`

	// VulnerabilityScanning enables vulnerability scanning
	VulnerabilityScanning bool `yaml:"vulnerabilityScanning"`

	// FailOnVulnerabilities determines if builds should fail on vulnerabilities
	FailOnVulnerabilities bool `yaml:"failOnVulnerabilities"`

	// Scanners defines the scanners to use
	Scanners []ScannerConfig `yaml:"scanners"`
}

// ScannerConfig defines the configuration for a specific scanner
type ScannerConfig struct {
	// Name of the scanner (e.g., "trivy")
	Name string `yaml:"name"`

	// Config is scanner-specific configuration
	Config map[string]interface{} `yaml:"config"`
}

// TrivyConfig defines Trivy-specific configuration
type TrivyConfig struct {
	// Severity levels to scan for
	Severity string `yaml:"severity"`

	// IgnoreFile path to the ignore file
	IgnoreFile string `yaml:"ignoreFile"`

	// SkipDirectories directories to skip
	SkipDirectories []string `yaml:"skipDirectories"`
}

// Scanner defines the interface for security scanners
type Scanner interface {
	// Name returns the name of the scanner
	Name() string

	// ScanPackage scans a package for vulnerabilities
	ScanPackage(ctx context.Context, pkg *Package, buildDir string) (*ScanResult, error)

	// GenerateSBOM generates an SBOM for a package
	GenerateSBOM(ctx context.Context, pkg *Package, buildDir string) (*SBOM, error)
}

// ScanResult represents the result of a vulnerability scan
type ScanResult struct {
	// Vulnerabilities found during scanning
	Vulnerabilities []Vulnerability

	// RawOutput from the scanner
	RawOutput []byte
}

// Vulnerability represents a security vulnerability
type Vulnerability struct {
	// ID of the vulnerability (e.g., CVE-2021-44228)
	ID string `json:"id"`

	// Severity of the vulnerability
	Severity string `json:"severity"`

	// Package affected by the vulnerability
	Package string `json:"package"`

	// Version of the package
	Version string `json:"version"`

	// Description of the vulnerability
	Description string `json:"description"`

	// References to more information
	References []string `json:"references"`
}

// SBOM represents a Software Bill of Materials
type SBOM struct {
	// Format of the SBOM (e.g., CycloneDX, SPDX)
	Format string

	// Content of the SBOM
	Content []byte
}

// TrivyScanner implements the Scanner interface for Trivy
type TrivyScanner struct {
	Config TrivyConfig
}

// Name returns the name of the scanner
func (s *TrivyScanner) Name() string {
	return "trivy"
}

// ScanPackage scans a package using Trivy
func (s *TrivyScanner) ScanPackage(ctx context.Context, pkg *Package, buildDir string) (*ScanResult, error) {
	log.WithField("package", pkg.FullName()).Debug("scanning package with Trivy")

	// Build Trivy command
	severity := s.Config.Severity
	if severity == "" {
		severity = "HIGH,CRITICAL"
	}

	cmd := exec.CommandContext(ctx, "trivy", "fs",
		"--severity", severity,
		"--format", "json",
		buildDir)

	// Set up ignore file if specified
	if s.Config.IgnoreFile != "" {
		ignoreFile := s.Config.IgnoreFile
		if !filepath.IsAbs(ignoreFile) {
			ignoreFile = filepath.Join(pkg.C.W.Origin, ignoreFile)
		}
		cmd.Args = append(cmd.Args, "--ignorefile", ignoreFile)
	}

	// Skip directories if specified
	for _, dir := range s.Config.SkipDirectories {
		cmd.Args = append(cmd.Args, "--skip-dirs", dir)
	}

	// Execute command and parse results
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Trivy returns non-zero exit code when vulnerabilities are found
		// We don't want to treat this as an error
		if !bytes.Contains(output, []byte("error")) {
			log.WithField("output", string(output)).Debug("trivy found vulnerabilities but continuing")
		} else {
			return nil, fmt.Errorf("trivy scan failed: %w: %s", err, string(output))
		}
	}

	// Parse JSON output
	var trivyResult struct {
		Results []struct {
			Target         string `json:"Target"`
			Vulnerabilities []struct {
				VulnerabilityID  string   `json:"VulnerabilityID"`
				PkgName          string   `json:"PkgName"`
				InstalledVersion string   `json:"InstalledVersion"`
				Severity         string   `json:"Severity"`
				Description      string   `json:"Description"`
				References       []string `json:"References"`
			} `json:"Vulnerabilities"`
		} `json:"Results"`
	}

	if err := json.Unmarshal(output, &trivyResult); err != nil {
		return nil, fmt.Errorf("failed to parse trivy output: %w", err)
	}

	// Convert Trivy result to our format
	result := &ScanResult{
		RawOutput: output,
	}

	for _, res := range trivyResult.Results {
		for _, vuln := range res.Vulnerabilities {
			result.Vulnerabilities = append(result.Vulnerabilities, Vulnerability{
				ID:          vuln.VulnerabilityID,
				Severity:    vuln.Severity,
				Package:     vuln.PkgName,
				Version:     vuln.InstalledVersion,
				Description: vuln.Description,
				References:  vuln.References,
			})
		}
	}

	return result, nil
}

// GenerateSBOM generates an SBOM using Trivy
func (s *TrivyScanner) GenerateSBOM(ctx context.Context, pkg *Package, buildDir string) (*SBOM, error) {
	log.WithField("package", pkg.FullName()).Debug("generating SBOM with Trivy")

	sbomFile := filepath.Join(buildDir, SbomFilename)

	// Build Trivy command for SBOM generation
	cmd := exec.CommandContext(ctx, "trivy", "fs",
		"--format", "cyclonedx",
		"--output", sbomFile,
		buildDir)

	// Skip directories if specified
	for _, dir := range s.Config.SkipDirectories {
		cmd.Args = append(cmd.Args, "--skip-dirs", dir)
	}

	// Execute command
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("trivy SBOM generation failed: %w: %s", err, string(output))
	}

	// Read generated SBOM
	content, err := os.ReadFile(sbomFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read SBOM file: %w", err)
	}

	return &SBOM{
		Format:  "CycloneDX",
		Content: content,
	}, nil
}

// StoreSBOM stores an SBOM in the build artifacts
func StoreSBOM(buildDir string, sbom *SBOM) error {
	return os.WriteFile(filepath.Join(buildDir, SbomFilename), sbom.Content, 0644)
}

// RetrieveSBOM retrieves an SBOM from a cached package
func RetrieveSBOM(cacheFn string) (*SBOM, error) {
	var sbomContent []byte

	err := AccessFileInCachedArchive(cacheFn, SbomFilename, func(r io.Reader) error {
		var err error
		sbomContent, err = io.ReadAll(r)
		return err
	})

	if err != nil {
		return nil, err
	}

	return &SBOM{
		Format:  detectSBOMFormat(sbomContent),
		Content: sbomContent,
	}, nil
}

// AccessFileInCachedArchive provides access to a file in a cached build artifact.
func AccessFileInCachedArchive(fn, targetFile string, handler func(file io.Reader) error) error {
	f, err := os.Open(fn)
	if err != nil {
		return err
	}
	defer f.Close()

	g, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer g.Close()

	var fileFound bool
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

		if hdr.Name != "./"+targetFile && hdr.Name != "package/"+targetFile {
			continue
		}

		err = handler(io.LimitReader(a, hdr.Size))
		if err != nil {
			return err
		}
		fileFound = true
		break
	}
	if err != nil {
		return err
	}

	if !fileFound {
		return fmt.Errorf("file %s not found in archive", targetFile)
	}

	return nil
}

// detectSBOMFormat detects the format of an SBOM from its content
func detectSBOMFormat(content []byte) string {
	// Simple detection based on content
	if bytes.Contains(content, []byte("CycloneDX")) {
		return "CycloneDX"
	}
	if bytes.Contains(content, []byte("SPDX")) {
		return "SPDX"
	}
	return "Unknown"
}

// RunSecurityScan performs security scanning on a package
func RunSecurityScan(buildCtx *buildContext, pkg *Package, buildDir string) error {
	if !pkg.C.W.Security.Enabled {
		return nil
	}

	log.WithField("package", pkg.FullName()).Info("running security scan")

	// Create scanner based on configuration
	var scanner Scanner
	for _, scannerCfg := range pkg.C.W.Security.Scanners {
		if scannerCfg.Name == "trivy" {
			// Convert generic config to TrivyConfig
			var trivyConfig TrivyConfig
			if scannerCfg.Config != nil {
				if severity, ok := scannerCfg.Config["severity"].(string); ok {
					trivyConfig.Severity = severity
				}
				if ignoreFile, ok := scannerCfg.Config["ignoreFile"].(string); ok {
					trivyConfig.IgnoreFile = ignoreFile
				}
				if skipDirs, ok := scannerCfg.Config["skipDirectories"].([]interface{}); ok {
					for _, dir := range skipDirs {
						if dirStr, ok := dir.(string); ok {
							trivyConfig.SkipDirectories = append(trivyConfig.SkipDirectories, dirStr)
						}
					}
				}
			}
			scanner = &TrivyScanner{Config: trivyConfig}
			break
		}
	}

	if scanner == nil {
		// Default to Trivy if no scanner is configured
		scanner = &TrivyScanner{
			Config: TrivyConfig{
				Severity: "HIGH,CRITICAL",
			},
		}
	}

	// Generate SBOM if enabled
	if pkg.C.W.Security.SBOMGeneration {
		sbom, err := scanner.GenerateSBOM(context.Background(), pkg, buildDir)
		if err != nil {
			return xerrors.Errorf("SBOM generation failed: %w", err)
		}

		if err := StoreSBOM(buildDir, sbom); err != nil {
			return xerrors.Errorf("failed to store SBOM: %w", err)
		}

		log.WithField("package", pkg.FullName()).Info("generated SBOM")
	}

	// Scan for vulnerabilities if enabled
	if pkg.C.W.Security.VulnerabilityScanning {
		result, err := scanner.ScanPackage(context.Background(), pkg, buildDir)
		if err != nil {
			return xerrors.Errorf("vulnerability scanning failed: %w", err)
		}

		// Write scan results to file
		resultFile := filepath.Join(buildDir, "security-scan-result.json")
		resultJSON, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return xerrors.Errorf("failed to marshal scan results: %w", err)
		}

		if err := os.WriteFile(resultFile, resultJSON, 0644); err != nil {
			return xerrors.Errorf("failed to write scan results: %w", err)
		}

		// Check if we should fail on vulnerabilities
		if pkg.C.W.Security.FailOnVulnerabilities && len(result.Vulnerabilities) > 0 {
			var criticalVulns []string
			for _, vuln := range result.Vulnerabilities {
				if strings.ToUpper(vuln.Severity) == "CRITICAL" {
					criticalVulns = append(criticalVulns, vuln.ID)
				}
			}

			if len(criticalVulns) > 0 {
				return xerrors.Errorf("critical vulnerabilities found: %s", strings.Join(criticalVulns, ", "))
			}
		}

		log.WithField("package", pkg.FullName()).
			WithField("vulnerabilities", len(result.Vulnerabilities)).
			Info("completed vulnerability scanning")
	}

	return nil
}

// AddSBOMToProvenance adds SBOM information to the provenance subjects
func AddSBOMToProvenance(buildDir string, subjects []in_toto.Subject) ([]in_toto.Subject, error) {
	sbomPath := filepath.Join(buildDir, SbomFilename)
	if _, err := os.Stat(sbomPath); err != nil {
		// SBOM file doesn't exist, return original subjects
		return subjects, nil
	}

	sbomContent, err := os.ReadFile(sbomPath)
	if err != nil {
		return nil, xerrors.Errorf("failed to read SBOM file: %w", err)
	}

	sbomDigest := sha256.Sum256(sbomContent)
	sbomSubject := in_toto.Subject{
		Name: SbomFilename,
		Digest: common.DigestSet{
			"sha256": hex.EncodeToString(sbomDigest[:]),
		},
	}

	return append(subjects, sbomSubject), nil
}
