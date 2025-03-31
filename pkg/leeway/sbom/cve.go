package sbom

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/anchore/grype/grype"
	"github.com/anchore/grype/grype/db"
	"github.com/anchore/grype/grype/matcher"
	"github.com/anchore/grype/grype/presenter"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/sbom"
	"github.com/gitpod-io/leeway/pkg/leeway/common"
	log "github.com/sirupsen/logrus"
	"golang.org/x/xerrors"
	"gopkg.in/yaml.v3"
)

// VulnerabilityReport represents a vulnerability report
type VulnerabilityReport struct {
	// Matches is a list of vulnerability matches
	Matches []VulnerabilityMatch `json:"matches"`

	// Metadata is metadata about the scan
	Metadata *ScanMetadata `json:"metadata,omitempty"`
}

// VulnerabilityMatch represents a vulnerability match
type VulnerabilityMatch struct {
	// Vulnerability is the vulnerability that was matched
	Vulnerability Vulnerability `json:"vulnerability"`

	// Package is the package that was matched
	Package Package `json:"package"`

	// Severity is the severity of the vulnerability
	Severity string `json:"severity"`
}

// Vulnerability represents a vulnerability
type Vulnerability struct {
	// ID is the vulnerability ID
	ID string `json:"id"`

	// DataSource is the source of the vulnerability data
	DataSource string `json:"dataSource"`

	// Severity is the severity of the vulnerability
	Severity string `json:"severity"`

	// Description is a description of the vulnerability
	Description string `json:"description"`

	// CVSS is the CVSS score of the vulnerability
	CVSS *CVSS `json:"cvss,omitempty"`

	// URLs is a list of URLs with more information about the vulnerability
	URLs []string `json:"urls,omitempty"`

	// Fix is information about how to fix the vulnerability
	Fix *Fix `json:"fix,omitempty"`
}

// CVSS represents a CVSS score
type CVSS struct {
	// Version is the CVSS version
	Version string `json:"version"`

	// Vector is the CVSS vector
	Vector string `json:"vector"`

	// BaseScore is the CVSS base score
	BaseScore float64 `json:"baseScore"`
}

// Fix represents information about how to fix a vulnerability
type Fix struct {
	// Versions is a list of versions that fix the vulnerability
	Versions []string `json:"versions,omitempty"`

	// State is the state of the fix
	State string `json:"state,omitempty"`
}

// Package represents a package
type Package struct {
	// Name is the name of the package
	Name string `json:"name"`

	// Version is the version of the package
	Version string `json:"version"`

	// Type is the type of the package
	Type string `json:"type"`

	// Language is the language of the package
	Language string `json:"language,omitempty"`

	// CPEs is a list of CPEs for the package
	CPEs []string `json:"cpes,omitempty"`

	// PURL is the package URL
	PURL string `json:"purl,omitempty"`
}

// ScanForVulnerabilities scans an SBOM for vulnerabilities
func ScanForVulnerabilities(sbomDoc *sbom.SBOM, options *CVEOptions) (*VulnerabilityReport, error) {
	if options == nil {
		options = DefaultCVEOptions()
	}

	log.Info("Scanning for vulnerabilities")

	// Create a vulnerability matcher
	store, err := db.NewStore(db.Config{
		DBRootDir:           "", // Use default
		ListingURL:          "", // Use default
		ValidateByHashOnGet: false,
	})
	if err != nil {
		return nil, xerrors.Errorf("failed to create vulnerability database store: %w", err)
	}

	// Update the vulnerability database
	updateProgress := db.ProgressCallback(func(progress float64) {
		log.WithField("progress", fmt.Sprintf("%.2f%%", progress*100)).Debug("Updating vulnerability database")
	})
	if err := store.Update(context.Background(), updateProgress); err != nil {
		return nil, xerrors.Errorf("failed to update vulnerability database: %w", err)
	}

	// Get the latest vulnerability database
	dbCurator, err := store.GetCurator(context.Background())
	if err != nil {
		return nil, xerrors.Errorf("failed to get vulnerability database curator: %w", err)
	}

	// Create a vulnerability matcher
	vulnMatcher := matcher.New(matcher.Config{
		UpdateListingURL: "", // Use default
	})

	// Match vulnerabilities
	matchers := vulnMatcher.ProviderByPackages(sbomDoc.Artifacts.Packages)
	matches, err := grype.FindVulnerabilities(
		context.Background(),
		sbomDoc.Artifacts.Packages,
		matchers,
		dbCurator.Resolver,
		grype.NewVulnerabilityMetadataProvider(dbCurator.Store),
		grype.MatcherConfig{
			IgnoreFilePath: "",
		},
	)
	if err != nil {
		return nil, xerrors.Errorf("failed to find vulnerabilities: %w", err)
	}

	// Create a vulnerability report
	report := &VulnerabilityReport{
		Matches: make([]VulnerabilityMatch, 0),
	}

	// Add matches to the report
	for _, match := range matches.Sorted() {
		// Skip ignored vulnerabilities
		if isIgnored(match.Vulnerability.ID, match.Package.Name, options.IgnoreRules) {
			log.WithFields(log.Fields{
				"id":      match.Vulnerability.ID,
				"package": match.Package.Name,
			}).Debug("Ignoring vulnerability")
			continue
		}

		// Add the match to the report
		report.Matches = append(report.Matches, convertMatch(match))
	}

	// Add metadata to the report
	if options.IncludeMetadata {
		report.Metadata = &ScanMetadata{
			Timestamp:  time.Now().Format(time.RFC3339),
			SBOMFormat: sbomDoc.Descriptor.Format,
			FailOn:     options.FailOn,
		}
	}

	return report, nil
}

// isIgnored checks if a vulnerability is ignored
func isIgnored(id, pkgName string, ignoreRules []IgnoreRule) bool {
	for _, rule := range ignoreRules {
		if strings.EqualFold(rule.ID, id) {
			// Check if the rule has an expiration date
			if rule.Expiration != "" {
				expiration, err := time.Parse(time.RFC3339, rule.Expiration)
				if err == nil && time.Now().After(expiration) {
					// Rule has expired
					return false
				}
			}

			// Check if the rule applies to specific packages
			if len(rule.Packages) > 0 {
				for _, pkg := range rule.Packages {
					if strings.EqualFold(pkg, pkgName) {
						return true
					}
				}
				return false
			}

			// Rule applies to all packages
			return true
		}
	}
	return false
}

// convertMatch converts a vulnerability match to a VulnerabilityMatch
func convertMatch(match vulnerability.Match) VulnerabilityMatch {
	// Create a vulnerability match
	vulnMatch := VulnerabilityMatch{
		Vulnerability: Vulnerability{
			ID:          match.Vulnerability.ID,
			DataSource:  match.Vulnerability.DataSource,
			Severity:    match.Vulnerability.Severity,
			Description: match.Vulnerability.Description,
			URLs:        match.Vulnerability.URLs,
		},
		Package: Package{
			Name:     match.Package.Name,
			Version:  match.Package.Version,
			Type:     string(match.Package.Type),
			Language: match.Package.Language,
			PURL:     match.Package.PURL,
		},
		Severity: match.Vulnerability.Severity,
	}

	// Add CPEs
	if match.Package.CPEs != nil {
		vulnMatch.Package.CPEs = make([]string, len(match.Package.CPEs))
		for i, cpe := range match.Package.CPEs {
			vulnMatch.Package.CPEs[i] = cpe.String()
		}
	}

	// Add CVSS
	if match.Vulnerability.CVSS != nil {
		vulnMatch.Vulnerability.CVSS = &CVSS{
			Version:   match.Vulnerability.CVSS[0].Version,
			Vector:    match.Vulnerability.CVSS[0].Vector,
			BaseScore: match.Vulnerability.CVSS[0].BaseScore,
		}
	}

	// Add fix
	if match.Vulnerability.Fix != nil {
		vulnMatch.Vulnerability.Fix = &Fix{
			Versions: match.Vulnerability.Fix.Versions,
			State:    match.Vulnerability.Fix.State,
		}
	}

	return vulnMatch
}

// WriteToFile writes a vulnerability report to a file
func (r *VulnerabilityReport) WriteToFile(path string) error {
	// Create parent directory if it doesn't exist
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return xerrors.Errorf("failed to create output directory: %w", err)
	}

	// Marshal the report to JSON
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return xerrors.Errorf("failed to marshal report: %w", err)
	}

	// Write the report to the file
	if err := os.WriteFile(path, data, 0644); err != nil {
		return xerrors.Errorf("failed to write report: %w", err)
	}

	log.WithField("path", path).Info("Vulnerability report written to file")
	return nil
}

// HasFailureLevelVulnerabilities checks if the report has vulnerabilities with the specified severity levels
func (r *VulnerabilityReport) HasFailureLevelVulnerabilities(failOn []string) bool {
	// Convert failOn to a map for faster lookup
	failOnMap := make(map[string]struct{})
	for _, severity := range failOn {
		failOnMap[strings.ToUpper(severity)] = struct{}{}
	}

	// Check if any matches have a severity level in failOn
	for _, match := range r.Matches {
		if _, ok := failOnMap[strings.ToUpper(match.Severity)]; ok {
			return true
		}
	}

	return false
}

// GenerateScanMetadata generates metadata for a CVE scan
func GenerateScanMetadata(pkgInfo *common.PackageInfo, sbomOptions *SBOMOptions, cveOptions *CVEOptions) (*ScanMetadata, error) {
	// Create metadata
	metadata := &ScanMetadata{
		Timestamp:  time.Now().Format(time.RFC3339),
		Package:    pkgInfo.FullName,
		Version:    pkgInfo.Version,
		SBOMFormat: sbomOptions.Format,
		FailOn:     cveOptions.FailOn,
	}

	return metadata, nil
}

// WriteMetadataFile writes metadata to a file
func WriteMetadataFile(path string, metadata *ScanMetadata) error {
	// Create parent directory if it doesn't exist
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return xerrors.Errorf("failed to create output directory: %w", err)
	}

	// Marshal the metadata to JSON
	data, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return xerrors.Errorf("failed to marshal metadata: %w", err)
	}

	// Write the metadata to the file
	if err := os.WriteFile(path, data, 0644); err != nil {
		return xerrors.Errorf("failed to write metadata: %w", err)
	}

	log.WithField("path", path).Debug("Metadata written to file")
	return nil
}

// WriteIgnoreFile writes ignore rules to a file
func WriteIgnoreFile(path string, rules []IgnoreRule, metadata *ScanMetadata) error {
	// Create parent directory if it doesn't exist
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return xerrors.Errorf("failed to create output directory: %w", err)
	}

	// Create ignore file
	ignoreFile := struct {
		IgnoreRules []IgnoreRule `yaml:"ignoreRules"`
		Metadata    *ScanMetadata `yaml:"metadata,omitempty"`
	}{
		IgnoreRules: rules,
		Metadata:    metadata,
	}

	// Marshal the ignore file to YAML
	data, err := yaml.Marshal(ignoreFile)
	if err != nil {
		return xerrors.Errorf("failed to marshal ignore file: %w", err)
	}

	// Write the ignore file to the file
	if err := os.WriteFile(path, data, 0644); err != nil {
		return xerrors.Errorf("failed to write ignore file: %w", err)
	}

	log.WithField("path", path).Debug("Ignore file written to file")
	return nil
}

// GetVulnerabilitySummary returns a summary of vulnerabilities by severity
func GetVulnerabilitySummary(report *VulnerabilityReport) map[string]int {
	// Create a map of severity to count
	summary := make(map[string]int)

	// Count vulnerabilities by severity
	for _, match := range report.Matches {
		severity := strings.ToUpper(match.Severity)
		summary[severity]++
	}

	return summary
}

// FormatVulnerabilityReport formats a vulnerability report for display
func FormatVulnerabilityReport(report *VulnerabilityReport) string {
	// Get a summary of vulnerabilities by severity
	summary := GetVulnerabilitySummary(report)

	// Format the report
	var sb strings.Builder
	sb.WriteString("Vulnerability Scan Results:\n")
	sb.WriteString("  Summary:\n")
	for _, severity := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE", "UNKNOWN"} {
		count := summary[severity]
		if count > 0 {
			sb.WriteString(fmt.Sprintf("    %s: %d\n", severity, count))
		}
	}

	// Add details for critical and high vulnerabilities
	sb.WriteString("\n  Details:\n")
	for _, match := range report.Matches {
		severity := strings.ToUpper(match.Severity)
		if severity == "CRITICAL" || severity == "HIGH" {
			sb.WriteString(fmt.Sprintf("    %s (%s):\n", match.Vulnerability.ID, severity))
			sb.WriteString(fmt.Sprintf("      Package: %s@%s\n", match.Package.Name, match.Package.Version))
			if match.Vulnerability.Description != "" {
				sb.WriteString(fmt.Sprintf("      Description: %s\n", match.Vulnerability.Description))
			}
			if match.Vulnerability.Fix != nil && len(match.Vulnerability.Fix.Versions) > 0 {
				sb.WriteString(fmt.Sprintf("      Fixed in: %s\n", strings.Join(match.Vulnerability.Fix.Versions, ", ")))
			}
			if len(match.Vulnerability.URLs) > 0 {
				sb.WriteString(fmt.Sprintf("      URLs: %s\n", strings.Join(match.Vulnerability.URLs, ", ")))
			}
			sb.WriteString("\n")
		}
	}

	return sb.String()
}
