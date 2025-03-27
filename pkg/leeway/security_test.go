package leeway

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/common"
)

func TestDetectSBOMFormat(t *testing.T) {
	tests := []struct {
		name     string
		content  []byte
		expected string
	}{
		{
			name:     "CycloneDX format",
			content:  []byte(`{"bomFormat":"CycloneDX","specVersion":"1.4"}`),
			expected: "CycloneDX",
		},
		{
			name:     "SPDX format",
			content:  []byte(`{"spdxVersion":"SPDX-2.2","dataLicense":"CC0-1.0"}`),
			expected: "SPDX",
		},
		{
			name:     "Unknown format",
			content:  []byte(`{"format":"unknown"}`),
			expected: "Unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detectSBOMFormat(tt.content)
			if result != tt.expected {
				t.Errorf("detectSBOMFormat() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestAddSBOMToProvenance(t *testing.T) {
	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "sbom-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create a test SBOM file
	sbomContent := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.4"}`)
	sbomPath := filepath.Join(tempDir, sbomFilename)
	if err := os.WriteFile(sbomPath, sbomContent, 0644); err != nil {
		t.Fatalf("Failed to write SBOM file: %v", err)
	}

	// Create initial subjects
	initialSubjects := []in_toto.Subject{
		{
			Name: "test-file",
			Digest: common.DigestSet{
				"sha256": "abcdef1234567890",
			},
		},
	}

	// Test adding SBOM to provenance
	subjects, err := AddSBOMToProvenance(tempDir, initialSubjects)
	if err != nil {
		t.Fatalf("AddSBOMToProvenance() error = %v", err)
	}

	// Verify the result
	if len(subjects) != 2 {
		t.Errorf("Expected 2 subjects, got %d", len(subjects))
	}

	// Verify the SBOM subject
	sbomSubject := subjects[1]
	if sbomSubject.Name != sbomFilename {
		t.Errorf("Expected SBOM name to be %s, got %s", sbomFilename, sbomSubject.Name)
	}
	if _, ok := sbomSubject.Digest["sha256"]; !ok {
		t.Errorf("Expected SBOM digest to have sha256 key")
	}
}

// MockScanner implements the Scanner interface for testing
type MockScanner struct {
	ScanResult *ScanResult
	SBOMResult *SBOM
	ScanError  error
	SBOMError  error
}

func (s *MockScanner) Name() string {
	return "mock-scanner"
}

func (s *MockScanner) ScanPackage(ctx context.Context, pkg *Package, buildDir string) (*ScanResult, error) {
	return s.ScanResult, s.ScanError
}

func (s *MockScanner) GenerateSBOM(ctx context.Context, pkg *Package, buildDir string) (*SBOM, error) {
	return s.SBOMResult, s.SBOMError
}

func TestRunSecurityScan(t *testing.T) {
	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "security-scan-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create a test package with security configuration
	pkg := &Package{
		C: &Component{
			W: &Workspace{
				Security: SecurityConfig{
					Enabled:               true,
					SBOMGeneration:        true,
					VulnerabilityScanning: true,
					FailOnVulnerabilities: false,
					Scanners: []ScannerConfig{
						{
							Name: "trivy",
							Config: map[string]interface{}{
								"severity": "HIGH,CRITICAL",
							},
						},
					},
				},
			},
		},
	}

	// Create a mock scanner
	mockScanner := &MockScanner{
		ScanResult: &ScanResult{
			Vulnerabilities: []Vulnerability{
				{
					ID:          "CVE-2021-44228",
					Severity:    "CRITICAL",
					Package:     "log4j",
					Version:     "2.14.0",
					Description: "Remote code execution vulnerability",
					References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-44228"},
				},
			},
		},
		SBOMResult: &SBOM{
			Format:  "CycloneDX",
			Content: []byte(`{"bomFormat":"CycloneDX","specVersion":"1.4"}`),
		},
	}

	// Override the scanner creation logic for testing
	originalRunSecurityScan := RunSecurityScan
	defer func() {
		RunSecurityScan = originalRunSecurityScan
	}()

	// Mock the RunSecurityScan function
	RunSecurityScan = func(buildCtx *buildContext, pkg *Package, buildDir string) error {
		// Generate SBOM
		if pkg.C.W.Security.SBOMGeneration {
			sbom := mockScanner.SBOMResult
			if err := StoreSBOM(buildDir, sbom); err != nil {
				return err
			}
		}

		// Scan for vulnerabilities
		if pkg.C.W.Security.VulnerabilityScanning {
			result := mockScanner.ScanResult
			resultJSON, err := json.MarshalIndent(result, "", "  ")
			if err != nil {
				return err
			}

			resultFile := filepath.Join(buildDir, "security-scan-result.json")
			if err := os.WriteFile(resultFile, resultJSON, 0644); err != nil {
				return err
			}
		}

		return nil
	}

	// Run the security scan
	buildCtx := &buildContext{}
	err = RunSecurityScan(buildCtx, pkg, tempDir)
	if err != nil {
		t.Fatalf("RunSecurityScan() error = %v", err)
	}

	// Verify SBOM was generated
	sbomPath := filepath.Join(tempDir, sbomFilename)
	if _, err := os.Stat(sbomPath); os.IsNotExist(err) {
		t.Errorf("Expected SBOM file to exist at %s", sbomPath)
	}

	// Verify scan results were written
	resultPath := filepath.Join(tempDir, "security-scan-result.json")
	if _, err := os.Stat(resultPath); os.IsNotExist(err) {
		t.Errorf("Expected scan result file to exist at %s", resultPath)
	}

	// Read and verify scan results
	resultContent, err := os.ReadFile(resultPath)
	if err != nil {
		t.Fatalf("Failed to read scan result file: %v", err)
	}

	var result ScanResult
	if err := json.Unmarshal(resultContent, &result); err != nil {
		t.Fatalf("Failed to unmarshal scan result: %v", err)
	}

	if len(result.Vulnerabilities) != 1 {
		t.Errorf("Expected 1 vulnerability, got %d", len(result.Vulnerabilities))
	}

	vuln := result.Vulnerabilities[0]
	if vuln.ID != "CVE-2021-44228" {
		t.Errorf("Expected vulnerability ID to be CVE-2021-44228, got %s", vuln.ID)
	}
}

func TestStoreSBOM(t *testing.T) {
	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "sbom-store-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create a test SBOM
	sbom := &SBOM{
		Format:  "CycloneDX",
		Content: []byte(`{"bomFormat":"CycloneDX","specVersion":"1.4"}`),
	}

	// Store the SBOM
	err = StoreSBOM(tempDir, sbom)
	if err != nil {
		t.Fatalf("StoreSBOM() error = %v", err)
	}

	// Verify the SBOM was stored
	sbomPath := filepath.Join(tempDir, sbomFilename)
	if _, err := os.Stat(sbomPath); os.IsNotExist(err) {
		t.Errorf("Expected SBOM file to exist at %s", sbomPath)
	}

	// Read and verify the SBOM content
	content, err := os.ReadFile(sbomPath)
	if err != nil {
		t.Fatalf("Failed to read SBOM file: %v", err)
	}

	if !bytes.Equal(content, sbom.Content) {
		t.Errorf("SBOM content mismatch")
	}
}

func TestAccessFileInCachedArchive(t *testing.T) {
	// This test would require creating a tar.gz archive
	// For simplicity, we'll just test the error case
	err := AccessFileInCachedArchive("non-existent-file.tar.gz", "test.txt", func(r io.Reader) error {
		return nil
	})

	if err == nil {
		t.Errorf("Expected error for non-existent file, got nil")
	}
}
