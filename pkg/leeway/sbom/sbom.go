package sbom

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/format/cyclonedxjson"
	"github.com/anchore/syft/syft/format/spdxjson"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
	"github.com/gitpod-io/leeway/pkg/leeway"
	log "github.com/sirupsen/logrus"
	"golang.org/x/xerrors"
)

// GenerateSBOM generates a Software Bill of Materials (SBOM) for a package
func GenerateSBOM(p *leeway.Package, buildDir string, options *SBOMOptions) (*sbom.SBOM, error) {
	if options == nil {
		options = DefaultSBOMOptions()
	}

	log.WithFields(log.Fields{
		"package": p.FullName(),
		"format":  options.Format,
	}).Info("Generating SBOM")

	var sbomDoc *sbom.SBOM
	var err error

	switch p.Type {
	case leeway.DockerPackage:
		sbomDoc, err = generateDockerSBOM(p, buildDir)
	case leeway.GoPackage:
		sbomDoc, err = generateGoSBOM(p, buildDir)
	case leeway.YarnPackage:
		sbomDoc, err = generateYarnSBOM(p, buildDir)
	case leeway.GenericPackage:
		sbomDoc, err = generateGenericSBOM(p, buildDir)
	default:
		return nil, xerrors.Errorf("unsupported package type for SBOM generation: %s", p.Type)
	}

	if err != nil {
		return nil, xerrors.Errorf("failed to generate SBOM: %w", err)
	}

	// Write SBOM to file if output path is specified
	if options.OutputPath != "" {
		if err := writeSBOMToFile(sbomDoc, options.OutputPath, options.Format); err != nil {
			return nil, xerrors.Errorf("failed to write SBOM to file: %w", err)
		}
	}

	return sbomDoc, nil
}

// generateDockerSBOM generates an SBOM for a Docker package
func generateDockerSBOM(p *leeway.Package, buildDir string) (*sbom.SBOM, error) {
	// For Docker packages, we need to find the image name
	cfg, ok := p.Config.(leeway.DockerPkgConfig)
	if !ok {
		return nil, xerrors.Errorf("package should have Docker config")
	}

	// Check if we have a container directory with extracted content
	containerDir := filepath.Join(buildDir, "container")
	contentDir := filepath.Join(containerDir, "content")
	
	if _, err := os.Stat(contentDir); err == nil {
		// We have extracted content, use directory source
		return generateSBOMFromDirectory(contentDir)
	}

	// If we don't have extracted content, check if we have image names
	imgNamesFile := filepath.Join(buildDir, leeway.DockerImageNamesFiles)
	if _, err := os.Stat(imgNamesFile); err == nil {
		// Read the image name from the file
		imgNames, err := os.ReadFile(imgNamesFile)
		if err != nil {
			return nil, xerrors.Errorf("failed to read image names file: %w", err)
		}

		// Use the first image name
		imgName := strings.TrimSpace(strings.Split(string(imgNames), "\n")[0])
		if imgName != "" {
			return generateSBOMFromImage(imgName)
		}
	}

	// If we have image names in the config, use the first one
	if len(cfg.Image) > 0 {
		return generateSBOMFromImage(cfg.Image[0])
	}

	return nil, xerrors.Errorf("could not determine Docker image for SBOM generation")
}

// generateGoSBOM generates an SBOM for a Go package
func generateGoSBOM(p *leeway.Package, buildDir string) (*sbom.SBOM, error) {
	// For Go packages, we analyze the go.mod file
	goModPath := filepath.Join(buildDir, "go.mod")
	if _, err := os.Stat(goModPath); err != nil {
		return nil, xerrors.Errorf("go.mod file not found: %w", err)
	}

	return generateSBOMFromDirectory(buildDir)
}

// generateYarnSBOM generates an SBOM for a Yarn package
func generateYarnSBOM(p *leeway.Package, buildDir string) (*sbom.SBOM, error) {
	// For Yarn packages, we analyze the package.json and node_modules
	packageJSONPath := filepath.Join(buildDir, "package.json")
	if _, err := os.Stat(packageJSONPath); err != nil {
		return nil, xerrors.Errorf("package.json file not found: %w", err)
	}

	return generateSBOMFromDirectory(buildDir)
}

// generateGenericSBOM generates an SBOM for a Generic package
func generateGenericSBOM(p *leeway.Package, buildDir string) (*sbom.SBOM, error) {
	// For Generic packages, we analyze the directory
	return generateSBOMFromDirectory(buildDir)
}

// generateSBOMFromDirectory generates an SBOM from a directory
func generateSBOMFromDirectory(dir string) (*sbom.SBOM, error) {
	log.WithField("directory", dir).Debug("Generating SBOM from directory")

	// Create a source from the directory
	src, err := source.NewFromDirectory(context.Background(), dir)
	if err != nil {
		return nil, xerrors.Errorf("failed to create source from directory: %w", err)
	}
	defer src.Close()

	// Generate catalog from source
	catalog, relationships, err := syft.CatalogPackages(context.Background(), src, nil)
	if err != nil {
		return nil, xerrors.Errorf("failed to catalog packages: %w", err)
	}

	// Create SBOM
	sbomDoc := &sbom.SBOM{
		Artifacts: sbom.Artifacts{
			Packages:      catalog,
			Relationships: relationships,
		},
		Source: src.Metadata,
	}

	return sbomDoc, nil
}

// generateSBOMFromImage generates an SBOM from a Docker image
func generateSBOMFromImage(imgName string) (*sbom.SBOM, error) {
	log.WithField("image", imgName).Debug("Generating SBOM from Docker image")

	// Create a source from the image
	src, err := source.NewFromImage(context.Background(), imgName, nil)
	if err != nil {
		return nil, xerrors.Errorf("failed to create source from image: %w", err)
	}
	defer src.Close()

	// Generate catalog from source
	catalog, relationships, err := syft.CatalogPackages(context.Background(), src, nil)
	if err != nil {
		return nil, xerrors.Errorf("failed to catalog packages: %w", err)
	}

	// Create SBOM
	sbomDoc := &sbom.SBOM{
		Artifacts: sbom.Artifacts{
			Packages:      catalog,
			Relationships: relationships,
		},
		Source: src.Metadata,
	}

	return sbomDoc, nil
}

// WriteSBOMToFile writes an SBOM to a file in the specified format
func WriteSBOMToFile(sbomDoc *sbom.SBOM, outputPath, formatStr string) error {
	// Create parent directory if it doesn't exist
	if err := os.MkdirAll(filepath.Dir(outputPath), 0755); err != nil {
		return xerrors.Errorf("failed to create output directory: %w", err)
	}

	// Determine format
	var encoder format.Encoder
	switch strings.ToLower(formatStr) {
	case "cyclonedx", "cyclonedxjson":
		encoder = cyclonedxjson.NewEncoder()
	case "spdx", "spdxjson":
		encoder = spdxjson.NewEncoder()
	default:
		return xerrors.Errorf("unsupported SBOM format: %s", formatStr)
	}

	// Encode SBOM
	sbomBytes, err := encoder.Encode(context.Background(), *sbomDoc)
	if err != nil {
		return xerrors.Errorf("failed to encode SBOM: %w", err)
	}

	// Write to file
	if err := os.WriteFile(outputPath, sbomBytes, 0644); err != nil {
		return xerrors.Errorf("failed to write SBOM to file: %w", err)
	}

	log.WithField("path", outputPath).Info("SBOM written to file")
	return nil
}

// MergeSBOMs merges multiple SBOMs into a single SBOM
func MergeSBOMs(sboms []*sbom.SBOM) (*sbom.SBOM, error) {
	if len(sboms) == 0 {
		return nil, xerrors.Errorf("no SBOMs to merge")
	}

	if len(sboms) == 1 {
		return sboms[0], nil
	}

	// Create a new SBOM with the first SBOM's source
	merged := &sbom.SBOM{
		Source: sboms[0].Source,
		Artifacts: sbom.Artifacts{
			Packages:      pkg.NewCollection(),
			Relationships: sboms[0].Relationships,
		},
	}

	// Add packages from all SBOMs
	for _, s := range sboms {
		s.Artifacts.Packages.Enumerate(func(p pkg.Package) error {
			merged.Artifacts.Packages.Add(p)
			return nil
		})
		merged.Artifacts.Relationships = append(merged.Artifacts.Relationships, s.Artifacts.Relationships...)
	}

	return merged, nil
}

// GetSBOMSummary returns a summary of an SBOM
func GetSBOMSummary(sbomDoc *sbom.SBOM) (map[string]interface{}, error) {
	summary := make(map[string]interface{})

	// Count packages by type
	packagesByType := make(map[string]int)
	sbomDoc.Artifacts.Packages.Enumerate(func(p pkg.Package) error {
		packagesByType[string(p.Type)]++
		return nil
	})
	summary["packagesByType"] = packagesByType

	// Count total packages
	var totalPackages int
	sbomDoc.Artifacts.Packages.Enumerate(func(p pkg.Package) error {
		totalPackages++
		return nil
	})
	summary["totalPackages"] = totalPackages

	// Add source information
	summary["source"] = map[string]interface{}{
		"type": sbomDoc.Source.Metadata.Type,
		"id":   sbomDoc.Source.Metadata.ID,
	}

	return summary, nil
}

// GetSBOMJSON returns the SBOM as JSON
func GetSBOMJSON(sbomDoc *sbom.SBOM) ([]byte, error) {
	encoder := cyclonedxjson.NewEncoder()
	return encoder.Encode(context.Background(), *sbomDoc)
}

// GetSBOMPackages returns a list of packages in the SBOM
func GetSBOMPackages(sbomDoc *sbom.SBOM) []map[string]interface{} {
	var packages []map[string]interface{}

	sbomDoc.Artifacts.Packages.Enumerate(func(p pkg.Package) error {
		pkg := map[string]interface{}{
			"name":    p.Name,
			"version": p.Version,
			"type":    string(p.Type),
		}

		if p.CPEs != nil && len(p.CPEs) > 0 {
			pkg["cpe"] = p.CPEs[0].String()
		}

		if p.PURL != "" {
			pkg["purl"] = p.PURL
		}

		packages = append(packages, pkg)
		return nil
	})

	return packages
}
