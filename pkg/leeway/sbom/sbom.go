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
	"github.com/gitpod-io/leeway/pkg/leeway/common"
	log "github.com/sirupsen/logrus"
	"golang.org/x/xerrors"
)

// GenerateSBOM generates a Software Bill of Materials (SBOM) for a package
func GenerateSBOM(pkgInfo *common.PackageInfo, buildDir string, options *SBOMOptions) (*sbom.SBOM, error) {
	if options == nil {
		options = DefaultSBOMOptions()
	}

	log.WithFields(log.Fields{
		"package": pkgInfo.FullName,
		"format":  options.Format,
	}).Info("Generating SBOM")

	// For now, we'll just generate a generic SBOM from the build directory
	sbomDoc, err := generateSBOMFromDirectory(buildDir)

	if err != nil {
		return nil, xerrors.Errorf("failed to generate SBOM: %w", err)
	}

	// Write SBOM to file if output path is specified
	if options.OutputPath != "" {
		if err := WriteSBOMToFile(sbomDoc, options.OutputPath, options.Format); err != nil {
			return nil, xerrors.Errorf("failed to write SBOM to file: %w", err)
		}
	}

	return sbomDoc, nil
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
