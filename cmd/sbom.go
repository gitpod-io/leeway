package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/gitpod-io/leeway/pkg/leeway"
	"github.com/gitpod-io/leeway/pkg/leeway/sbom"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var sbomCmd = &cobra.Command{
	Use:   "sbom [targetPackage]",
	Short: "Generate a Software Bill of Materials (SBOM) for a package",
	Args:  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		_, pkg, _, _ := getTarget(args, false)
		if pkg == nil {
			log.Fatal("sbom needs a package")
		}

		// Get options
		format, _ := cmd.Flags().GetString("format")
		output, _ := cmd.Flags().GetString("output")

		// Get build directory
		buildDir := os.Getenv(leeway.EnvvarBuildDir)
		if buildDir == "" {
			buildDir = filepath.Join(os.TempDir(), "leeway", "build")
		}

		// Create SBOM options
		options := &sbom.SBOMOptions{
			Format:     format,
			OutputPath: output,
		}

		// Get package info
		pkgInfo, err := pkg.GetPackageInfo()
		if err != nil {
			log.WithError(err).Fatal("failed to get package info")
		}

		// Generate SBOM
		sbomDoc, err := sbom.GenerateSBOM(pkgInfo, buildDir, options)
		if err != nil {
			log.WithError(err).Fatal("failed to generate SBOM")
		}

		// Write SBOM to file if output is specified
		if output != "" {
			if err := sbom.WriteSBOMToFile(sbomDoc, output, format); err != nil {
				log.WithError(err).Fatal("failed to write SBOM to file")
			}
			fmt.Printf("SBOM written to %s\n", output)
		} else {
			// Print SBOM summary
			summary, err := sbom.GetSBOMSummary(sbomDoc)
			if err != nil {
				log.WithError(err).Fatal("failed to get SBOM summary")
			}

			fmt.Printf("SBOM Summary for %s:\n", pkg.FullName())
			fmt.Printf("  Total Packages: %d\n", summary["totalPackages"])
			fmt.Printf("  Packages by Type:\n")
			for pkgType, count := range summary["packagesByType"].(map[string]int) {
				fmt.Printf("    %s: %d\n", pkgType, count)
			}
		}
	},
}

var cveCmd = &cobra.Command{
	Use:   "cve [targetPackage]",
	Short: "Scan a package for vulnerabilities",
	Args:  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		_, pkg, _, _ := getTarget(args, false)
		if pkg == nil {
			log.Fatal("cve needs a package")
		}

		// Get options
		sbomFormat, _ := cmd.Flags().GetString("sbom-format")
		output, _ := cmd.Flags().GetString("output")
		failOn, _ := cmd.Flags().GetStringSlice("fail-on")
		ignoreFile, _ := cmd.Flags().GetString("ignore-file")

		// Get build directory
		buildDir := os.Getenv(leeway.EnvvarBuildDir)
		if buildDir == "" {
			buildDir = filepath.Join(os.TempDir(), "leeway", "build")
		}

		// Create SBOM options
		sbomOptions := &sbom.SBOMOptions{
			Format: sbomFormat,
		}

		// Create CVE options
		cveOptions := &sbom.CVEOptions{
			FailOn:          failOn,
			OutputPath:      output,
			IncludeMetadata: true,
		}

		// Read ignore rules if specified
		if ignoreFile != "" {
			ignoreRules, err := sbom.ReadIgnoreRulesFromFile(ignoreFile)
			if err != nil {
				log.WithError(err).Fatal("failed to read ignore rules")
			}
			cveOptions.IgnoreRules = ignoreRules
		}

		// Get package info
		pkgInfo, err := pkg.GetPackageInfo()
		if err != nil {
			log.WithError(err).Fatal("failed to get package info")
		}

		// Generate SBOM
		sbomDoc, err := sbom.GenerateSBOM(pkgInfo, buildDir, sbomOptions)
		if err != nil {
			log.WithError(err).Fatal("failed to generate SBOM")
		}

		// Scan for vulnerabilities
		report, err := sbom.ScanForVulnerabilities(sbomDoc, cveOptions)
		if err != nil {
			log.WithError(err).Fatal("failed to scan for vulnerabilities")
		}

		// Write report to file if output is specified
		if output != "" {
			if err := report.WriteToFile(output); err != nil {
				log.WithError(err).Fatal("failed to write report to file")
			}
			fmt.Printf("Vulnerability report written to %s\n", output)
		}

		// Print report summary
		summary := sbom.GetVulnerabilitySummary(report)
		fmt.Printf("Vulnerability Scan Results for %s:\n", pkg.FullName())
		fmt.Printf("  Summary:\n")
		for _, severity := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE", "UNKNOWN"} {
			count := summary[severity]
			if count > 0 {
				fmt.Printf("    %s: %d\n", severity, count)
			}
		}

		// Check if there are vulnerabilities that should fail the build
		if report.HasFailureLevelVulnerabilities(failOn) {
			fmt.Println("\nVulnerabilities found with severity levels:", failOn)
			os.Exit(1)
		}
	},
}

func init() {
	rootCmd.AddCommand(sbomCmd)
	rootCmd.AddCommand(cveCmd)

	// SBOM command flags
	sbomCmd.Flags().StringP("format", "f", "cyclonedx", "SBOM format (cyclonedx, spdx)")
	sbomCmd.Flags().StringP("output", "o", "", "Path to write the SBOM file")

	// CVE command flags
	cveCmd.Flags().String("sbom-format", "cyclonedx", "SBOM format (cyclonedx, spdx)")
	cveCmd.Flags().StringP("output", "o", "", "Path to write the vulnerability report")
	cveCmd.Flags().StringSlice("fail-on", []string{"CRITICAL"}, "Severity levels to fail the build on (CRITICAL, HIGH, MEDIUM, LOW, NEGLIGIBLE)")
	cveCmd.Flags().String("ignore-file", "", "Path to a YAML file containing CVE ignore rules")
}
