package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/gitpod-io/leeway/pkg/leeway"
	"github.com/gookit/color"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// securityCmd represents the security command
var securityCmd = &cobra.Command{
	Use:   "security",
	Short: "Security-related commands",
	Long: color.Render(`<light_yellow>Security commands</> provide functionality for vulnerability scanning and SBOM generation.

These commands allow you to:
  - Scan packages for vulnerabilities
  - Generate and view Software Bill of Materials (SBOM)
  - Configure security settings for your workspace

<white>Configuration</>
Security scanning can be configured in the WORKSPACE.yaml file:
  security:
    enabled: true
    sbomGeneration: true
    vulnerabilityScanning: true
    failOnVulnerabilities: false
    scanners:
      - name: "trivy"
        config:
          severity: "HIGH,CRITICAL"
          ignoreFile: ".trivyignore"
          skipDirectories:
            - "node_modules"
            - "vendor"
`),
}

// securityScanCmd represents the security scan command
var securityScanCmd = &cobra.Command{
	Use:   "scan [package]",
	Short: "Scan a package for vulnerabilities",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		_, pkg, _, _ := getTarget(args, false)
		if pkg == nil {
			log.Fatal("scan needs a package")
		}

		// Get build options
		opts, localCache := getBuildOpts(cmd)

		// Check if package is built
		pkgFN, exists := localCache.Location(pkg)
		if !exists {
			log.Fatalf("package %s is not built - build it first", pkg.FullName())
		}

		// Create a temporary directory for scanning
		tempDir, err := os.MkdirTemp("", "leeway-security-scan-")
		if err != nil {
			log.WithError(err).Fatal("failed to create temporary directory")
		}
		defer os.RemoveAll(tempDir)

		// Extract package to temporary directory
		log.WithField("package", pkg.FullName()).Info("extracting package for scanning")
		untarCmd, err := leeway.BuildUnTarCommand(
			leeway.WithInputFile(pkgFN),
			leeway.WithTargetDir(tempDir),
			leeway.WithAutoDetectCompression(true),
		)
		if err != nil {
			log.WithError(err).Fatal("failed to build untar command")
		}

		// Execute untar command
		untarCmd[0] = filepath.Join("/bin", untarCmd[0])
		cmd2 := untarCmd[0]
		args2 := untarCmd[1:]
		if err := run(nil, pkg, nil, tempDir, cmd2, args2...); err != nil {
			log.WithError(err).Fatal("failed to extract package")
		}

		// Create a workspace with security enabled
		workspace := pkg.C.W
		workspace.Security.Enabled = true
		workspace.Security.VulnerabilityScanning = true

		// Get severity from flag
		severity, _ := cmd.Flags().GetString("severity")
		if severity != "" {
			// Update or create Trivy scanner config
			var trivyConfigFound bool
			for i, scanner := range workspace.Security.Scanners {
				if scanner.Name == "trivy" {
					if scanner.Config == nil {
						scanner.Config = make(map[string]interface{})
					}
					scanner.Config["severity"] = severity
					workspace.Security.Scanners[i] = scanner
					trivyConfigFound = true
					break
				}
			}

			if !trivyConfigFound {
				workspace.Security.Scanners = append(workspace.Security.Scanners, leeway.ScannerConfig{
					Name: "trivy",
					Config: map[string]interface{}{
						"severity": severity,
					},
				})
			}
		}

		// Create a build context
		buildCtx := &leeway.BuildContext{
			BuildOptions: opts,
		}

		// Run security scan
		log.WithField("package", pkg.FullName()).Info("scanning package for vulnerabilities")
		err = leeway.RunSecurityScan(buildCtx, pkg, tempDir)
		if err != nil {
			log.WithError(err).Fatal("security scan failed")
		}

		// Check if scan results exist
		resultFile := filepath.Join(tempDir, "security-scan-result.json")
		if _, err := os.Stat(resultFile); os.IsNotExist(err) {
			log.Info("no vulnerabilities found")
			return
		}

		// Read scan results
		resultContent, err := os.ReadFile(resultFile)
		if err != nil {
			log.WithError(err).Fatal("failed to read scan results")
		}

		var result leeway.ScanResult
		if err := json.Unmarshal(resultContent, &result); err != nil {
			log.WithError(err).Fatal("failed to parse scan results")
		}

		// Display scan results
		if len(result.Vulnerabilities) == 0 {
			log.Info("no vulnerabilities found")
			return
		}

		fmt.Printf("\n%s\n", color.Bold.Render("Vulnerabilities found:"))
		fmt.Printf("%-16s %-10s %-20s %-15s %s\n", "ID", "Severity", "Package", "Version", "Description")
		fmt.Println(color.Gray.Render("--------------------------------------------------------------------------------"))

		for _, vuln := range result.Vulnerabilities {
			severityColor := color.FgGray
			switch vuln.Severity {
			case "CRITICAL":
				severityColor = color.FgRed
			case "HIGH":
				severityColor = color.FgLightRed
			case "MEDIUM":
				severityColor = color.FgYellow
			case "LOW":
				severityColor = color.FgGreen
			}

			fmt.Printf("%-16s %s %-20s %-15s %s\n",
				vuln.ID,
				severityColor.Render(fmt.Sprintf("%-10s", vuln.Severity)),
				vuln.Package,
				vuln.Version,
				truncateString(vuln.Description, 50),
			)
		}

		fmt.Printf("\nFound %d vulnerabilities in %s\n", len(result.Vulnerabilities), pkg.FullName())
	},
}

// securitySBOMCmd represents the security sbom command
var securitySBOMCmd = &cobra.Command{
	Use:   "sbom [package]",
	Short: "Generate or display SBOM for a package",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		_, pkg, _, _ := getTarget(args, false)
		if pkg == nil {
			log.Fatal("sbom needs a package")
		}

		// Get build options
		opts, localCache := getBuildOpts(cmd)

		// Check if package is built
		pkgFN, exists := localCache.Location(pkg)
		if !exists {
			log.Fatalf("package %s is not built - build it first", pkg.FullName())
		}

		// Check if we should generate a new SBOM
		generate, _ := cmd.Flags().GetBool("generate")
		if generate {
			// Create a temporary directory for SBOM generation
			tempDir, err := os.MkdirTemp("", "leeway-sbom-gen-")
			if err != nil {
				log.WithError(err).Fatal("failed to create temporary directory")
			}
			defer os.RemoveAll(tempDir)

			// Extract package to temporary directory
			log.WithField("package", pkg.FullName()).Info("extracting package for SBOM generation")
			untarCmd, err := leeway.BuildUnTarCommand(
				leeway.WithInputFile(pkgFN),
				leeway.WithTargetDir(tempDir),
				leeway.WithAutoDetectCompression(true),
			)
			if err != nil {
				log.WithError(err).Fatal("failed to build untar command")
			}

			// Execute untar command
			untarCmd[0] = filepath.Join("/bin", untarCmd[0])
			cmd2 := untarCmd[0]
			args2 := untarCmd[1:]
			if err := run(nil, pkg, nil, tempDir, cmd2, args2...); err != nil {
				log.WithError(err).Fatal("failed to extract package")
			}

			// Create a workspace with security enabled
			workspace := pkg.C.W
			workspace.Security.Enabled = true
			workspace.Security.SBOMGeneration = true

			// Create a build context
			buildCtx := &leeway.BuildContext{
				BuildOptions: opts,
			}

			// Generate SBOM
			log.WithField("package", pkg.FullName()).Info("generating SBOM")
			err = leeway.RunSecurityScan(buildCtx, pkg, tempDir)
			if err != nil {
				log.WithError(err).Fatal("SBOM generation failed")
			}

			// Check if SBOM exists
			sbomFile := filepath.Join(tempDir, leeway.SbomFilename)
			if _, err := os.Stat(sbomFile); os.IsNotExist(err) {
				log.Fatal("SBOM generation failed - no SBOM file found")
			}

			// Copy SBOM to output file
			outputFile, _ := cmd.Flags().GetString("output")
			if outputFile == "" {
				outputFile = fmt.Sprintf("%s-sbom.json", pkg.FilesystemSafeName())
			}

			sbomContent, err := os.ReadFile(sbomFile)
			if err != nil {
				log.WithError(err).Fatal("failed to read generated SBOM")
			}

			err = os.WriteFile(outputFile, sbomContent, 0644)
			if err != nil {
				log.WithError(err).Fatal("failed to write SBOM to output file")
			}

			log.WithField("file", outputFile).Info("SBOM generated successfully")
			return
		}

		// Try to retrieve existing SBOM
		sbom, err := leeway.RetrieveSBOM(pkgFN)
		if err != nil {
			log.WithError(err).Fatal("failed to retrieve SBOM - try using --generate to create one")
		}

		// Output SBOM to file or stdout
		outputFile, _ := cmd.Flags().GetString("output")
		if outputFile != "" {
			err = os.WriteFile(outputFile, sbom.Content, 0644)
			if err != nil {
				log.WithError(err).Fatal("failed to write SBOM to output file")
			}
			log.WithField("file", outputFile).Info("SBOM written to file")
		} else {
			fmt.Println(string(sbom.Content))
		}
	},
}

func init() {
	// Add security command to root command
	rootCmd.AddCommand(securityCmd)

	// Add subcommands to security command
	securityCmd.AddCommand(securityScanCmd)
	securityCmd.AddCommand(securitySBOMCmd)

	// Add flags to scan command
	securityScanCmd.Flags().String("severity", "HIGH,CRITICAL", "Severity levels to scan for")
	addBuildFlags(securityScanCmd)

	// Add flags to sbom command
	securitySBOMCmd.Flags().Bool("generate", false, "Generate a new SBOM even if one already exists")
	securitySBOMCmd.Flags().String("output", "", "Output file for SBOM (defaults to stdout)")
	addBuildFlags(securitySBOMCmd)
}

// truncateString truncates a string to the specified length and adds "..." if truncated
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
