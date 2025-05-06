package cmd

import (
	"os"

	"github.com/gitpod-io/leeway/pkg/leeway"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// sbomScanCmd represents the sbom scan command
var sbomScanCmd = &cobra.Command{
	Use:   "scan [package]",
	Short: "Scans a package's SBOM for vulnerabilities",
	Long: `Scans a package's SBOM for vulnerabilities and exports the results to a specified directory.
	
This command uses existing SBOM files from previously built packages. It checks if SBOM is enabled
in the workspace settings. If not, it aborts. The scan results are exported to the directory
specified by the --output-dir flag.

When used with --with-dependencies, it scans the package and all its dependencies for vulnerabilities.

If no package is specified, the workspace's default target is used.`,
	Args: cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		// Get the package
		_, pkg, _, _ := getTarget(args, false)
		if pkg == nil {
			log.Fatal("sbom scan requires a package or a default target in the workspace")
		}

		// Get cache
		_, localCache := getBuildOpts(cmd)

		// Get output directory
		outputDir, _ := cmd.Flags().GetString("output-dir")
		if outputDir == "" {
			log.Fatal("--output-dir is required")
		}

		// Create output directory if it doesn't exist
		if err := os.MkdirAll(outputDir, 0755); err != nil {
			log.WithError(err).Fatalf("cannot create output directory %s", outputDir)
		}

		// Get with-dependencies flag
		withDependencies, _ := cmd.Flags().GetBool("with-dependencies")

		var allpkg []*leeway.Package
		allpkg = append(allpkg, pkg)

		if withDependencies {
			// Get all dependencies
			deps := pkg.GetTransitiveDependencies()
			log.Infof("Scanning SBOMs for %s and %d dependencies to %s", pkg.FullName(), len(deps), outputDir)

			allpkg = append(allpkg, deps...)
		}

		// Download packages from remote cache when needed
		for _, p := range allpkg {
			GetPackagePath(p, localCache)
		}

		// Get update-ignore-rules and remove-outdated-rules flags
		updateIgnoreRules, _ := cmd.Flags().GetString("update-ignore-rules")
		removeOutdatedRules, _ := cmd.Flags().GetBool("remove-outdated-rules")

		if err := leeway.ScanAllPackagesForVulnerabilities(localCache, allpkg, outputDir, updateIgnoreRules, removeOutdatedRules); err != nil {
			log.WithError(err).Fatalf("Failed to scan package %s for vulnerabilities", pkg.FullName())
		}

		if withDependencies {
			log.Infof("Vulnerability scan completed for package %s and its dependencies", pkg.FullName())
		} else {
			log.Infof("Vulnerability scan completed for package %s", pkg.FullName())
		}
		log.Infof("Scan results exported to %s", outputDir)

		// If we have failOn configured, the ScanPackageForVulnerabilities function will have already
		// returned an error if vulnerabilities at those severity levels were found
	},
}

func init() {
	sbomScanCmd.Flags().String("output-dir", "", "Directory to export scan results (required)")
	if err := sbomScanCmd.MarkFlagRequired("output-dir"); err != nil {
		log.WithError(err).Fatal("failed to mark output-dir flag as required")
	}
	sbomScanCmd.Flags().Bool("with-dependencies", false, "Scan the package and all its dependencies")
	sbomScanCmd.Flags().String("update-ignore-rules", "", "Update ignore rules in BUILD.yaml for vulnerabilities with specified severity levels (comma-separated, e.g., 'critical,high')")
	sbomScanCmd.Flags().Bool("remove-outdated-rules", false, "Remove ignore rules that no longer match any findings")

	sbomCmd.AddCommand(sbomScanCmd)
	addBuildFlags(sbomScanCmd)
}
