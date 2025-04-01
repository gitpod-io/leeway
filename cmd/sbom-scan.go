package cmd

import (
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// sbomScanCmd represents the sbom scan command
var sbomScanCmd = &cobra.Command{
	Use:   "scan <package>",
	Short: "Scans a package's SBOM for vulnerabilities",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		// This is a placeholder for the actual implementation
		log.Info("SBOM vulnerability scanning functionality will be implemented here")
	},
}

func init() {
	sbomScanCmd.Flags().Bool("fail-on-critical", true, "fail the scan if critical vulnerabilities are found")
	sbomScanCmd.Flags().Bool("fail-on-high", false, "fail the scan if high vulnerabilities are found")

	sbomCmd.AddCommand(sbomScanCmd)
	addBuildFlags(sbomScanCmd)
}
