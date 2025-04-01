package cmd

import (
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// sbomExportCmd represents the sbom export command
var sbomExportCmd = &cobra.Command{
	Use:   "export <package>",
	Short: "Exports the SBOM of a (previously built) package",
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		// This is a placeholder for the actual implementation
		log.Info("SBOM export functionality will be implemented here")
	},
}

func init() {
	sbomCmd.AddCommand(sbomExportCmd)
	addBuildFlags(sbomExportCmd)
}
