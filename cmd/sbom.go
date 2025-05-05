package cmd

import (
	"github.com/spf13/cobra"
)

// sbomCmd represents the sbom command
var sbomCmd = &cobra.Command{
	Use:   "sbom <command>",
	Short: "Helpful commands for working with Software Bill of Materials (SBOM)",
	Long: `Helpful commands for working with Software Bill of Materials (SBOM).
	
The subcommands (export, scan) can be used with or without specifying a package.
If no package is specified, the workspace's default target is used.`,
	Args: cobra.MinimumNArgs(1),
}

func init() {
	rootCmd.AddCommand(sbomCmd)
}
