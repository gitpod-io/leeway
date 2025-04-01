package cmd

import (
	"github.com/spf13/cobra"
)

// sbomCmd represents the sbom command
var sbomCmd = &cobra.Command{
	Use:     "sbom <command>",
	Short:   "Commands for working with Software Bill of Materials",
	Args:    cobra.MinimumNArgs(1),
	Aliases: []string{"bom"},
}

func init() {
	rootCmd.AddCommand(sbomCmd)
}
