package cmd

import (
	"github.com/spf13/cobra"
)

// provenanceCmd represents the provenance command
var provenanceCmd = &cobra.Command{
	Use:     "provenance <command>",
	Short:   "Helpful commands for inspecing package provenance",
	Args:    cobra.MinimumNArgs(1),
	Aliases: []string{"prov"},
}

func init() {
	rootCmd.AddCommand(provenanceCmd)
}
