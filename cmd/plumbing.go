package cmd

import (
	"github.com/spf13/cobra"
)

// plumbingCmd represents the version command
var plumbingCmd = &cobra.Command{
	Use:    "plumbing",
	Short:  "Internal commands used by leeway itself",
	Hidden: true,
	Args:   cobra.MinimumNArgs(1),
}

func init() {
	rootCmd.AddCommand(plumbingCmd)
}
