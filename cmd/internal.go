package cmd

import "github.com/spf13/cobra"

// describeCmd represents the describe command
var internalCmd = &cobra.Command{
	Use:    "internal",
	Short:  "Internal commands used by leeway itself",
	Hidden: true,
}

func init() {
	rootCmd.AddCommand(internalCmd)
}
