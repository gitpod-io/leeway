package cmd

import (
	"fmt"

	"github.com/gitpod-io/leeway/pkg/leeway"
	"github.com/spf13/cobra"
)

// versionCmd represents the version command
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Prints the version of this leeway build",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf(leeway.Version)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
