package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/gitpod-io/leeway/pkg/leeway"
)

// exportCmd represents the version command
var exportCmd = &cobra.Command{
	Use:   "export <destination>",
	Short: "Copies a workspace to the destination",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if _, err := os.Stat(args[0]); err == nil {
			return fmt.Errorf("destination %s exists already", args[0])
		}

		workspace, err := getWorkspace()
		if err != nil {
			return err
		}

		strict, _ := cmd.Flags().GetBool("strict")
		return leeway.CopyWorkspace(args[0], &workspace, strict)
	},
}

func init() {
	rootCmd.AddCommand(exportCmd)

	exportCmd.Flags().Bool("strict", false, "keep only package source files")
}
