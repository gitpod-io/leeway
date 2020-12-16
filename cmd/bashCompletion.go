package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

// bashCompletionCmd represents the bashCompletion command
var bashCompletionCmd = &cobra.Command{
	Use:    "bash-completion",
	Short:  "Provides bash completion for leeway. Use with `. <(leeway bash-completion)`",
	Hidden: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		return rootCmd.GenBashCompletion(os.Stdout)
	},
}

func init() {
	rootCmd.AddCommand(bashCompletionCmd)
}
