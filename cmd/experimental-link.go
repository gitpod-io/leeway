package cmd

import (
	"github.com/spf13/cobra"
	"github.com/typefox/leeway/pkg/linker"
)

// linkCmd represents the version command
var linkCmd = &cobra.Command{
	Use:   "link",
	Short: "Links all packages in-situ",
	RunE: func(cmd *cobra.Command, args []string) error {
		ws, err := getWorkspace()
		if err != nil {
			return err
		}

		err = linker.LinkGoModules(&ws)
		if err != nil {
			return err
		}

		return nil
	},
}

func init() {
	addExperimentalCommand(rootCmd, linkCmd)
}
