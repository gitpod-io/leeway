package cmd

import (
	log "github.com/sirupsen/logrus"
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

		if ok, _ := cmd.Flags().GetBool("go-link"); ok {
			err = linker.LinkGoModules(&ws)
			if err != nil {
				return err
			}
		} else {
			log.Info("go module linking disabled")
		}

		if ok, _ := cmd.Flags().GetBool("yarn2-link"); ok {
			err = linker.LinkYarnPackagesWithYarn2(&ws)
			if err != nil {
				return err
			}
		} else {
			log.Info("yarn2 package linking disabled")
		}

		return nil
	},
}

func init() {
	addExperimentalCommand(rootCmd, linkCmd)

	linkCmd.Flags().Bool("yarn2-link", false, "link yarn packages using yarn2 resolutions")
	linkCmd.Flags().Bool("go-link", true, "link Go modules")
}
