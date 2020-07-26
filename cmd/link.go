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

		if ws.Linker.GoModules {
			err = linker.LinkGoModules(&ws)
			if err != nil {
				return err
			}
		} else {
			log.Debug("go module linking disabled")
		}

		if ws.Linker.Yarn {
			err = linker.LinkYarnPackagesCrossWorkspace(&ws)
			if err != nil {
				return err
			}
		} else {
			log.Debug("yarn cross-workspace package linking disabled")
		}

		if ws.Linker.Yarn2 {
			err = linker.LinkYarnPackagesWithYarn2(&ws)
			if err != nil {
				return err
			}
		} else {
			log.Debug("yarn2 package linking disabled")
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(linkCmd)
}
