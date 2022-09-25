package cmd

import (
	"os"
	"path/filepath"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/gitpod-io/leeway/pkg/linker"
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
		_, pkg, _, _ := getTarget(args, false)

		switch val, _ := cmd.Flags().GetString("go-link"); val {
		case "auto":
			if _, ferr := os.Stat(filepath.Join(ws.Origin, "go.work")); ferr == nil {
				err = linker.LinkGoWorkspace(&ws)
			} else {
				err = linker.LinkGoModules(&ws, pkg)
			}
		case "module":
			err = linker.LinkGoModules(&ws, pkg)
		case "workspace":
			err = linker.LinkGoWorkspace(&ws)
		}
		if err != nil {
			return err
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
	rootCmd.AddCommand(linkCmd)

	linkCmd.Flags().Bool("yarn2-link", false, "link yarn packages using yarn2 resolutions")
	linkCmd.Flags().String("go-link", "auto", "link Go modules or workspace. Valid values are auto, module or workspace")
}
