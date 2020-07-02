// +build linux

package cmd

import (
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/typefox/leeway/pkg/graphview"
)

// graphviewCmd represents the mount command
var graphviewCmd = &cobra.Command{
	Use:   "graphview <package>",
	Short: "[experimental] Serves a web-based view of a package's dependencies",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		_, pkg, _, _ := getTarget(args, false)
		if pkg == nil {
			log.Fatal("graphview needs a package")
		}

		log.Fatal(graphview.Serve(pkg, ":8080"))

		return nil
	},
}

func init() {
	addExperimentalCommand(rootCmd, graphviewCmd)
}
