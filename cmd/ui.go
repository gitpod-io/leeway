package cmd

import (
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	uibackend "github.com/typefox/leeway/pkg/ui/backend"
)

// versionCmd represents the version command
var uiCmd = &cobra.Command{
	Use:   "ui <addr>",
	Short: "Starts a leeway UI server - this is experimental",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		srv, err := uibackend.NewServer()
		if err != nil {
			log.Fatal(err)
		}

		err = srv.Serve(args[0])
		if err != nil {
			log.Fatal(err)
		}
	},
}

func init() {
	rootCmd.AddCommand(uiCmd)
}
