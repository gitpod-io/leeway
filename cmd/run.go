package cmd

import (
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// runCmd represents the version command
var runCmd = &cobra.Command{
	Use:   "run <script>",
	Short: "Executes a script",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		_, _, script, _ := getTarget(args, true)
		if script == nil {
			log.Fatal("tree needs a package")
		}

		opts, _ := getBuildOpts(cmd)
		err := script.Run(opts...)
		if err != nil {
			log.Fatal(err)
		}
	},
}

func init() {
	rootCmd.AddCommand(runCmd)
	addBuildFlags(runCmd)
}
