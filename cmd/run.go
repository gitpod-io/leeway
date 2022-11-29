package cmd

import (
	"errors"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
)

// runCmd represents the version command
var runCmd = &cobra.Command{
	Use:   "run [scripts]",
	Short: "Executes one or more scripts in parallel",
	Long: `Executes one or more scripts in parallel
All scripts will run to completion, regardless of whether or not the other scripts exit with errors.

Should any of the scripts fail Leeway will exit with an exit code of 1 once all scripts are done executing.
`,
	Args: cobra.MinimumNArgs(1),
	Run:  run,
}

func run(cmd *cobra.Command, args []string) {
	g := new(errgroup.Group)
	for _, scriptName := range args {
		scriptName := scriptName
		g.Go(func() error {
			return runScript(cmd, scriptName)
		})
	}
	err := g.Wait()
	if err != nil {
		log.Fatal(err)
	}
}

func runScript(cmd *cobra.Command, name string) error {
	_, _, script, _ := getTarget([]string{name}, true)
	if script == nil {
		return errors.New("tree needs a package")
	}
	opts, _ := getBuildOpts(cmd)
	return script.Run(opts...)
}

func init() {
	rootCmd.AddCommand(runCmd)
	addBuildFlags(runCmd)
}
