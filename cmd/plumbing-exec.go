package cmd

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// plumbingExecCmd represents the version command
var plumbingExecCmd = &cobra.Command{
	Use:   "exec <file>",
	Short: "Executes commands",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		input, err := os.ReadFile(args[0])
		if err != nil {
			log.WithError(err).Fatal("cannot read input file")
		}

		dec, err := base64.StdEncoding.DecodeString(string(input))
		if err != nil {
			log.WithError(err).Fatal("failed to base64 decode commands")
		}

		var commands [][]string
		err = json.Unmarshal(dec, &commands)
		if err != nil {
			log.WithError(err).Fatal("failed to unmarshal commands")
		}

		for _, c := range commands {
			name, args := c[0], c[1:]
			log.WithField("command", strings.Join(append([]string{name}, args...), " ")).Debug("running")

			cmd := exec.Command(name, args...)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			cmd.Stdin = os.Stdin
			err := cmd.Run()
			if err != nil {
				os.Exit(1)
			}
		}
	},
}

func init() {
	plumbingCmd.AddCommand(plumbingExecCmd)
}
