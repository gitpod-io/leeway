//go:build linux
// +build linux

package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/gitpod-io/leeway/pkg/earthly"
)

var earthlyOpts struct {
	DefaultImage string
}

// earthlyCmd represents the mount command
var earthlyCmd = &cobra.Command{
	Use:   "earthly <dst>",
	Short: "[experimental] Generates earthly files",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ws, err := getWorkspace()
		if err != nil {
			return fmt.Errorf("cannot load workspace: %q", err)
		}

		gen := earthly.Generator{
			DefaultImage: earthlyOpts.DefaultImage,
		}
		fs, err := gen.Workspace(&ws)
		if err != nil {
			return err
		}
		err = earthly.Write(args[0], fs)
		if err != nil {
			return err
		}

		return nil
	},
}

func init() {
	addExperimentalCommand(rootCmd, earthlyCmd)

	earthlyCmd.Flags().StringVar(&earthlyOpts.DefaultImage, "default-image", "docker.io/library/alpine:latest", "Default image to use for earthly")
}
