package cmd

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/gitpod-io/leeway/pkg/leeway"
)

// fmtCmd represents the version command
var fmtCmd = &cobra.Command{
	Use:   "fmt [files...]",
	Short: "Formats BUILD.yaml files",
	RunE: func(cmd *cobra.Command, args []string) error {
		fns := args
		if len(fns) == 0 {
			ws, err := getWorkspace()
			if err != nil {
				return err
			}
			for _, comp := range ws.Components {
				fns = append(fns, filepath.Join(comp.Origin, "BUILD.yaml"))
			}
		}

		var (
			inPlace, _ = cmd.Flags().GetBool("in-place")
			fix, _     = cmd.Flags().GetBool("fix")
		)
		for _, fn := range fns {
			err := formatBuildYaml(fn, inPlace, fix)
			if err != nil {
				return err
			}
		}

		return nil
	},
}

func formatBuildYaml(fn string, inPlace, fix bool) error {
	f, err := os.OpenFile(fn, os.O_RDWR, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	var out io.Writer = os.Stdout
	if inPlace {
		buf := bytes.NewBuffer(nil)
		out = buf
		//nolint:errcheck
		defer func() {
			f.Seek(0, 0)
			f.Truncate(0)

			io.Copy(f, buf)
		}()
	} else {
		fmt.Printf("---\n# %s\n", fn)
	}

	err = leeway.FormatBUILDyaml(out, f, fix)
	if err != nil {
		return err
	}

	return nil
}

func init() {
	rootCmd.AddCommand(fmtCmd)

	fmtCmd.Flags().BoolP("in-place", "i", false, "format file in place rather than printing it to stdout")
	fmtCmd.Flags().BoolP("fix", "f", false, "fix issues other than formatting (e.g. deprecated package types)")
}
