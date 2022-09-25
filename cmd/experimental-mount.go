//go:build linux
// +build linux

package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/gitpod-io/leeway/pkg/leeway"
)

// mountCmd represents the mount command
var mountCmd = &cobra.Command{
	Use:   "mount <destination>",
	Short: "[experimental] Mounts a package or workspace variant",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ws, err := getWorkspace()
		if err != nil {
			return fmt.Errorf("cannot load workspace: %q", err)
		}

		dest := args[0]
		err = os.MkdirAll(dest, 0777)
		if err != nil && !os.IsExist(err) {
			return fmt.Errorf("cannot create destination dir: %q", err)
		}

		wdbase, _ := cmd.Flags().GetString("workdir")
		if wdbase != "" {
			err = os.MkdirAll(wdbase, 0777)
		} else {
			wdbase, err = os.MkdirTemp(filepath.Dir(dest), "leeway-workdir-*")
		}
		if err != nil && !os.IsExist(err) {
			return err
		}
		var (
			delup = filepath.Join(wdbase, "delup")
			delmp = filepath.Join(wdbase, "delmp")
			wd    = filepath.Join(wdbase, "work")
			upper = filepath.Join(wdbase, "upper")
		)
		for _, p := range []string{delup, delmp, wd, upper} {
			err = os.MkdirAll(p, 0777)
			if err != nil && !os.IsExist(err) {
				return err
			}
		}

		// prepare delup
		err = syscall.Mount("overlay", delmp, "overlay", 0, fmt.Sprintf("lowerdir=%s,upperdir=%s,workdir=%s", ws.Origin, delup, wd))
		if err != nil {
			return fmt.Errorf("cannot mount delup overlay: %q", err)
		}
		strict, _ := cmd.Flags().GetBool("strict")
		err = leeway.DeleteNonWorkspaceFiles(delmp, &ws, strict)
		if err != nil {
			return err
		}

		// actually mount overlay
		err = syscall.Mount("overlay", dest, "overlay", 0, fmt.Sprintf("lowerdir=%s,upperdir=%s,workdir=%s", delmp, upper, wd))
		if err != nil {
			return fmt.Errorf("cannot mount overlay: %q", err)
		}

		return nil
	},
}

func init() {
	addExperimentalCommand(rootCmd, mountCmd)

	mountCmd.Flags().String("workdir", "", "overlayfs workdir location (must be on the same volume as the destination)")
	mountCmd.Flags().Bool("strict", false, "keep only package source files")
}
