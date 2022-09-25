//go:build linux
// +build linux

package cmd

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// unmountCmd represents the version command
var unmountCmd = &cobra.Command{
	Use:   "unmount <mountpoint>",
	Short: "[experimental] Unmounts a previously mounted overlay",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		mp := args[0]
		origin, upper, delmp, err := findOverlayMount(mp)
		if err != nil {
			return err
		}

		err = syscall.Unmount(mp, 0)
		if err != nil {
			return err
		}
		defer func() {
			err = syscall.Unmount(delmp, 0)
			if err != nil {
				logrus.WithError(err).WithField("mountpoint", delmp).Error("cannot unmount delup overlay")
			}
		}()

		applyChanges, _ := cmd.Flags().GetBool("apply")
		if !applyChanges {
			return nil
		}

		err = filepath.Walk(upper, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			dst := filepath.Join(origin, strings.TrimPrefix(path, upper))
			if path == upper || dst == origin {
				return nil
			}

			if info.Mode()&os.ModeCharDevice == os.ModeCharDevice {
				logrus.WithField("dest", dst).Debug("applying change: deleting file")
				err = os.RemoveAll(dst)
				if err != nil && !os.IsNotExist(err) {
					return err
				}
				return nil
			}

			if info.IsDir() {
				logrus.WithField("dest", dst).Debug("applying change: creating directory")
				err = os.MkdirAll(dst, info.Mode())
				if err != nil && !os.IsExist(err) {
					return err
				}
				stat := info.Sys().(*syscall.Stat_t)
				err = os.Chown(dst, int(stat.Uid), int(stat.Gid))
				if err != nil {
					return err
				}
				return nil
			}

			src, err := os.Open(path)
			if err != nil {
				return err
			}
			defer src.Close()

			f, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, info.Mode())
			if err != nil {
				return err
			}
			defer f.Close()

			logrus.WithField("dest", dst).Debug("applying change: copying content")
			_, err = io.Copy(f, src)
			if err != nil {
				return err
			}

			stat := info.Sys().(*syscall.Stat_t)
			err = os.Chown(dst, int(stat.Uid), int(stat.Gid))
			if err != nil {
				return err
			}

			return nil
		})
		if err != nil {
			return err
		}

		return nil
	},
}

func findOverlayMount(mountpoint string) (origin, upper, delmp string, err error) {
	mnts, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return
	}

	for _, row := range strings.Split(string(mnts), "\n") {
		segs := strings.Split(row, " ")
		if len(segs) < 4 {
			continue
		}
		if segs[1] != mountpoint {
			continue
		}

		opts := strings.Split(segs[3], ",")
		for _, opt := range opts {
			if strings.HasPrefix(opt, "lowerdir=") {
				delmp = strings.TrimPrefix(opt, "lowerdir=")
			} else if strings.HasPrefix(opt, "upperdir=") {
				upper = strings.TrimPrefix(opt, "upperdir=")
			}
		}
		if delmp == "" {
			err = fmt.Errorf("did not find lowerdir")
			return
		}
		if upper == "" {
			err = fmt.Errorf("did not find upperdir")
			return
		}
	}
	for _, row := range strings.Split(string(mnts), "\n") {
		segs := strings.Split(row, " ")
		if len(segs) < 4 {
			continue
		}
		if segs[1] != delmp {
			continue
		}

		opts := strings.Split(segs[3], ",")
		for _, opt := range opts {
			if strings.HasPrefix(opt, "lowerdir=") {
				origin = strings.TrimPrefix(opt, "lowerdir=")
			}
		}
		if origin == "" {
			err = fmt.Errorf("did not find origin")
			return
		}
	}

	if origin == "" {
		err = fmt.Errorf("did not find mountpoint")
		return
	}

	return
}

func init() {
	addExperimentalCommand(rootCmd, unmountCmd)

	unmountCmd.Flags().Bool("apply", true, "apply the changes made in the overlay back to the original workspace")
}
