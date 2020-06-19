// +build linux

package cmd

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/bmatcuk/doublestar"
	"github.com/spf13/cobra"
	"github.com/typefox/leeway/pkg/leeway"
)

// mountCmd represents the mount command
var mountCmd = &cobra.Command{
	Use:   "mount <destination> [package]",
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

		var pkg *leeway.Package
		if len(args) > 1 {
			pkgn := args[1]
			for _, p := range ws.Packages {
				if p.FullName() == pkgn {
					pkg = p
					break
				}
			}
		}

		wdbase, _ := cmd.Flags().GetString("workdir")
		if wdbase != "" {
			err = os.MkdirAll(wdbase, 0777)
		} else {
			wdbase, err = ioutil.TempDir(filepath.Dir(dest), "leeway-workdir-*")
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
		err = deleteFilesOtherThan(delmp, &ws, pkg, ws.SelectedVariant)
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

func deleteFilesOtherThan(loc string, workspace *leeway.Workspace, pkg *leeway.Package, variant *leeway.PackageVariant) error {
	dc := make(map[string]struct{})

	if pkg != nil {
		fns, err := doublestar.Glob(filepath.Join(loc, "**/*"))
		if err != nil {
			return fmt.Errorf("cannot list files: %q", err)
		}
		for _, del := range fns {
			dc[filepath.Join(loc, strings.TrimPrefix(pkg.C.W.Origin, del))] = struct{}{}
		}

		for _, inc := range pkg.Sources {
			delete(dc, filepath.Join(loc, strings.TrimPrefix(pkg.C.W.Origin, inc)))
		}
	} else if variant != nil {
		for _, p := range workspace.Packages {
			loc := filepath.Join(loc, strings.TrimPrefix(p.C.Origin, workspace.Origin))

			for _, excl := range variant.Sources.Exclude {
				fns, err := doublestar.Glob(filepath.Join(loc, excl))
				if err != nil {
					return fmt.Errorf("cannot list variant exluded files: %q", err)
				}

				for _, fn := range fns {
					dc[fn] = struct{}{}
				}
			}
		}

	} else {
		return fmt.Errorf("mounting without package or variant would result in an empty directory")
	}

	for f := range dc {
		err := os.RemoveAll(f)
		if err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("cannot remove superflous file: %q", err)
		}
	}

	return nil
}

func init() {
	rootCmd.AddCommand(mountCmd)

	mountCmd.Flags().String("workdir", "", "overlayfs workdir location (must be on the same volume as the destination)")
}
