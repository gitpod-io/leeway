package leeway

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"
)

// CopyWorkspace copies all folders/files from a workspace to a destination.
// If strict is true we'll only copy the files that leeway actully knows are source files.
// Otherwise we'll copy all files that are not excluded by the variant.
func CopyWorkspace(dst string, workspace *Workspace, strict bool) error {
	out, err := exec.Command("cp", "-R", workspace.Origin, dst).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, string(out))
	}

	return DeleteNonWorkspaceFiles(dst, workspace, strict)
}

// DeleteNonWorkspaceFiles removes all files that do not belong to a workspace.
// If strict is true this function deletes all files that are not listed as source in a package.
// If strict is fales this function deletes files excluded by a variant.
func DeleteNonWorkspaceFiles(dst string, workspace *Workspace, strict bool) (err error) {
	var (
		excl = make(map[string]struct{})
		incl = make(map[string]struct{})
	)
	if strict {
		for _, pkg := range workspace.Packages {
			for _, s := range pkg.Sources {
				rels := strings.TrimPrefix(s, workspace.Origin)
				incl[rels] = struct{}{}

				// package sources are files only - we need to include their parent directories as well
				for p := filepath.Dir(rels); p != "/"; p = filepath.Dir(p) {
					incl[p] = struct{}{}
				}
			}
		}
	} else {
		err = filepath.Walk(workspace.Origin, func(path string, info os.FileInfo, err error) error {
			s := strings.TrimPrefix(path, workspace.Origin)
			incl[s] = struct{}{}
			return nil
		})
		if err != nil {
			return err
		}

		if workspace.SelectedVariant != nil {
			vinc, vexc, err := workspace.SelectedVariant.ResolveSources(workspace, dst)
			if err != nil {
				return err
			}

			for _, p := range vinc {
				incl[strings.TrimPrefix(p, dst)] = struct{}{}
			}
			for _, p := range vexc {
				excl[strings.TrimPrefix(p, dst)] = struct{}{}
			}
		}
	}

	// keep if incl and not excl
	return filepath.Walk(dst, func(path string, info os.FileInfo, err error) error {
		if path == dst {
			return nil
		}

		s := strings.TrimPrefix(path, dst)
		_, inc := incl[s]
		_, exc := excl[s]
		lg := log.WithField("inc", inc).WithField("exc", exc).WithField("s", s).WithField("dst", dst)
		if inc && !exc {
			lg.Debug("not deleting file")
			return nil
		}
		lg.Debug("deleting file")

		return os.RemoveAll(path)
	})
}
