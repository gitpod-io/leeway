package leeway

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"
	"golang.org/x/xerrors"
)

type GitInfo struct {
	WorkingCopyLoc string
	Commit         string
	Origin         string

	dirty      bool
	dirtyFiles map[string]struct{}
}

// GetGitInfo returns the git status required during a leeway build
func GetGitInfo(loc string) (*GitInfo, error) {
	gitfc := filepath.Join(loc, ".git")
	stat, err := os.Stat(gitfc)
	if err != nil || !stat.IsDir() {
		return nil, nil
	}

	cmd := exec.Command("git", "rev-parse", "HEAD")
	cmd.Dir = loc
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, err
	}
	res := GitInfo{
		WorkingCopyLoc: loc,
		Commit:         strings.TrimSpace(string(out)),
	}

	cmd = exec.Command("git", "config", "--get", "remote.origin.url")
	cmd.Dir = loc
	out, err = cmd.CombinedOutput()
	if err != nil && len(out) > 0 {
		return nil, err
	}
	res.Origin = strings.TrimSpace(string(out))

	cmd = exec.Command("git", "status", "--porcelain")
	cmd.Dir = loc
	out, err = cmd.CombinedOutput()
	if serr, ok := err.(*exec.ExitError); ok && serr.ExitCode() != 128 {
		// git status --short seems to exit with 128 all the time - that's ok, but we need to account for that.
		log.WithField("exitCode", serr.ExitCode()).Debug("git status --porcelain exited with failed exit code. Working copy is dirty.")
		res.dirty = true
	} else if _, ok := err.(*exec.ExitError); !ok && err != nil {
		return nil, err
	} else if len(strings.TrimSpace(string(out))) != 0 {
		log.WithField("out", string(out)).Debug("`git status --porcelain` produced output. Working copy is dirty.")

		res.dirty = true
		res.dirtyFiles, err = parseGitStatus(out)
		if err != nil {
			log.WithError(err).Warn("cannot parse git status: assuming all files are dirty")
		}
	}

	return &res, nil
}

// parseGitStatus parses the output of "git status --porcelain"
func parseGitStatus(out []byte) (files map[string]struct{}, err error) {
	in := strings.TrimSpace(string(out))
	if len(in) == 0 {
		// no files - nothing's dirty
		return nil, nil
	}

	lines := strings.Split(in, "\n")
	files = make(map[string]struct{}, len(lines))
	for _, l := range lines {
		segs := strings.Fields(l)
		if len(segs) == 0 {
			continue
		}
		if len(segs) != 2 {
			return nil, xerrors.Errorf("cannot parse git status \"%s\": expected two segments, got %d", l, len(segs))
		}
		files[segs[1]] = struct{}{}
	}
	return
}

// DirtyFiles returns true if a single file of the file list
// is dirty.
func (gi *GitInfo) DirtyFiles(files []string) bool {
	if !gi.dirty {
		// nothing's dirty
		log.WithField("workingCopy", gi.WorkingCopyLoc).Debug("building from a clean working copy")
		return false
	}
	if len(gi.dirtyFiles) == 0 {
		// we don't have any record of dirty files, just that the
		// working copy is dirty. Hence, we assume all files are dirty.
		log.WithField("workingCopy", gi.WorkingCopyLoc).Debug("no records of dirty files - assuming dirty Git working copy")
		return true
	}
	for _, f := range files {
		if !strings.HasPrefix(f, gi.WorkingCopyLoc) {
			// We don't know anything about this file, but the caller
			// might make important decisions on the dirty-state of
			// the files. For good measure we assume the file is dirty.
			log.WithField("workingCopy", gi.WorkingCopyLoc).WithField("fn", f).Debug("no records of this file - assuming it's dirty")
			return true
		}

		fn := strings.TrimPrefix(f, gi.WorkingCopyLoc)
		fn = strings.TrimPrefix(fn, "/")
		_, dirty := gi.dirtyFiles[fn]
		if dirty {
			log.WithField("workingCopy", gi.WorkingCopyLoc).WithField("fn", f).Debug("found dirty source file")
			return true
		}
	}
	return false
}
