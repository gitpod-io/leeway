package leeway

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"
	"golang.org/x/xerrors"
)

const (
	gitDirName     = ".git"
	gitStatusError = 128
)

// GitError represents an error that occurred during a Git operation
type GitError struct {
	Op  string
	Err error
}

func (e *GitError) Error() string {
	return fmt.Sprintf("git operation %s failed: %v", e.Op, e.Err)
}

// GitInfo represents the state of a Git working copy including commit information,
// origin URL, and dirty state tracking.
type GitInfo struct {
	// WorkingCopyLoc is the absolute path to the Git working copy
	WorkingCopyLoc string
	// Commit is the current HEAD commit hash
	Commit string
	// Origin is the remote origin URL
	Origin string

	dirty      bool
	dirtyFiles map[string]struct{}
}

// executeGitCommand is a helper function to execute Git commands and handle their output
func executeGitCommand(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", &GitError{
			Op:  strings.Join(args, " "),
			Err: err,
		}
	}
	return strings.TrimSpace(string(out)), nil
}

// GetGitInfo returns the git status required during a leeway build
func GetGitInfo(loc string) (*GitInfo, error) {
	gitfc := filepath.Join(loc, gitDirName)
	stat, err := os.Stat(gitfc)
	if err != nil || !stat.IsDir() {
		return nil, nil
	}

	commit, err := executeGitCommand(loc, "rev-parse", "HEAD")
	if err != nil {
		return nil, err
	}

	res := GitInfo{
		WorkingCopyLoc: loc,
		Commit:         commit,
	}

	origin, err := executeGitCommand(loc, "config", "--get", "remote.origin.url")
	if err == nil {
		res.Origin = origin
	}

	status, err := executeGitCommand(loc, "status", "--porcelain")
	if serr, ok := err.(*exec.ExitError); ok && serr.ExitCode() != gitStatusError {
		log.WithFields(log.Fields{
			"exitCode":    serr.ExitCode(),
			"workingCopy": loc,
		}).Debug("git status --porcelain exited with failed exit code. Working copy is dirty.")
		res.dirty = true
	} else if _, ok := err.(*exec.ExitError); !ok && err != nil {
		return nil, err
	} else if status != "" {
		log.WithFields(log.Fields{
			"workingCopy": loc,
			"status":      status,
		}).Debug("working copy is dirty")

		res.dirty = true
		res.dirtyFiles, err = parseGitStatus([]byte(status))
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

// IsDirty returns whether the working copy has any modifications
func (info *GitInfo) IsDirty() bool {
	return info.dirty
}

// HasDirtyFile checks if a specific file is dirty
func (info *GitInfo) HasDirtyFile(file string) bool {
	if !info.dirty {
		return false
	}
	if len(info.dirtyFiles) == 0 {
		return true
	}

	file = strings.TrimPrefix(file, info.WorkingCopyLoc)
	file = strings.TrimPrefix(file, "/")
	_, isDirty := info.dirtyFiles[file]
	return isDirty
}

// DirtyFiles returns true if a single file of the file list is dirty
func (info *GitInfo) DirtyFiles(files []string) bool {
	if !info.dirty {
		log.WithField("workingCopy", info.WorkingCopyLoc).Debug("building from a clean working copy")
		return false
	}
	if len(info.dirtyFiles) == 0 {
		log.WithField("workingCopy", info.WorkingCopyLoc).Debug("no records of dirty files - assuming dirty Git working copy")
		return true
	}
	for _, f := range files {
		if !strings.HasPrefix(f, info.WorkingCopyLoc) {
			log.WithFields(log.Fields{
				"workingCopy": info.WorkingCopyLoc,
				"file":        f,
			}).Debug("no records of this file - assuming it's dirty")
			return true
		}

		if info.HasDirtyFile(f) {
			log.WithFields(log.Fields{
				"workingCopy": info.WorkingCopyLoc,
				"file":        f,
			}).Debug("found dirty source file")
			return true
		}
	}
	return false
}
