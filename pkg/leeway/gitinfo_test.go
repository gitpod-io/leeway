package leeway

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestParseGitStatus(t *testing.T) {
	type Expectation struct {
		Files map[string]struct{}
		Err   string
	}
	tests := []struct {
		Name        string
		In          string
		Expectation Expectation
	}{
		{
			Name:        "empty input",
			Expectation: Expectation{},
		},
		{
			Name: "garbage",
			In:   "hello world, this is garbage\nand some more",
			Expectation: Expectation{
				Err: `cannot parse git status "hello world, this is garbage": expected two segments, got 5`,
			},
		},
		{
			Name: "valid input",
			In:   " M foobar\n M this/is/a/file",
			Expectation: Expectation{
				Files: map[string]struct{}{
					"foobar":         {},
					"this/is/a/file": {},
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			files, err := parseGitStatus([]byte(test.In))
			var act Expectation
			act.Files = files
			if err != nil {
				act.Err = err.Error()
			}
			if diff := cmp.Diff(test.Expectation, act); diff != "" {
				t.Errorf("ParseGitStatus() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestGitInfoDirtyFiles(t *testing.T) {
	tests := []struct {
		Name        string
		In          *GitInfo
		Files       []string
		Expectation bool
	}{
		{
			Name:        "empty input",
			In:          &GitInfo{},
			Expectation: false,
		},
		{
			Name: "dirty working copy",
			In: &GitInfo{
				dirty: true,
			},
			Files:       []string{"foo"},
			Expectation: true,
		},
		{
			Name: "dirty file",
			In: &GitInfo{
				dirty: true,
				dirtyFiles: map[string]struct{}{
					"foo": {},
				},
			},
			Files:       []string{"foo"},
			Expectation: true,
		},
		{
			Name: "dirty file loc",
			In: &GitInfo{
				WorkingCopyLoc: "bar/",
				dirty:          true,
				dirtyFiles: map[string]struct{}{
					"foo": {},
				},
			},
			Files:       []string{"bar/foo"},
			Expectation: true,
		},
		{
			Name: "unknown file",
			In: &GitInfo{
				WorkingCopyLoc: "bar/",
				dirty:          true,
				dirtyFiles: map[string]struct{}{
					"foo": {},
				},
			},
			Files:       []string{"not/in/this/working/copy"},
			Expectation: true,
		},
		{
			Name: "clean file",
			In: &GitInfo{
				dirty: true,
				dirtyFiles: map[string]struct{}{
					"foo": {},
				},
			},
			Files:       []string{"bar"},
			Expectation: false,
		},
	}
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			act := test.In.DirtyFiles(test.Files)
			if diff := cmp.Diff(test.Expectation, act); diff != "" {
				t.Errorf("ParseGitStatus() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
