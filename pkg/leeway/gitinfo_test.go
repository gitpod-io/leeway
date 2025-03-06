package leeway

import (
	"fmt"
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

func TestGitError(t *testing.T) {
	err := &GitError{
		Op:  "status",
		Err: fmt.Errorf("command failed"),
	}
	expected := "git operation status failed: command failed"
	if err.Error() != expected {
		t.Errorf("GitError.Error() = %q, want %q", err.Error(), expected)
	}
}

func TestGitInfoIsDirty(t *testing.T) {
	tests := []struct {
		name string
		info *GitInfo
		want bool
	}{
		{
			name: "clean working copy",
			info: &GitInfo{dirty: false},
			want: false,
		},
		{
			name: "dirty working copy",
			info: &GitInfo{dirty: true},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.info.IsDirty(); got != tt.want {
				t.Errorf("GitInfo.IsDirty() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGitInfoHasDirtyFile(t *testing.T) {
	tests := []struct {
		name string
		info *GitInfo
		file string
		want bool
	}{
		{
			name: "clean working copy",
			info: &GitInfo{dirty: false},
			file: "foo",
			want: false,
		},
		{
			name: "dirty working copy no files tracked",
			info: &GitInfo{
				dirty:      true,
				dirtyFiles: nil,
			},
			file: "foo",
			want: true,
		},
		{
			name: "dirty working copy with specific file",
			info: &GitInfo{
				dirty: true,
				dirtyFiles: map[string]struct{}{
					"foo": {},
				},
			},
			file: "foo",
			want: true,
		},
		{
			name: "dirty working copy with clean file",
			info: &GitInfo{
				dirty: true,
				dirtyFiles: map[string]struct{}{
					"foo": {},
				},
			},
			file: "bar",
			want: false,
		},
		{
			name: "dirty working copy with file in working copy",
			info: &GitInfo{
				WorkingCopyLoc: "/path/to",
				dirty:          true,
				dirtyFiles: map[string]struct{}{
					"foo": {},
				},
			},
			file: "/path/to/foo",
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.info.HasDirtyFile(tt.file); got != tt.want {
				t.Errorf("GitInfo.HasDirtyFile() = %v, want %v", got, tt.want)
			}
		})
	}
}
