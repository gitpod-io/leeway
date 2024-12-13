package doublestar_test

import (
	"fmt"
	"testing"

	"github.com/gitpod-io/leeway/pkg/doublestar"
)

func TestMatch(t *testing.T) {
	tests := []struct {
		Pattern     string
		Path        string
		Match       bool
		SkipSubDirs bool
	}{
		{Pattern: "**", Path: "/", Match: true, SkipSubDirs: false},
		{Pattern: "**/*.go", Path: "foo.go", Match: true, SkipSubDirs: false},
		{Pattern: "**/foo.go", Path: "foo.go", Match: true, SkipSubDirs: false},
		{Pattern: "**/BUILD.yaml", Path: "fixtures/scripts/BUILD.yaml", Match: true, SkipSubDirs: false},
		{Pattern: "**/*.go", Path: "a/b/c/foo.go", Match: true, SkipSubDirs: false},
		{Pattern: "**/*.go", Path: "/c/foo.go", Match: true, SkipSubDirs: false},
		{Pattern: "**/*.go", Path: "a/b/c/foo.txt", Match: false, SkipSubDirs: false},
		{Pattern: "**/*.go", Path: "a/b/c", Match: false, SkipSubDirs: false},
		{Pattern: "**/*.go", Path: "/a/b/c", Match: false, SkipSubDirs: false},
		{Pattern: "/a/b/**", Path: "/a/b/c", Match: true, SkipSubDirs: false},
		{Pattern: "/a/b/**", Path: "/a/b/c/d/e/f/g", Match: true, SkipSubDirs: false},
		{Pattern: "/a/b/**", Path: "/a/b", Match: false, SkipSubDirs: false},
		{Pattern: "/a/b/**", Path: "a/b/c", Match: false, SkipSubDirs: true},
		{Pattern: "/a/b/**/c", Path: "/a/b/c", Match: true, SkipSubDirs: false},
		{Pattern: "/a/b/**/c", Path: "/a/b/1/2/3/4/c", Match: true, SkipSubDirs: false},
		{Pattern: "/a/b/**/c/*.go", Path: "/a/b/1/2/3/4/c/foo.go", Match: true, SkipSubDirs: false},
		{Pattern: "/a/b/**/c/*.go", Path: "/a/b/1/2/3/4/c/foo.txt", Match: false, SkipSubDirs: false},
		{Pattern: "/a/b/**/**/c", Path: "/a/b/1/2/3/4/c", Match: true, SkipSubDirs: false},
		{Pattern: "/a/b/**/**/c", Path: "/a/b/1/c", Match: true, SkipSubDirs: false},
		{Pattern: "/a/b/**/c/**/d", Path: "/a/b/1/c/2/d", Match: true, SkipSubDirs: false},
		{Pattern: "/a/b/**/c/**/d", Path: "/a/b/1/c/2", Match: false, SkipSubDirs: false},
		{Pattern: "*/*.go", Path: "src/foo.go", Match: true, SkipSubDirs: false},
		{Pattern: "/a/b/**/*.go", Path: "/a/b", Match: false, SkipSubDirs: false},
		{Pattern: "/a/b/**/*.go", Path: "/a/c", Match: false, SkipSubDirs: true},
		{Pattern: "go.mod", Path: "go.mod", Match: true, SkipSubDirs: false},
	}
	for i, test := range tests {
		t.Run(fmt.Sprintf("%03d_%s_%s", i, test.Pattern, test.Path), func(t *testing.T) {
			match, skip, err := doublestar.Match(test.Pattern, test.Path)
			if err != nil {
				t.Fatalf("unexpected error: %q", err)
			}
			if match != test.Match {
				t.Errorf("unexpected match: expected %v, got %v", test.Match, match)
			}
			if skip != test.SkipSubDirs {
				t.Errorf("unexpected skip: expected %v, got %v", test.SkipSubDirs, skip)
			}
		})
	}
}
