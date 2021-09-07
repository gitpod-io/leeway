package doublestar_test

import (
	"fmt"
	"testing"

	"github.com/gitpod-io/leeway/pkg/doublestar"
)

func TestMatch(t *testing.T) {
	tests := []struct {
		Pattern string
		Path    string
		Match   bool
	}{
		{"**", "/", true},
		{"**/*.go", "foo.go", true},
		{"**/foo.go", "foo.go", true},
		{"**/BUILD.yaml", "fixtures/scripts/BUILD.yaml", true},
		{"**/*.go", "a/b/c/foo.go", true},
		{"**/*.go", "/c/foo.go", true},
		{"**/*.go", "a/b/c/foo.txt", false},
		{"**/*.go", "a/b/c", false},
		{"**/*.go", "/a/b/c", false},
		{"/a/b/**", "/a/b/c", true},
		{"/a/b/**", "/a/b/c/d/e/f/g", true},
		{"/a/b/**", "/a/b", false},
		{"/a/b/**", "a/b/c", false},
		{"/a/b/**/c", "/a/b/c", true},
		{"/a/b/**/c", "/a/b/1/2/3/4/c", true},
		{"/a/b/**/c/*.go", "/a/b/1/2/3/4/c/foo.go", true},
		{"/a/b/**/c/*.go", "/a/b/1/2/3/4/c/foo.txt", false},
		{"/a/b/**/**/c", "/a/b/1/2/3/4/c", true},
		{"/a/b/**/**/c", "/a/b/1/c", true},
		{"/a/b/**/c/**/d", "/a/b/1/c/2/d", true},
		{"/a/b/**/c/**/d", "/a/b/1/c/2", false},
		{"*/*.go", "src/foo.go", true},
	}
	for i, test := range tests {
		t.Run(fmt.Sprintf("%03d_%s_%s", i, test.Pattern, test.Path), func(t *testing.T) {
			match, err := doublestar.Match(test.Pattern, test.Path)
			if err != nil {
				t.Fatalf("unexpected error: %q", err)
			}
			if match != test.Match {
				t.Errorf("unexpected match: expected %v, got %v", test.Match, match)
			}
		})
	}
}
