package testutil

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/gitpod-io/leeway/pkg/leeway"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestLoadFromYAML(t *testing.T) {
	ignores := cmpopts.IgnoreUnexported(
		leeway.Workspace{},
		leeway.Component{},
		leeway.Package{},
		leeway.WorkspaceProvenance{},
		leeway.GitInfo{},
	)

	tests := []struct {
		Name        string
		Content     string
		Expectation *Setup
	}{
		{
			Name:        "empty",
			Expectation: &Setup{},
		},
		{
			Name: "single",
			Expectation: &Setup{
				Components: []Component{
					{
						Location: "comp1",
						Packages: []leeway.Package{
							{
								PackageInternal: leeway.PackageInternal{
									Name:    "pkg1",
									Type:    leeway.GenericPackage,
									Sources: []string{"**"},
								},
								Config: leeway.GenericPkgConfig{
									Commands: [][]string{{"foo"}},
								},
							},
						},
					},
				},
			},
			Content: `components:
  - location: comp1
    packages:
      - name: pkg1
        type: generic
        srcs: 
          - "**"
        config:
          commands: [["foo"]]`,
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			act, err := LoadFromYAML(bytes.NewBufferString(test.Content))
			if err != nil {
				t.Fatal(err)
			}

			if diff := cmp.Diff(test.Expectation, act, ignores); diff != "" {
				t.Errorf("LoadFromYAML() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestMaterialise(t *testing.T) {
	type File struct {
		Path   string
		Size   int64
		SHA256 string
	}
	tests := []struct {
		Name        string
		Setup       Setup
		Expectation []File
	}{
		{
			Name: "simple",
			Setup: Setup{
				Components: []Component{
					{
						Location: "comp1",
						Files: map[string]string{
							"someFile":           "content",
							"some/other/file":    "more content",
							"some/other/another": "more content",
						},
						Comp: leeway.Component{
							Constants: leeway.Arguments{
								"hello": "world",
							},
						},
						Packages: []leeway.Package{
							{
								PackageInternal: leeway.PackageInternal{
									Name:    "pkg1",
									Type:    leeway.GenericPackage,
									Sources: []string{"**"},
								},
								Config: leeway.GenericPkgConfig{
									Commands: [][]string{{"bla"}},
								},
							},
						},
					},
				},
			},
			Expectation: []File{
				{Path: "WORKSPACE.yaml"},
				{Path: "comp1/BUILD.yaml", SHA256: "6cc73a81aa8f00851c4738947d0d22ae296d8c626af4d1f4fe60fbabb09f906f"},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			loc, err := test.Setup.Materialize()
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { os.RemoveAll(loc) })
			t.Logf("materialized at %s", loc)

			for _, f := range test.Expectation {
				fn := filepath.Join(loc, f.Path)
				stat, err := os.Stat(fn)
				if err != nil {
					t.Errorf("expected file mismatch: %s: %v", f.Path, err)
					continue
				}

				if f.Size > 0 && stat.Size() != f.Size {
					t.Errorf("expected file size mismatch: %s: expected %d, got %d", f.Path, f.Size, stat.Size())
				}

				if f.SHA256 == "" {
					continue
				}
				hash := sha256.New()
				fp, err := os.Open(fn)
				if err != nil {
					t.Errorf("cannot hash %s: %v", fn, err)
					continue
				}
				_, err = io.Copy(hash, fp)
				fp.Close()
				if err != nil {
					t.Errorf("cannot hash %s: %v", fn, err)
					continue
				}

				sum := fmt.Sprintf("%x", hash.Sum(nil))
				if f.SHA256 != sum {
					t.Errorf("file hash mismatch: %s: expected %s, got %s", f.Path, f.SHA256, sum)
				}
			}
		})
	}
}
