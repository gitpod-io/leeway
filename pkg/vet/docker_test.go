package vet

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/gitpod-io/leeway/pkg/leeway"
)

func TestCheckDockerCopyFromPackage(t *testing.T) {
	tests := []struct {
		Name       string
		Dockerfile string
		Deps       []string
		Findings   []string
	}{
		{
			Name: "true positive copy",
			Dockerfile: `FROM alpine:latest
COPY from-some-pkg--build/hello.txt hello.txt`,
			Findings: []string{
				"Dockerfile copies from from-some-pkg--build/hello.txt which looks like a package path, but no dependency satisfies it",
			},
		},
		{
			Name: "true negative copy",
			Dockerfile: `FROM alpine:latest
COPY from-some-pkg--build/hello.txt hello.txt`,
			Deps: []string{"from-some-pkg:build"},
		},
		{
			Name: "true positive add",
			Dockerfile: `FROM alpine:latest
ADD from-some-pkg--build/hello.txt hello.txt`,
			Findings: []string{
				"Dockerfile copies from from-some-pkg--build/hello.txt which looks like a package path, but no dependency satisfies it",
			},
		},
		{
			Name: "true negative add",
			Dockerfile: `FROM alpine:latest
ADD from-some-pkg--build/hello.txt hello.txt`,
			Deps: []string{"from-some-pkg:build"},
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			failOnErr := func(err error) {
				if err != nil {
					t.Fatalf("cannot set up test: %q", err)
				}
			}

			tmpdir, err := os.MkdirTemp("", "leeway-test-*")
			failOnErr(err)
			defer os.RemoveAll(tmpdir)

			var pkgdeps string
			failOnErr(os.WriteFile(filepath.Join(tmpdir, "WORKSPACE.yaml"), []byte("environmentManifest:\n  - name: \"docker\"\n    command: [\"echo\"]"), 0644))
			for _, dep := range test.Deps {
				segs := strings.Split(dep, ":")
				loc := filepath.Join(tmpdir, segs[0])
				failOnErr(os.MkdirAll(loc, 0755))
				failOnErr(os.WriteFile(filepath.Join(loc, "BUILD.yaml"), []byte(fmt.Sprintf(`packages:
- name: %s
  type: generic`, segs[1])), 0755))

				if pkgdeps == "" {
					pkgdeps = "\n  deps:\n"
				}
				pkgdeps += fmt.Sprintf("  - %s\n", dep)
			}
			failOnErr(os.MkdirAll(filepath.Join(tmpdir, "test-pkg"), 0755))
			failOnErr(os.WriteFile(filepath.Join(tmpdir, "test-pkg", "Dockerfile"), []byte(test.Dockerfile), 0644))
			failOnErr(os.WriteFile(filepath.Join(tmpdir, "test-pkg", "BUILD.yaml"), []byte(fmt.Sprintf(`packages:
- name: docker
  type: docker
  config:
    dockerfile: Dockerfile%s
`, pkgdeps)), 0644))

			ws, err := leeway.FindWorkspace(tmpdir, leeway.Arguments{}, "", "")
			failOnErr(err)
			pkg, ok := ws.Packages["test-pkg:docker"]
			if !ok {
				t.Fatalf("cannot find test package: test-pkg:docker")
			}

			findings, err := checkDockerCopyFromPackage(pkg)
			if err != nil {
				t.Fatalf("unexpected error: %s", err.Error())
			}

			var fs []string
			if len(findings) > 0 {
				fs = make([]string, len(findings))
				for i := range findings {
					fs[i] = findings[i].Description
				}
			}
			if diff := cmp.Diff(test.Findings, fs); diff != "" {
				t.Errorf("MakeGatewayInfo() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
