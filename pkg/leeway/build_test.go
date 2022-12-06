package leeway_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gitpod-io/leeway/pkg/leeway"
	"github.com/gitpod-io/leeway/pkg/testutil"
	log "github.com/sirupsen/logrus"
)

const dummyDocker = `#!/bin/bash

POSITIONAL_ARGS=()

while [[ $# -gt 0 ]]; do
  case $1 in
    -o)
      OUTPUT="$2"
      shift # past argument
      shift # past value
      ;;
    *)
      POSITIONAL_ARGS+=("$1") # save positional arg
      shift # past argument
      ;;
  esac
done

set -- "${POSITIONAL_ARGS[@]}" # restore positional parameters

if [ "${POSITIONAL_ARGS}" == "save" ]; then
	tar cvvfz "${OUTPUT}" -T /dev/null
fi
`

func TestBuildDockerDeps(t *testing.T) {
	if *testutil.Dut {
		pth, err := os.MkdirTemp("", "")
		if err != nil {
			t.Fatal(err)
		}
		err = os.WriteFile(filepath.Join(pth, "docker"), []byte(dummyDocker), 0755)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.RemoveAll(pth) })

		os.Setenv("PATH", pth+":"+os.Getenv("PATH"))
		log.WithField("path", os.Getenv("PATH")).Debug("modified path to use dummy docker")
	}
	testutil.RunDUT()

	tests := []*testutil.CommandFixtureTest{
		{
			Name:        "docker dependency",
			T:           t,
			Args:        []string{"build", "-v", "-c", "none", "comp:pkg1"},
			StderrSub:   "DEP_COMP__PKG0=foobar:1234",
			NoStdoutSub: "already built",
			ExitCode:    0,
			Fixture: &testutil.Setup{
				Components: []testutil.Component{
					{
						Location: "comp",
						Files: map[string]string{
							"pkg0.Dockerfile": "FROM alpine:latest",
							"pkg1.Dockerfile": "FROM ${DEP_COMP__PKG0}",
						},
						Packages: []leeway.Package{
							{
								PackageInternal: leeway.PackageInternal{
									Name: "pkg0",
									Type: leeway.DockerPackage,
								},
								Config: leeway.DockerPkgConfig{
									Dockerfile: "pkg0.Dockerfile",
									Image:      []string{"foobar:1234"},
								},
							},
							{
								PackageInternal: leeway.PackageInternal{
									Name:         "pkg1",
									Type:         leeway.DockerPackage,
									Dependencies: []string{":pkg0"},
								},
								Config: leeway.DockerPkgConfig{
									Dockerfile: "pkg1.Dockerfile",
								},
							},
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		test.Run()
	}
}
