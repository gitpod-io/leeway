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
    --build-arg)
      # Print build arguments to stderr for test verification
      echo "$2" >&2
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
							"debug.sh": `#!/bin/bash
echo "DEBUG: Listing cache directory"
find /tmp/leeway* -type f -name "*.tar*" | xargs ls -la
echo "DEBUG: Examining tar.gz contents"
find /tmp/leeway* -type f -name "*.tar.gz" | xargs -I{} tar -tvf {} | grep imgnames.txt
echo "DEBUG: Examining tar contents"
find /tmp/leeway* -type f -name "*.tar" | xargs -I{} tar -tvf {} | grep imgnames.txt
`,
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
									PreparationCommands: [][]string{
										{"sh", "-c", "echo '#!/bin/bash\necho \"DEBUG: Listing build directory contents\" > /tmp/debug_output.txt\nls -la >> /tmp/debug_output.txt\necho \"DEBUG: Listing comp--pkg0 directory contents\" >> /tmp/debug_output.txt\nls -la comp--pkg0 >> /tmp/debug_output.txt\necho \"DEBUG: Contents of comp--pkg0/imgnames.txt\" >> /tmp/debug_output.txt\ncat comp--pkg0/imgnames.txt >> /tmp/debug_output.txt\necho \"DEBUG: Contents of comp--pkg0/metadata.yaml\" >> /tmp/debug_output.txt\ncat comp--pkg0/metadata.yaml >> /tmp/debug_output.txt\necho \"DEBUG: Listing cache directory\" >> /tmp/debug_output.txt\nfind /tmp/leeway* -type f -name \"*.tar*\" | xargs ls -la >> /tmp/debug_output.txt\necho \"DEBUG: Examining tar.gz contents\" >> /tmp/debug_output.txt\nfind /tmp/leeway* -type f -name \"*.tar.gz\" | xargs -I{} tar -tvf {} | grep imgnames.txt >> /tmp/debug_output.txt\necho \"DEBUG: Examining tar contents\" >> /tmp/debug_output.txt\nfind /tmp/leeway* -type f -name \"*.tar\" | xargs -I{} tar -tvf {} | grep imgnames.txt >> /tmp/debug_output.txt\ncat /tmp/debug_output.txt' > debug.sh"},
										{"chmod", "+x", "debug.sh"},
										{"sh", "debug.sh"},
									},
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
