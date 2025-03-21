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
    inspect)
      # Mock docker inspect to return a valid ID
      echo '[{"Id":"sha256:1234567890abcdef"}]'
      exit 0
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

// Create a mock for extractImageWithOCILibs to avoid dependency on actual Docker daemon
func init() {
	// Override with a simple mock implementation for tests
	leeway.ExtractImageWithOCILibs = func(destDir, imgTag string) error {
		log.WithFields(log.Fields{
			"image":   imgTag,
			"destDir": destDir,
		}).Info("Mock: Extracting container filesystem")

		// Create required directories
		contentDir := filepath.Join(destDir, "content")
		if err := os.MkdirAll(contentDir, 0755); err != nil {
			return err
		}

		// Create a mock file structure similar to what a real extraction would produce
		mockFiles := map[string]string{
			filepath.Join(destDir, "imgnames.txt"):        imgTag + "\n",
			filepath.Join(destDir, "metadata.yaml"):       "test: metadata\n",
			filepath.Join(destDir, "image-metadata.json"): `{"image":"` + imgTag + `"}`,
			filepath.Join(contentDir, "bin/testfile"):     "test content",
			filepath.Join(contentDir, "README.md"):        "# Test Container",
		}

		// Create directories for the mock files
		for filename := range mockFiles {
			if err := os.MkdirAll(filepath.Dir(filename), 0755); err != nil {
				return err
			}
		}

		// Create the mock files
		for filename, content := range mockFiles {
			if err := os.WriteFile(filename, []byte(content), 0644); err != nil {
				return err
			}
		}

		return nil
	}
}

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
									Metadata:   make(map[string]string),
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
									Metadata:   make(map[string]string),
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

func TestDockerPostProcessing(t *testing.T) {
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
			Name:      "docker extraction",
			T:         t,
			Args:      []string{"build", "-v", "-c", "none", "comp:pkg"},
			StderrSub: "Extracting container filesystem",
			ExitCode:  0,
			Fixture: &testutil.Setup{
				Components: []testutil.Component{
					{
						Location: "comp",
						Files: map[string]string{
							"Dockerfile": "FROM alpine:latest",
						},
						Packages: []leeway.Package{
							{
								PackageInternal: leeway.PackageInternal{
									Name: "pkg",
									Type: leeway.DockerPackage,
								},
								Config: leeway.DockerPkgConfig{
									Dockerfile: "Dockerfile",
									// No Image entry - should trigger extraction
								},
							},
						},
					},
				},
			},
		},
		{
			Name:      "docker content directory structure",
			T:         t,
			Args:      []string{"build", "-v", "-c", "none", "comp:content-test"},
			StderrSub: "Container files extracted successfully",
			ExitCode:  0,
			Fixture: &testutil.Setup{
				Components: []testutil.Component{
					{
						Location: "comp",
						Files: map[string]string{
							"content.Dockerfile": "FROM alpine:latest\nRUN mkdir -p /test/dir\nRUN echo 'test' > /test/file.txt",
						},
						Packages: []leeway.Package{
							{
								PackageInternal: leeway.PackageInternal{
									Name: "content-test",
									Type: leeway.DockerPackage,
								},
								Config: leeway.DockerPkgConfig{
									Dockerfile: "content.Dockerfile",
									// No Image entry - should trigger extraction
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
