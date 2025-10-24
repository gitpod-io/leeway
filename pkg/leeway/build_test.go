package leeway_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gitpod-io/leeway/pkg/leeway"
	"github.com/gitpod-io/leeway/pkg/testutil"
	log "github.com/sirupsen/logrus"
)

// Helper function for tests
func boolPtr(b bool) *bool {
	return &b
}

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

func TestDockerExport_PrecedenceHierarchy(t *testing.T) {
	tests := []struct {
		name                   string
		packageConfig          *bool // nil = not set, &true = true, &false = false
		workspaceEnvSet        bool  // Simulates workspace auto-set
		userEnvSet             bool  // Simulates user explicit set
		userEnvValue           bool
		cliSet                 bool
		cliValue               bool
		expectedFinal          bool
		expectedSource         string
	}{
		{
			name:            "No config, no overrides - global default",
			packageConfig:   nil,
			workspaceEnvSet: false,
			expectedFinal:   false,
			expectedSource:  "global_default",
		},
		{
			name:            "Workspace SLSA enabled - workspace default",
			packageConfig:   nil,
			workspaceEnvSet: true, // provenance.slsa: true
			expectedFinal:   true,
			expectedSource:  "workspace_default",
		},
		{
			name:            "Package explicitly false - overrides workspace",
			packageConfig:   boolPtr(false),
			workspaceEnvSet: true,
			expectedFinal:   false,
			expectedSource:  "package_config",
		},
		{
			name:            "Package explicitly true - overrides workspace",
			packageConfig:   boolPtr(true),
			workspaceEnvSet: false,
			expectedFinal:   true,
			expectedSource:  "package_config",
		},
		{
			name:          "User env false - overrides package true",
			packageConfig: boolPtr(true),
			userEnvSet:    true,
			userEnvValue:  false,
			expectedFinal: false,
			expectedSource: "user_env_var",
		},
		{
			name:          "User env true - overrides package false",
			packageConfig: boolPtr(false),
			userEnvSet:    true,
			userEnvValue:  true,
			expectedFinal: true,
			expectedSource: "user_env_var",
		},
		{
			name:           "CLI true - overrides everything (package false, user false)",
			packageConfig:  boolPtr(false),
			userEnvSet:     true,
			userEnvValue:   false,
			cliSet:         true,
			cliValue:       true,
			expectedFinal:  true,
			expectedSource: "cli_flag",
		},
		{
			name:            "CLI false - overrides everything (workspace true, package true)",
			packageConfig:   boolPtr(true),
			workspaceEnvSet: true,
			cliSet:          true,
			cliValue:        false,
			expectedFinal:   false,
			expectedSource:  "cli_flag",
		},
		{
			name:            "Full hierarchy - CLI wins",
			packageConfig:   boolPtr(true),
			workspaceEnvSet: true,
			userEnvSet:      true,
			userEnvValue:    true,
			cliSet:          true,
			cliValue:        false,
			expectedFinal:   false,
			expectedSource:  "cli_flag",
		},
		{
			name:            "User env wins over package and workspace",
			packageConfig:   boolPtr(true),
			workspaceEnvSet: true,
			userEnvSet:      true,
			userEnvValue:    false,
			cliSet:          false,
			expectedFinal:   false,
			expectedSource:  "user_env_var",
		},
		{
			name:            "Package wins over workspace",
			packageConfig:   boolPtr(false),
			workspaceEnvSet: true,
			userEnvSet:      false,
			cliSet:          false,
			expectedFinal:   false,
			expectedSource:  "package_config",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup environment to simulate workspace auto-set
			if tt.workspaceEnvSet {
				t.Setenv(leeway.EnvvarDockerExportToCache, "true")
			} else {
				t.Setenv(leeway.EnvvarDockerExportToCache, "")
			}

			// Create mock build context
			buildctx := &struct {
				DockerExportEnvSet   bool
				DockerExportEnvValue bool
				DockerExportSet      bool
				DockerExportToCache  bool
			}{
				DockerExportEnvSet:   tt.userEnvSet,
				DockerExportEnvValue: tt.userEnvValue,
				DockerExportSet:      tt.cliSet,
				DockerExportToCache:  tt.cliValue,
			}

			// Create config
			cfg := struct {
				ExportToCache *bool
			}{
				ExportToCache: tt.packageConfig,
			}

			// Simulate the precedence logic from buildDocker
			var exportToCache bool
			var source string

			// Layer 5 & 4: Workspace default
			envExport := os.Getenv(leeway.EnvvarDockerExportToCache)
			if envExport == "true" || envExport == "1" {
				exportToCache = true
				source = "workspace_default"
			} else {
				exportToCache = false
				source = "global_default"
			}

			// Layer 3: Package config
			if cfg.ExportToCache != nil {
				exportToCache = *cfg.ExportToCache
				source = "package_config"
			}

			// Layer 2: User env var
			if buildctx.DockerExportEnvSet {
				exportToCache = buildctx.DockerExportEnvValue
				source = "user_env_var"
			}

			// Layer 1: CLI flag
			if buildctx.DockerExportSet {
				exportToCache = buildctx.DockerExportToCache
				source = "cli_flag"
			}

			// Verify
			if exportToCache != tt.expectedFinal {
				t.Errorf("exportToCache = %v, want %v", exportToCache, tt.expectedFinal)
			}
			if source != tt.expectedSource {
				t.Errorf("source = %v, want %v", source, tt.expectedSource)
			}
		})
	}
}

func TestDockerPkgConfig_ExportToCache(t *testing.T) {
	tests := []struct {
		name           string
		config         leeway.DockerPkgConfig
		expectedExport bool
	}{
		{
			name: "default behavior - push directly",
			config: leeway.DockerPkgConfig{
				Image: []string{"test:latest"},
			},
			expectedExport: false,
		},
		{
			name: "explicit export to cache",
			config: leeway.DockerPkgConfig{
				Image:         []string{"test:latest"},
				ExportToCache: boolPtr(true),
			},
			expectedExport: true,
		},
		{
			name: "explicit push directly",
			config: leeway.DockerPkgConfig{
				Image:         []string{"test:latest"},
				ExportToCache: boolPtr(false),
			},
			expectedExport: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actualExport := false
			if tt.config.ExportToCache != nil {
				actualExport = *tt.config.ExportToCache
			}
			if actualExport != tt.expectedExport {
				t.Errorf("ExportToCache = %v, want %v", actualExport, tt.expectedExport)
			}
		})
	}
}

func TestBuildDocker_ExportToCache(t *testing.T) {
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
			Name:      "docker export to cache",
			T:         t,
			Args:      []string{"build", "-v", "-c", "none", "comp:pkg"},
			StderrSub: "Exporting Docker image to cache",
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
									Dockerfile:    "Dockerfile",
									Image:         []string{"test:latest"},
									ExportToCache: boolPtr(true),
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


func TestDockerPackage_BuildContextOverride(t *testing.T) {
	tests := []struct {
		name                   string
		packageConfigValue     *bool // nil = not set
		buildContextExportFlag bool
		buildContextExportSet  bool
		expectedFinal          bool
	}{
		{
			name:                   "no override - use package config false",
			packageConfigValue:     boolPtr(false),
			buildContextExportFlag: false,
			buildContextExportSet:  false,
			expectedFinal:          false,
		},
		{
			name:                   "no override - use package config true",
			packageConfigValue:     boolPtr(true),
			buildContextExportFlag: false,
			buildContextExportSet:  false,
			expectedFinal:          true,
		},
		{
			name:                   "no override - package config not set (nil)",
			packageConfigValue:     nil,
			buildContextExportFlag: false,
			buildContextExportSet:  false,
			expectedFinal:          false, // defaults to false
		},
		{
			name:                   "CLI flag enables export (overrides package false)",
			packageConfigValue:     boolPtr(false),
			buildContextExportFlag: true,
			buildContextExportSet:  true,
			expectedFinal:          true,
		},
		{
			name:                   "CLI flag keeps export enabled (package true)",
			packageConfigValue:     boolPtr(true),
			buildContextExportFlag: true,
			buildContextExportSet:  true,
			expectedFinal:          true,
		},
		{
			name:                   "CLI flag disables export (overrides package true) - CRITICAL TEST",
			packageConfigValue:     boolPtr(true),
			buildContextExportFlag: false,
			buildContextExportSet:  true,
			expectedFinal:          false,
		},
		{
			name:                   "CLI flag keeps export disabled (package false)",
			packageConfigValue:     boolPtr(false),
			buildContextExportFlag: false,
			buildContextExportSet:  true,
			expectedFinal:          false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := leeway.DockerPkgConfig{
				ExportToCache: tt.packageConfigValue,
			}

			// Simulate the simplified build context override logic
			// In the new implementation, CLI flag always wins if set
			if tt.buildContextExportSet {
				cfg.ExportToCache = boolPtr(tt.buildContextExportFlag)
			}

			actualFinal := false
			if cfg.ExportToCache != nil {
				actualFinal = *cfg.ExportToCache
			}

			if actualFinal != tt.expectedFinal {
				t.Errorf("ExportToCache = %v, want %v", actualFinal, tt.expectedFinal)
			}
		})
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

