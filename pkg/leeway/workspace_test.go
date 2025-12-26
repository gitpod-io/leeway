package leeway_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gitpod-io/leeway/pkg/leeway"
	"github.com/gitpod-io/leeway/pkg/testutil"
)

func TestFixtureLoadWorkspace(t *testing.T) {
	testutil.RunDUT()

	tests := []*testutil.CommandFixtureTest{
		{
			Name:              "single workspace packages",
			T:                 t,
			Args:              []string{"collect"},
			NoNestedWorkspace: true,
			ExitCode:          0,
			StdoutSubs:        []string{"pkg1:app"},
			FixturePath:       "fixtures/load-workspace.yaml",
		},
		{
			Name:              "workspace components",
			T:                 t,
			Args:              []string{"collect", "components"},
			NoNestedWorkspace: true,
			ExitCode:          0,
			StdoutSubs:        []string{"deeper/pkg0\nwsa\nwsa/pkg0\nwsa/pkg1"},
			FixturePath:       "fixtures/load-workspace.yaml",
		},
		{
			Name:              "workspace args file",
			T:                 t,
			Args:              []string{"describe", "comp:pkg"},
			NoNestedWorkspace: true,
			ExitCode:          0,
			StdoutSubs:        []string{"foobar"},
			Fixture: &testutil.Setup{
				Files: map[string]string{"WORKSPACE.args.yaml": "msg: foobar"},
				Workspace: leeway.Workspace{
					ArgumentDefaults: map[string]string{
						"msg": "blabla",
					},
				},
				Components: []testutil.Component{
					{
						Location: "comp",
						Packages: []leeway.Package{
							{
								PackageInternal: leeway.PackageInternal{
									Name: "pkg",
									Type: leeway.GenericPackage,
								},
								Config: leeway.GenericPkgConfig{
									Commands: [][]string{{"echo", "${msg}"}},
								},
							},
						},
					},
				},
			},
		},
		{
			Name: "environment manifest",
			T:    t,
			Args: []string{"describe", "environment-manifest"},
			Eval: func(t *testing.T, stdout, stderr string) {
				for _, k := range []string{"os", "arch", "foobar"} {
					if !strings.Contains(stdout, fmt.Sprintf("%s: ", k)) {
						t.Errorf("missing %s entry in environment manifest", k)
					}
				}
			},
			ExitCode:    0,
			FixturePath: "fixtures/load-workspace.yaml",
		},
	}

	for _, test := range tests {
		test.Run()
	}
}

func TestPackageDefinition(t *testing.T) {
	testutil.RunDUT()

	type pkginfo struct {
		Metadata struct {
			Version string `json:"version"`
		} `json:"metadata"`
	}

	tests := []struct {
		Name    string
		Layouts []map[string]string
		Tester  []func(t *testing.T, loc string, state map[string]string) *testutil.CommandFixtureTest
	}{
		{
			Name: "def change changes version",
			Layouts: []map[string]string{
				{
					"WORKSPACE.yaml":  "",
					"pkg1/BUILD.yaml": "packages:\n- name: foo\n  type: generic\n  srcs:\n  - \"doesNotExist\"",
				},
				{
					"pkg1/BUILD.yaml": "packages:\n- name: foo\n  type: generic\n  srcs:\n  - \"alsoDoesNotExist\"",
				},
			},
			Tester: []func(t *testing.T, loc string, state map[string]string) *testutil.CommandFixtureTest{
				func(t *testing.T, loc string, state map[string]string) *testutil.CommandFixtureTest {
					return &testutil.CommandFixtureTest{
						T:    t,
						Args: []string{"describe", "-w", loc, "-o", "json", "pkg1:foo"},
						Eval: func(t *testing.T, stdout, stderr string) {
							var dest pkginfo
							err := json.Unmarshal([]byte(stdout), &dest)
							if err != nil {
								fmt.Println(stdout)
								t.Fatal(err)
							}
							state["v"] = dest.Metadata.Version
						},
					}
				},
				func(t *testing.T, loc string, state map[string]string) *testutil.CommandFixtureTest {
					return &testutil.CommandFixtureTest{
						T:    t,
						Args: []string{"describe", "-w", loc, "-o", "json", "pkg1:foo"},
						Eval: func(t *testing.T, stdout, stderr string) {
							var dest pkginfo
							err := json.Unmarshal([]byte(stdout), &dest)
							if err != nil {
								fmt.Println(stdout)
								t.Fatal(err)
							}
							if state["v"] == dest.Metadata.Version {
								t.Errorf("definition change did not change version")
							}
						},
					}
				},
			},
		},
		{
			Name: "comp change doesnt change version",
			Layouts: []map[string]string{
				{
					"WORKSPACE.yaml":  "",
					"pkg1/BUILD.yaml": "packages:\n- name: foo\n  type: generic\n  srcs:\n  - \"doesNotExist\"",
				},
				{
					"pkg1/BUILD.yaml": "const:\n  foobar: baz\npackages:\n- name: foo\n  type: generic\n  srcs:\n  - \"doesNotExist\"",
				},
			},
			Tester: []func(t *testing.T, loc string, state map[string]string) *testutil.CommandFixtureTest{
				func(t *testing.T, loc string, state map[string]string) *testutil.CommandFixtureTest {
					return &testutil.CommandFixtureTest{
						T:    t,
						Args: []string{"describe", "-w", loc, "-o", "json", "pkg1:foo"},
						Eval: func(t *testing.T, stdout, stderr string) {
							var dest pkginfo
							err := json.Unmarshal([]byte(stdout), &dest)
							if err != nil {
								fmt.Println(stdout)
								t.Fatal(err)
							}
							state["v"] = dest.Metadata.Version
						},
					}
				},
				func(t *testing.T, loc string, state map[string]string) *testutil.CommandFixtureTest {
					return &testutil.CommandFixtureTest{
						T:    t,
						Args: []string{"describe", "-w", loc, "-o", "json", "pkg1:foo"},
						Eval: func(t *testing.T, stdout, stderr string) {
							var dest pkginfo
							err := json.Unmarshal([]byte(stdout), &dest)
							if err != nil {
								fmt.Println(stdout)
								t.Fatal(err)
							}
							if state["v"] != dest.Metadata.Version {
								t.Errorf("component change did change package version")
							}
						},
					}
				},
			},
		},
		{
			Name: "dependency def change changes version",
			Layouts: []map[string]string{
				{
					"WORKSPACE.yaml":  "",
					"pkg1/BUILD.yaml": "packages:\n- name: foo\n  type: generic\n  srcs:\n  - \"doesNotExist\"\n- name: bar\n  type: generic\n  srcs:\n  - \"doesNotExist\"\n  deps:\n  - :foo",
				},
				{
					"pkg1/BUILD.yaml": "packages:\n- name: foo\n  type: generic\n  srcs:\n  - \"alsoDoesNotExist\"\n- name: bar\n  type: generic\n  srcs:\n  - \"doesNotExist\"\n  deps:\n  - :foo",
				},
			},
			Tester: []func(t *testing.T, loc string, state map[string]string) *testutil.CommandFixtureTest{
				func(t *testing.T, loc string, state map[string]string) *testutil.CommandFixtureTest {
					return &testutil.CommandFixtureTest{
						T:    t,
						Args: []string{"describe", "-w", loc, "-o", "json", "pkg1:foo"},
						Eval: func(t *testing.T, stdout, stderr string) {
							var dest pkginfo
							err := json.Unmarshal([]byte(stdout), &dest)
							if err != nil {
								fmt.Println(stdout)
								t.Fatal(err)
							}
							state["v"] = dest.Metadata.Version
						},
					}
				},
				func(t *testing.T, loc string, state map[string]string) *testutil.CommandFixtureTest {
					return &testutil.CommandFixtureTest{
						T:    t,
						Args: []string{"describe", "-w", loc, "-o", "json", "pkg1:bar"},
						Eval: func(t *testing.T, stdout, stderr string) {
							var dest pkginfo
							err := json.Unmarshal([]byte(stdout), &dest)
							if err != nil {
								fmt.Println(stdout)
								t.Fatal(err)
							}
							if state["v"] == dest.Metadata.Version {
								t.Errorf("dependency def change didn't change version")
							}
						},
					}
				},
			},
		},
		{
			Name: "build args dont change version",
			Layouts: []map[string]string{
				{
					"WORKSPACE.yaml":  "",
					"pkg1/BUILD.yaml": "packages:\n- name: foo\n  type: generic\n  srcs:\n  - \"doesNotExist\"\n  config:\n    commands:\n    - [\"echo\", \"${msg}\"]",
				},
				{},
			},
			Tester: []func(t *testing.T, loc string, state map[string]string) *testutil.CommandFixtureTest{
				func(t *testing.T, loc string, state map[string]string) *testutil.CommandFixtureTest {
					return &testutil.CommandFixtureTest{
						T:    t,
						Args: []string{"describe", "-Dmsg=foo", "-w", loc, "-o", "json", "pkg1:foo"},
						Eval: func(t *testing.T, stdout, stderr string) {
							var dest pkginfo
							err := json.Unmarshal([]byte(stdout), &dest)
							if err != nil {
								fmt.Println(stdout)
								t.Fatal(err)
							}
							state["v"] = dest.Metadata.Version
						},
					}
				},
				func(t *testing.T, loc string, state map[string]string) *testutil.CommandFixtureTest {
					return &testutil.CommandFixtureTest{
						T:    t,
						Args: []string{"describe", "-Dmsg=bar", "-w", loc, "-o", "json", "pkg1:foo"},
						Eval: func(t *testing.T, stdout, stderr string) {
							var dest pkginfo
							err := json.Unmarshal([]byte(stdout), &dest)
							if err != nil {
								fmt.Println(stdout)
								t.Fatal(err)
							}
							if state["v"] != dest.Metadata.Version {
								t.Errorf("build arg did change version")
							}
						},
					}
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			loc, err := os.MkdirTemp("", "pkgdeftest-*")
			if err != nil {
				t.Fatalf("cannot create temporary dir: %q", err)
			}

			state := make(map[string]string)
			for i, l := range test.Layouts {
				for k, v := range l {
					err := os.MkdirAll(filepath.Join(loc, filepath.Dir(k)), 0755)
					if err != nil && !os.IsExist(err) {
						t.Fatalf("cannot create filesystem layout: %q", err)
					}
					err = os.WriteFile(filepath.Join(loc, k), []byte(v), 0644)
					if err != nil && !os.IsExist(err) {
						t.Fatalf("cannot create filesystem layout: %q", err)
					}
				}

				tester := test.Tester[i](t, loc, state)
				tester.Name = fmt.Sprintf("test-%003d", i)
				tester.Run()
			}
		})
	}
}

func TestWorkspace_ApplySLSADefaults(t *testing.T) {
	tests := []struct {
		name              string
		provenanceEnabled bool
		provenanceSLSA    bool
		gitOrigin         string
		existingEnvVars   map[string]string
		expectedEnvVars   map[string]string
	}{
		{
			name:              "SLSA enabled - sets all defaults",
			provenanceEnabled: true,
			provenanceSLSA:    true,
			gitOrigin:         "github.com/gitpod-io/leeway",
			existingEnvVars:   map[string]string{},
			expectedEnvVars: map[string]string{
				leeway.EnvvarSLSACacheVerification:   "true",
				leeway.EnvvarEnableInFlightChecksums: "true",
				leeway.EnvvarDockerExportToCache:     "true",
				leeway.EnvvarSLSASourceURI:           "github.com/gitpod-io/leeway",
			},
		},
		{
			name:              "SLSA disabled - no defaults set",
			provenanceEnabled: true,
			provenanceSLSA:    false,
			existingEnvVars:   map[string]string{},
			expectedEnvVars: map[string]string{
				leeway.EnvvarSLSACacheVerification:   "",
				leeway.EnvvarEnableInFlightChecksums: "",
				leeway.EnvvarDockerExportToCache:     "",
				leeway.EnvvarSLSASourceURI:           "",
			},
		},
		{
			name:              "Provenance disabled - no defaults set",
			provenanceEnabled: false,
			provenanceSLSA:    true,
			existingEnvVars:   map[string]string{},
			expectedEnvVars: map[string]string{
				leeway.EnvvarSLSACacheVerification:   "",
				leeway.EnvvarEnableInFlightChecksums: "",
				leeway.EnvvarDockerExportToCache:     "",
				leeway.EnvvarSLSASourceURI:           "",
			},
		},
		{
			name:              "Existing env vars - respects user overrides",
			provenanceEnabled: true,
			provenanceSLSA:    true,
			gitOrigin:         "github.com/gitpod-io/leeway",
			existingEnvVars: map[string]string{
				leeway.EnvvarSLSACacheVerification:   "false",
				leeway.EnvvarEnableInFlightChecksums: "false",
			},
			expectedEnvVars: map[string]string{
				leeway.EnvvarSLSACacheVerification:   "false", // Not overridden
				leeway.EnvvarEnableInFlightChecksums: "false", // Not overridden
				leeway.EnvvarDockerExportToCache:     "true",  // Set (wasn't present)
				leeway.EnvvarSLSASourceURI:           "github.com/gitpod-io/leeway",
			},
		},
		{
			name:              "SLSA enabled without Git origin",
			provenanceEnabled: true,
			provenanceSLSA:    true,
			gitOrigin:         "",
			existingEnvVars:   map[string]string{},
			expectedEnvVars: map[string]string{
				leeway.EnvvarSLSACacheVerification:   "true",
				leeway.EnvvarEnableInFlightChecksums: "true",
				leeway.EnvvarDockerExportToCache:     "true",
				leeway.EnvvarSLSASourceURI:           "", // Not set without Git origin
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear environment variables for clean test
			envVarsToCheck := []string{
				leeway.EnvvarSLSACacheVerification,
				leeway.EnvvarEnableInFlightChecksums,
				leeway.EnvvarDockerExportToCache,
				leeway.EnvvarSLSASourceURI,
			}
			for _, key := range envVarsToCheck {
				t.Setenv(key, "")
			}

			// Set existing env vars for this test
			for key, val := range tt.existingEnvVars {
				t.Setenv(key, val)
			}

			// Create test workspace
			ws := &leeway.Workspace{
				Provenance: leeway.WorkspaceProvenance{
					Enabled: tt.provenanceEnabled,
					SLSA:    tt.provenanceSLSA,
				},
				Git: leeway.GitInfo{
					Origin: tt.gitOrigin,
				},
			}

			// Apply defaults
			ws.ApplySLSADefaults()

			// Verify environment variables
			for key, expected := range tt.expectedEnvVars {
				actual := os.Getenv(key)
				if actual != expected {
					t.Errorf("%s: expected %q, got %q", key, expected, actual)
				}
			}
		})
	}
}
