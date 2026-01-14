package leeway

import (
	"fmt"
	"os"
	"path"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestResolveBuiltinGitVariables(t *testing.T) {
	// get the current file/dir so we can insert files/paths that will actually resolve to something
	_, filename, _, _ := runtime.Caller(0)
	// also files/dirs in `GitInfo.dirtyFiles` don't have a leading/trailing separator, so strip it
	filename = strings.TrimPrefix(filename, string(os.PathSeparator))
	dir := path.Dir(filename) + string(os.PathSeparator)

	depNotChanged := NewTestPackage("dep-no-change")
	depWithChange := NewTestPackage("dep-with-change")
	depWithChange.Sources = append(depWithChange.Sources, filename)

	tests := []struct {
		name              string
		gitInfo           *GitInfo
		sources           []string
		deps              []*Package
		expectedBuildArgs map[string]string
		expectedErr       error
	}{
		{
			name: "package is clean",
			gitInfo: &GitInfo{
				Commit: "425b74bc42c2eba6409cf2b869b084fe8c03067f",
				dirty:  false,
			},
			expectedBuildArgs: map[string]string{
				BuildinArgGitCommit:      "425b74bc42c2eba6409cf2b869b084fe8c03067f",
				BuildinArgGitCommitShort: "425b74b",
			},
			expectedErr: nil,
		},
		{
			name: "dirty tree, package is clean",
			gitInfo: &GitInfo{
				Commit: "425b74bc42c2eba6409cf2b869b084fe8c03067f",
				dirty:  true,
				dirtyFiles: map[string]struct{}{
					filename: {},
					dir:      {},
				},
			},
			expectedBuildArgs: map[string]string{
				BuildinArgGitCommit:      "425b74bc42c2eba6409cf2b869b084fe8c03067f",
				BuildinArgGitCommitShort: "425b74b",
			},
			expectedErr: nil,
		},
		{
			name:    "package is dirty. file not committed",
			sources: []string{filename},
			gitInfo: &GitInfo{
				Commit: "425b74bc42c2eba6409cf2b869b084fe8c03067f",
				dirty:  true,
				dirtyFiles: map[string]struct{}{
					filename: {},
				},
			},
			expectedBuildArgs: map[string]string{
				BuildinArgGitCommit:      "425b74bc42c2eba6409cf2b869b084fe8c03067f-this-version",
				BuildinArgGitCommitShort: "425b74b-this-version",
			},
			expectedErr: nil,
		},
		{
			name:    "package is dirty. source added and dir not in git",
			sources: []string{filename},
			gitInfo: &GitInfo{
				Commit: "425b74bc42c2eba6409cf2b869b084fe8c03067f",
				dirty:  true,
				dirtyFiles: map[string]struct{}{
					dir: {},
				},
			},
			expectedBuildArgs: map[string]string{
				BuildinArgGitCommit:      "425b74bc42c2eba6409cf2b869b084fe8c03067f-this-version",
				BuildinArgGitCommitShort: "425b74b-this-version",
			},
			expectedErr: nil,
		},
		{
			name: "has dep, dirty tree, pkg not dirty",
			gitInfo: &GitInfo{
				Commit: "425b74bc42c2eba6409cf2b869b084fe8c03067f",
				dirty:  true,
				dirtyFiles: map[string]struct{}{
					filename: {},
				},
			},
			deps: []*Package{depNotChanged},
			expectedBuildArgs: map[string]string{
				BuildinArgGitCommit:      "425b74bc42c2eba6409cf2b869b084fe8c03067f",
				BuildinArgGitCommitShort: "425b74b",
			},
			expectedErr: nil,
		},
		{
			name: "has dirty dep",
			gitInfo: &GitInfo{
				Commit: "425b74bc42c2eba6409cf2b869b084fe8c03067f",
				dirty:  true,
				dirtyFiles: map[string]struct{}{
					filename: {},
				},
			},
			deps: []*Package{depWithChange},
			expectedBuildArgs: map[string]string{
				BuildinArgGitCommit:      "425b74bc42c2eba6409cf2b869b084fe8c03067f-this-version",
				BuildinArgGitCommitShort: "425b74b-this-version",
			},
			expectedErr: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pkg := NewTestPackage("pkg")
			pkg.Sources = append(pkg.Sources, test.sources...)
			pkg.dependencies = append(pkg.dependencies, test.deps...)
			pkg.C.git = test.gitInfo

			vars := map[string]string{}
			err := resolveBuiltinGitVariables(pkg, vars)

			assert.ErrorIs(t, test.expectedErr, err)
			assert.Equal(t, test.expectedBuildArgs, vars)
		})
	}
}

func TestResolveBuiltinVariables(t *testing.T) {
	tests := []struct {
		PkgType     PackageType
		Cfg         PackageConfig
		ExpectedErr error
		ExpectedCfg PackageConfig
	}{
		{YarnPackage, YarnPkgConfig{TSConfig: "${__pkg_version}.json", Packaging: YarnLibrary}, nil, YarnPkgConfig{TSConfig: "this-version.json", Packaging: YarnLibrary}},
		{DockerPackage, DockerPkgConfig{Dockerfile: "leeway.Dockerfile", Image: []string{"foobar:${__pkg_version}"}}, nil, DockerPkgConfig{Dockerfile: "leeway.Dockerfile", Image: []string{"foobar:this-version"}}},
		{GoPackage, GoPkgConfig{Packaging: GoApp, BuildFlags: []string{"-ldflags", "-X cmd.version=${__pkg_version}"}}, nil, GoPkgConfig{Packaging: GoApp, BuildFlags: []string{"-ldflags", "-X cmd.version=this-version"}}},
		{GenericPackage, GenericPkgConfig{Commands: [][]string{{"echo", "${__pkg_version}"}}}, nil, GenericPkgConfig{Commands: [][]string{{"echo", "this-version"}}}},
	}

	for _, test := range tests {
		pkg := NewTestPackage("pkg")

		pkg.Type = test.PkgType
		pkg.Config = test.Cfg
		err := pkg.resolveBuiltinVariables()
		if err != test.ExpectedErr {
			t.Errorf("%s: error != expected error. expected: %v, actual: %v", test.PkgType, test.ExpectedErr, err)
			continue
		}

		if !reflect.DeepEqual(pkg.Config, test.ExpectedCfg) {
			t.Errorf("%s: pkg.Config != test.ExpectedCfg. expected: %v, actual: %v", test.PkgType, test.ExpectedCfg, pkg.Config)
			continue
		}
	}
}

func TestResolveBuiltinVariablesInPackageInternal(t *testing.T) {
	tests := []struct {
		Name         string
		Prep         [][]string
		Env          []string
		ExpectedPrep [][]string
		ExpectedEnv  []string
	}{
		{
			Name:         "prep with __pkg_version",
			Prep:         [][]string{{"/bin/bash", "prepare.sh", "${__pkg_version}"}},
			ExpectedPrep: [][]string{{"/bin/bash", "prepare.sh", "this-version"}},
		},
		{
			Name:        "env with __pkg_version",
			Env:         []string{"VERSION=${__pkg_version}"},
			ExpectedEnv: []string{"VERSION=this-version"},
		},
		{
			Name:         "prep and env with __pkg_version",
			Prep:         [][]string{{"echo", "${__pkg_version}"}},
			Env:          []string{"BUILD_VERSION=${__pkg_version}"},
			ExpectedPrep: [][]string{{"echo", "this-version"}},
			ExpectedEnv:  []string{"BUILD_VERSION=this-version"},
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			pkg := NewTestPackage("pkg")
			pkg.Type = GenericPackage
			pkg.Config = GenericPkgConfig{Commands: [][]string{{"echo", "hello"}}}
			pkg.PreparationCommands = test.Prep
			pkg.Environment = test.Env

			err := pkg.resolveBuiltinVariables()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if test.ExpectedPrep != nil && !reflect.DeepEqual(pkg.PreparationCommands, test.ExpectedPrep) {
				t.Errorf("PreparationCommands mismatch. expected: %v, actual: %v", test.ExpectedPrep, pkg.PreparationCommands)
			}

			if test.ExpectedEnv != nil && !reflect.DeepEqual(pkg.Environment, test.ExpectedEnv) {
				t.Errorf("Environment mismatch. expected: %v, actual: %v", test.ExpectedEnv, pkg.Environment)
			}
		})
	}
}

func TestFindCycles(t *testing.T) {
	tests := []struct {
		Name  string
		Pkg   func() *Package
		Cycle []string
		Error string
	}{
		{
			Name: "no cycles",
			Pkg: func() *Package {
				ps := make([]*Package, 5)
				for i := range ps {
					p := NewTestPackage(fmt.Sprintf("pkg-%d", i))
					if i > 0 {
						p.dependencies = ps[:i]
						p.C = ps[0].C
					}
					p.C.W.Packages[p.FullName()] = p
					ps[i] = p
				}
				return ps[len(ps)-1]
			},
			Cycle: nil,
		},
		{
			Name: "auto-dependency",
			Pkg: func() *Package {
				pkg := NewTestPackage("pkg")
				pkg.dependencies = []*Package{pkg}
				pkg.C.W.Packages = map[string]*Package{pkg.Name: pkg}
				return pkg
			},
			Cycle: []string{"testcomp:pkg", "testcomp:pkg"},
		},
		{
			Name: "full cycles",
			Pkg: func() *Package {
				ps := make([]*Package, 5)
				for i := range ps {
					p := NewTestPackage(fmt.Sprintf("pkg-%d", i))
					if i > 0 {
						p.C = ps[0].C
						p.dependencies = ps[i-1 : i]
					}
					p.C.W.Packages[p.FullName()] = p
					ps[i] = p
				}
				ps[0].dependencies = []*Package{ps[len(ps)-1]}
				return ps[0]
			},
			Cycle: []string{"testcomp:pkg-0", "testcomp:pkg-4", "testcomp:pkg-3", "testcomp:pkg-2", "testcomp:pkg-1", "testcomp:pkg-0"},
		},
		{
			Name: "broken index",
			Pkg: func() *Package {
				ps := make([]*Package, 5)
				for i := range ps {
					p := NewTestPackage(fmt.Sprintf("pkg-%d", i))
					if i > 0 {
						p.C = ps[0].C
						p.dependencies = ps[i-1 : i]
					}
					ps[i] = p
				}
				ps[0].dependencies = []*Package{ps[len(ps)-1]}
				return ps[0]
			},
			Error: "[internal error] depth exceeds max path length: looks like the workspace package index isn't build properly",
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			act, err := test.Pkg().findCycle()
			var errmsg string
			if err != nil {
				errmsg = err.Error()
			}
			if errmsg != test.Error {
				t.Errorf("unexpected error: expected %q, found %q", test.Error, errmsg)
			}
			if !reflect.DeepEqual(act, test.Cycle) {
				t.Errorf("found unexpected cycle: expected %q, found %q", test.Cycle, act)
			}
		})
	}
}

var benchmarkFindCycleDummyResult []string

func BenchmarkFindCycle(b *testing.B) {
	b.ReportAllocs()

	for _, size := range []int{5, 25, 50, 100, 200, 400} {
		b.Run(fmt.Sprintf("size-%03d", size), func(b *testing.B) {
			var ps = make([]*Package, size)
			for i := range ps {
				p := NewTestPackage(fmt.Sprintf("pkg-%d", i))
				if i > 0 {
					p.C = ps[0].C
					p.dependencies = ps[i-1 : i]
				}
				p.C.W.Packages[p.FullName()] = p
				ps[i] = p
			}
			ps[0].dependencies = []*Package{ps[len(ps)-1]}
			b.ResetTimer()

			p := ps[len(ps)-1]
			var r []string
			for n := 0; n < b.N; n++ {
				r, _ = p.findCycle()
			}
			benchmarkFindCycleDummyResult = r
		})
	}

}

func NewTestPackage(name string) *Package {
	return &Package{
		C: &Component{
			W: &Workspace{
				Packages: make(map[string]*Package),
			},
			Origin: "testcomp",
			Name:   "testcomp",
		},

		PackageInternal: PackageInternal{
			Name: name,
			Type: GenericPackage,
		},
		versionCache: "this-version",
		Config:       GenericPkgConfig{},
	}
}

func TestGoLibraryAutoWeakDeps(t *testing.T) {
	t.Run("Go library deps auto-converted to weak deps", func(t *testing.T) {
		goLib := NewTestPackage("go-lib")
		goLib.Type = GoPackage
		goLib.Config = GoPkgConfig{Packaging: GoLibrary}

		pkg := NewTestPackage("main-pkg")
		pkg.Dependencies = []string{"testcomp:go-lib"}
		pkg.dependencies = nil // Reset to allow linking

		idx := map[string]*Package{
			"testcomp:go-lib": goLib,
		}

		err := pkg.link(idx)
		assert.NoError(t, err)

		// Go library should be in weak deps, not hard deps
		assert.Len(t, pkg.GetDependencies(), 0, "Go library should not be in hard deps")
		assert.Len(t, pkg.GetWeakDependencies(), 1, "Go library should be in weak deps")
		assert.Equal(t, "go-lib", pkg.GetWeakDependencies()[0].Name)
	})

	t.Run("Go app deps remain as hard deps", func(t *testing.T) {
		goApp := NewTestPackage("go-app")
		goApp.Type = GoPackage
		goApp.Config = GoPkgConfig{Packaging: GoApp}

		pkg := NewTestPackage("main-pkg")
		pkg.Dependencies = []string{"testcomp:go-app"}
		pkg.dependencies = nil

		idx := map[string]*Package{
			"testcomp:go-app": goApp,
		}

		err := pkg.link(idx)
		assert.NoError(t, err)

		// Go app should remain as hard dep
		assert.Len(t, pkg.GetDependencies(), 1, "Go app should be in hard deps")
		assert.Len(t, pkg.GetWeakDependencies(), 0, "Go app should not be in weak deps")
	})

	t.Run("non-Go deps remain as hard deps", func(t *testing.T) {
		dockerPkg := NewTestPackage("docker-pkg")
		dockerPkg.Type = DockerPackage
		dockerPkg.Config = DockerPkgConfig{Dockerfile: "Dockerfile"}

		pkg := NewTestPackage("main-pkg")
		pkg.Dependencies = []string{"testcomp:docker-pkg"}
		pkg.dependencies = nil

		idx := map[string]*Package{
			"testcomp:docker-pkg": dockerPkg,
		}

		err := pkg.link(idx)
		assert.NoError(t, err)

		assert.Len(t, pkg.GetDependencies(), 1)
		assert.Len(t, pkg.GetWeakDependencies(), 0)
	})

	t.Run("mixed deps correctly separated", func(t *testing.T) {
		goLib := NewTestPackage("go-lib")
		goLib.Type = GoPackage
		goLib.Config = GoPkgConfig{Packaging: GoLibrary}

		goApp := NewTestPackage("go-app")
		goApp.Type = GoPackage
		goApp.Config = GoPkgConfig{Packaging: GoApp}

		genericPkg := NewTestPackage("generic-pkg")
		genericPkg.Type = GenericPackage
		genericPkg.Config = GenericPkgConfig{}

		pkg := NewTestPackage("main-pkg")
		pkg.Dependencies = []string{"testcomp:go-lib", "testcomp:go-app", "testcomp:generic-pkg"}
		pkg.dependencies = nil

		idx := map[string]*Package{
			"testcomp:go-lib":      goLib,
			"testcomp:go-app":      goApp,
			"testcomp:generic-pkg": genericPkg,
		}

		err := pkg.link(idx)
		assert.NoError(t, err)

		// Go library -> weak dep, others -> hard deps
		assert.Len(t, pkg.GetDependencies(), 2, "Should have 2 hard deps")
		assert.Len(t, pkg.GetWeakDependencies(), 1, "Should have 1 weak dep")

		// Verify the weak dep is the Go library
		assert.Equal(t, "go-lib", pkg.GetWeakDependencies()[0].Name)
	})

	t.Run("Go library layout respected", func(t *testing.T) {
		goLib := NewTestPackage("go-lib")
		goLib.Type = GoPackage
		goLib.Config = GoPkgConfig{Packaging: GoLibrary}

		pkg := NewTestPackage("main-pkg")
		pkg.Dependencies = []string{"testcomp:go-lib"}
		pkg.Layout = map[string]string{"testcomp:go-lib": "custom-location"}
		pkg.dependencies = nil

		idx := map[string]*Package{
			"testcomp:go-lib": goLib,
		}

		err := pkg.link(idx)
		assert.NoError(t, err)

		loc := pkg.BuildLayoutLocation(goLib)
		assert.Equal(t, "custom-location", loc)
	})

	t.Run("weak deps included in version manifest", func(t *testing.T) {
		goLib := NewTestPackage("go-lib")
		goLib.Type = GoPackage
		goLib.Config = GoPkgConfig{Packaging: GoLibrary}
		goLib.versionCache = "lib-version-hash"

		pkg := NewTestPackage("main-pkg")
		pkg.Dependencies = []string{"testcomp:go-lib"}
		pkg.dependencies = nil

		idx := map[string]*Package{
			"testcomp:go-lib": goLib,
		}

		err := pkg.link(idx)
		assert.NoError(t, err)

		pkg.versionCache = "" // Clear cache to force recalculation

		var buf strings.Builder
		err = pkg.WriteVersionManifest(&buf)
		assert.NoError(t, err)

		manifest := buf.String()
		assert.Contains(t, manifest, "weak:testcomp:go-lib.lib-version-hash")
	})

	t.Run("weak dep change affects version", func(t *testing.T) {
		goLib1 := NewTestPackage("go-lib")
		goLib1.Type = GoPackage
		goLib1.Config = GoPkgConfig{Packaging: GoLibrary}
		goLib1.versionCache = "version-1"

		goLib2 := NewTestPackage("go-lib")
		goLib2.Type = GoPackage
		goLib2.Config = GoPkgConfig{Packaging: GoLibrary}
		goLib2.versionCache = "version-2"

		pkg1 := NewTestPackage("main-pkg")
		pkg1.dependencies = []*Package{}
		pkg1.weakDependencies = []*Package{goLib1}
		pkg1.versionCache = ""

		pkg2 := NewTestPackage("main-pkg")
		pkg2.dependencies = []*Package{}
		pkg2.weakDependencies = []*Package{goLib2}
		pkg2.versionCache = ""

		var buf1, buf2 strings.Builder
		_ = pkg1.WriteVersionManifest(&buf1)
		_ = pkg2.WriteVersionManifest(&buf2)

		// Different weak dep versions should produce different manifests
		assert.NotEqual(t, buf1.String(), buf2.String())
	})

	t.Run("nested Go library deps become weak deps", func(t *testing.T) {
		// lib-c is a Go library
		libC := NewTestPackage("lib-c")
		libC.Type = GoPackage
		libC.Config = GoPkgConfig{Packaging: GoLibrary}

		// lib-b is a Go library that depends on lib-c
		libB := NewTestPackage("lib-b")
		libB.Type = GoPackage
		libB.Config = GoPkgConfig{Packaging: GoLibrary}
		libB.Dependencies = []string{"testcomp:lib-c"}
		libB.dependencies = nil

		// Link lib-b first
		idx := map[string]*Package{
			"testcomp:lib-c": libC,
		}
		err := libB.link(idx)
		assert.NoError(t, err)

		// lib-c should be a weak dep of lib-b (since it's a Go library)
		assert.Len(t, libB.GetDependencies(), 0, "lib-c should not be hard dep of lib-b")
		assert.Len(t, libB.GetWeakDependencies(), 1, "lib-c should be weak dep of lib-b")

		// app depends on lib-b
		app := NewTestPackage("app")
		app.Type = GoPackage
		app.Config = GoPkgConfig{Packaging: GoApp}
		app.Dependencies = []string{"testcomp:lib-b"}
		app.dependencies = nil

		idx["testcomp:lib-b"] = libB
		err = app.link(idx)
		assert.NoError(t, err)

		// lib-b should be a weak dep of app
		assert.Len(t, app.GetDependencies(), 0)
		assert.Len(t, app.GetWeakDependencies(), 1)
		assert.Equal(t, "lib-b", app.GetWeakDependencies()[0].Name)
	})

	t.Run("GetTransitiveWeakDependencies collects nested weak deps", func(t *testing.T) {
		// lib-c is a Go library
		libC := NewTestPackage("lib-c")
		libC.Type = GoPackage
		libC.Config = GoPkgConfig{Packaging: GoLibrary}
		libC.dependencies = []*Package{}
		libC.weakDependencies = []*Package{}

		// lib-b depends on lib-c (both Go libraries)
		libB := NewTestPackage("lib-b")
		libB.Type = GoPackage
		libB.Config = GoPkgConfig{Packaging: GoLibrary}
		libB.dependencies = []*Package{}
		libB.weakDependencies = []*Package{libC}

		// app depends on lib-b
		app := NewTestPackage("app")
		app.Type = GoPackage
		app.Config = GoPkgConfig{Packaging: GoApp}
		app.dependencies = []*Package{}
		app.weakDependencies = []*Package{libB}

		// GetTransitiveWeakDependencies should return both lib-b and lib-c
		transitiveWeakDeps := app.GetTransitiveWeakDependencies()

		assert.Len(t, transitiveWeakDeps, 2, "Should have 2 transitive weak deps")

		names := make(map[string]bool)
		for _, p := range transitiveWeakDeps {
			names[p.Name] = true
		}
		assert.True(t, names["lib-b"], "Should include lib-b")
		assert.True(t, names["lib-c"], "Should include lib-c")
	})

	t.Run("version manifest includes transitive weak deps", func(t *testing.T) {
		// lib-c is a Go library
		libC := NewTestPackage("lib-c")
		libC.Type = GoPackage
		libC.Config = GoPkgConfig{Packaging: GoLibrary}
		libC.dependencies = []*Package{}
		libC.weakDependencies = []*Package{}
		libC.versionCache = "lib-c-version"

		// lib-b depends on lib-c (both Go libraries)
		libB := NewTestPackage("lib-b")
		libB.Type = GoPackage
		libB.Config = GoPkgConfig{Packaging: GoLibrary}
		libB.dependencies = []*Package{}
		libB.weakDependencies = []*Package{libC}
		libB.versionCache = "lib-b-version"

		// app depends on lib-b
		app := NewTestPackage("app")
		app.Type = GoPackage
		app.Config = GoPkgConfig{Packaging: GoApp}
		app.dependencies = []*Package{}
		app.weakDependencies = []*Package{libB}
		app.versionCache = ""

		var buf strings.Builder
		err := app.WriteVersionManifest(&buf)
		assert.NoError(t, err)

		manifest := buf.String()
		// Both lib-b and lib-c should be in the manifest (transitive weak deps)
		assert.Contains(t, manifest, "weak:testcomp:lib-b.lib-b-version")
		assert.Contains(t, manifest, "weak:testcomp:lib-c.lib-c-version")
	})
}

func TestCodecovComponentName(t *testing.T) {
	tests := []struct {
		Test     string
		Package  string
		Expected string
	}{
		{"valid package format", "components/ee/ws-scheduler", "components-ee-ws-scheduler-coverage.out"},
		{"lower case", "COMPONENTS/gitpod-cli:app", "components-gitpod-cli-app-coverage.out"},
		{"special character", "components/~ü:app", "components-app-coverage.out"},
		{"with numbers", "components/1icens0r:app", "components-1icens0r-app-coverage.out"},
	}

	for _, test := range tests {
		name := codecovComponentName(test.Package)
		if name != test.Expected {
			t.Errorf("%s: expected: %v, actual: %v", test.Test, test.Expected, name)
		}
	}
}
