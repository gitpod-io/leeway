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
