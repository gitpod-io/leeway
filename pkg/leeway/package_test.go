package leeway

import (
	"fmt"
	"reflect"
	"testing"
)

func TestResolveBuiltinVariables(t *testing.T) {
	tests := []struct {
		PkgType     PackageType
		Cfg         PackageConfig
		ExpectedErr error
		ExpectedCfg PackageConfig
	}{
		{TypescriptPackage, TypescriptPkgConfig{TSConfig: "${__pkg_version}.json", Packaging: TypescriptLibrary}, nil, TypescriptPkgConfig{TSConfig: "this-version.json", Packaging: TypescriptLibrary}},
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

		packageInternal: packageInternal{
			Name: name,
			Type: GenericPackage,
		},
		versionCache: "this-version",
		Config:       GenericPkgConfig{},
	}
}
