package leeway

import (
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
		{GenericPackage, GenericPkgConfig{Command: []string{"echo", "${__pkg_version}"}}, nil, GenericPkgConfig{Command: []string{"echo", "this-version"}}},
	}

	for _, test := range tests {
		pkg := NewTestPackage()

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

func NewTestPackage() *Package {
	return &Package{
		C: &Component{
			W:      &Workspace{},
			Origin: "testcomp",
			Name:   "testcomp",
		},

		packageInternal: packageInternal{
			Name: "pkg",
			Type: GenericPackage,
		},
		versionCache: "this-version",
		Config:       GenericPkgConfig{},
	}
}
