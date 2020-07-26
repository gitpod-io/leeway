package vet

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/typefox/leeway/pkg/internal/yarn"
	"github.com/typefox/leeway/pkg/leeway"
	"gopkg.in/yaml.v3"
)

func init() {
	register(PackageCheck("deprecated-type", "checks if the package uses the deprecated typescript type", leeway.YarnPackage, checkYarnDeprecatedType))
	register(&checkImplicitTransitiveDependencies{})
}

func checkYarnDeprecatedType(pkg *leeway.Package) ([]Finding, error) {
	var rp struct {
		Type string `yaml:"type"`
	}
	err := yaml.Unmarshal(pkg.Definition, &rp)
	if err != nil {
		return nil, err
	}

	if rp.Type == string(leeway.DeprecatedTypescriptPackage) {
		return []Finding{
			{
				Description: "package uses deprecated \"typescript\" type - use \"yarn\" instead (run `leeway fmt -fi` to fix this)",
				Component:   pkg.C,
				Package:     pkg,
			},
		}, nil
	}

	return nil, nil
}

type checkImplicitTransitiveDependencies struct {
	pkgs map[yarn.PackageName][]*leeway.Package
}

func (c *checkImplicitTransitiveDependencies) Info() CheckInfo {
	tpe := leeway.YarnPackage
	return CheckInfo{
		Name:          "yarn:implicit-transitive-dependency",
		Description:   "checks if the package's code uses another Yarn package in the workspace without declaring the dependency",
		AppliesToType: &tpe,
		PackageCheck:  true,
	}
}

func (c *checkImplicitTransitiveDependencies) Init(ws leeway.Workspace) (err error) {
	c.pkgs, _, err = yarn.MapYarnToLeeway(&ws)
	if err != nil {
		return err
	}
	return nil
}

func (c *checkImplicitTransitiveDependencies) grepInFile(fn string, pat string) (contains bool, err error) {
	f, err := os.Open(fn)
	if err != nil {
		return
	}
	defer f.Close()

	patb := []byte(pat)
	r := bufio.NewReader(f)
	for {
		bt, err := r.ReadBytes('\n')
		if err == io.EOF {
			break
		}
		if err != nil {
			return false, err
		}

		if bytes.Contains(bt, patb) {
			return true, nil
		}
	}

	return false, nil
}

func (c *checkImplicitTransitiveDependencies) RunCmp(pkg *leeway.Component) ([]Finding, error) {
	return nil, fmt.Errorf("not a component check")
}

func (c *checkImplicitTransitiveDependencies) RunPkg(pkg *leeway.Package) ([]Finding, error) {
	depsInCode := make(map[yarn.PackageName]string)
	for _, src := range pkg.Sources {
		switch filepath.Ext(src) {
		case ".js":
		case ".ts":
		default:
			continue
		}

		for yarnpkg := range c.pkgs {
			ok, err := c.grepInFile(src, string(yarnpkg))
			if err != nil {
				return nil, err
			}
			if ok {
				depsInCode[yarnpkg] = src
			}
		}
	}

	var findings []Finding
	for yarnDep, src := range depsInCode {
		var found bool
		for _, leewayDep := range c.pkgs[yarnDep] {
			for _, dep := range pkg.GetDependencies() {
				if dep.FullName() == leewayDep.FullName() {
					found = true
					break
				}
			}
		}
		if found {
			continue
		}

		packageNames := make([]string, len(c.pkgs[yarnDep]))
		for i, p := range c.pkgs[yarnDep] {
			packageNames[i] = p.Name
		}
		findings = append(findings, Finding{
			Description: fmt.Sprintf("%s depends on the workspace Yarn-package %s (provided by %s) but does not declare that dependency in its BUILD.yaml", src, yarnDep, strings.Join(packageNames, ", ")),
			Error:       true,
			Component:   pkg.C,
			Package:     pkg,
		})
	}

	pkgjson, err := yarn.GetPackageJSON(pkg)
	if err != nil {
		return findings, err
	}
	for yarnDep, src := range depsInCode {
		_, found := pkgjson.Dependencies[yarnDep]
		if found {
			continue
		}

		log.WithField("pkg", pkg.FullName()).WithField("pkgJsonDeclaredDeps", pkgjson.Dependencies).WithField("yarnName", pkgjson.Name).Debug("found use of implicit transitive dependency")
		findings = append(findings, Finding{
			Description: fmt.Sprintf("%s depends on the workspace Yarn-package %s but does not declare that dependency in its package.json", src, yarnDep),
			Component:   pkg.C,
			Package:     pkg,
		})
	}

	return findings, nil
}
