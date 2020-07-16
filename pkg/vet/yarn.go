package vet

import (
	"github.com/typefox/leeway/pkg/leeway"
	"gopkg.in/yaml.v3"
)

func init() {
	register(Check{
		Name:        "yarn:deprecated-type",
		Description: "checks if the package uses the deprecated typescript type",
		RunPkg:      checkYarnDeprecatedType,
	})
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
