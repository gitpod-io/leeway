package vet

import (
	"strings"

	"github.com/typefox/leeway/pkg/leeway"
)

func init() {
	tpe := leeway.GoPackage
	register(Check{
		Name:          "golang:has-gomod",
		Description:   "ensures all Go packages have a go.mod file in their source list",
		AppliesToType: &tpe,
		RunPkg:        checkGolangHasGomod,
	})
}

func checkGolangHasGomod(pkg *leeway.Package) ([]Finding, error) {
	var (
		foundGoMod bool
		foundGoSum bool
	)
	for _, src := range pkg.Sources {
		if strings.HasSuffix(src, "/go.mod") {
			foundGoMod = true
		}
		if strings.HasSuffix(src, "/go.sum") {
			foundGoSum = true
		}
		if foundGoSum && foundGoMod {
			return nil, nil
		}
	}

	var f []Finding
	if !foundGoMod {
		f = append(f, Finding{
			Component:   pkg.C,
			Description: "package sources contain no go.mod file",
			Error:       true,
			Package:     pkg,
		})
	}
	if !foundGoSum {
		f = append(f, Finding{
			Component:   pkg.C,
			Description: "package sources contain no go.sum file",
			Error:       true,
			Package:     pkg,
		})
	}
	return f, nil
}
