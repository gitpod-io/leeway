package vet

import (
	"fmt"

	"github.com/gitpod-io/leeway/pkg/leeway"
)

func init() {
	register(PackageCheck("build-layout", "validates the build layout of all packages", "", checkBuildLayout))
}

func checkBuildLayout(pkg *leeway.Package) (findings []Finding, err error) {
	layoutIdx := make(map[string]string)
	for dep, loc := range pkg.Layout {
		otherdep, taken := layoutIdx[loc]
		if !taken {
			layoutIdx[loc] = dep
			continue
		}

		findings = append(findings, Finding{
			Description: fmt.Sprintf("build-time location %v is used by %v and %v", loc, dep, otherdep),
			Component:   pkg.C,
			Error:       true,
			Package:     pkg,
		})
	}
	return
}
