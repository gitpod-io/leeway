package vet

import (
	"fmt"

	log "github.com/sirupsen/logrus"
	"github.com/typefox/leeway/pkg/leeway"
)

func init() {
	register(PackageCheck("use-package", "attempts to find broken package paths in the commands", leeway.GenericPackage, checkArgsReferingToPackage))
}

func checkArgsReferingToPackage(pkg *leeway.Package) ([]Finding, error) {
	cfg, ok := pkg.Config.(leeway.GenericPkgConfig)
	if !ok {
		// this is an error as compared to a finding because the issue most likely is with leeway,
		// and not a user config error.
		return nil, fmt.Errorf("Generic package does not have generic package config")
	}

	var findings []Finding
	for i, cmd := range cfg.Commands {
		for _, seg := range cmd {
			if !filesystemSafePathPattern.MatchString(seg) {
				continue
			}

			pth := filesystemSafePathPattern.FindString(seg)
			log.WithField("pth", pth).WithField("pkg", pkg.FullName()).Debug("found potential package use")

			// we've found something that looks like a path - check if we have a dependency that could satisfy it
			var satisfied bool
			for _, dep := range pkg.GetDependencies() {
				if dep.FilesystemSafeName() == pth {
					satisfied = true
					break
				}
			}
			if satisfied {
				continue
			}

			findings = append(findings, Finding{
				Description: fmt.Sprintf("Command %d refers to %s which looks like a package path, but no dependency satisfies it", i, seg),
				Component:   pkg.C,
				Package:     pkg,
				Error:       false,
			})
		}
	}

	return findings, nil
}
