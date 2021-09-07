package vet

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/gitpod-io/leeway/pkg/leeway"
)

func init() {
	register(PackageCheck("copy-from-pacakge", "attempts to find broken package paths in COPY and ADD statements", leeway.DockerPackage, checkDockerCopyFromPackage))
}

var (
	filesystemSafePathPattern = regexp.MustCompile(`([a-zA-Z0-9\.]+\-)+\-([a-zA-Z0-9\.\-]+)`)
)

func checkDockerCopyFromPackage(pkg *leeway.Package) ([]Finding, error) {
	cfg, ok := pkg.Config.(leeway.DockerPkgConfig)
	if !ok {
		// this is an error as compared to a finding because the issue most likely is with leeway,
		// and not a user config error.
		return nil, fmt.Errorf("Docker package does not have docker package config")
	}

	var dockerfileFN string
	for _, src := range pkg.Sources {
		if strings.HasSuffix(src, "/"+cfg.Dockerfile) {
			dockerfileFN = src
		}
	}
	if dockerfileFN == "" {
		return []Finding{{
			Component:   pkg.C,
			Package:     pkg,
			Description: "package has no Dockerfile",
			Error:       true,
		}}, nil
	}

	f, err := os.Open(dockerfileFN)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var findings []Finding
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		segs := strings.Fields(scanner.Text())
		if len(segs) == 0 {
			continue
		}

		cmd := strings.ToLower(segs[0])
		if cmd != "add" && cmd != "copy" {
			continue
		}

		for _, s := range segs[1 : len(segs)-1] {
			if !filesystemSafePathPattern.MatchString(s) {
				continue
			}

			pth := filesystemSafePathPattern.FindString(s)
			log.WithField("pth", pth).WithField("dockerFile", dockerfileFN).WithField("pkg", pkg.FullName()).Debug("found potential copy source path")

			// we've found something that looks like a path - check if we have a dependency that could satisfy it
			var satisfied bool
			for _, dep := range pkg.GetDependencies() {
				if pkg.BuildLayoutLocation(dep) == pth {
					satisfied = true
					break
				}
			}
			if satisfied {
				continue
			}

			findings = append(findings, Finding{
				Description: fmt.Sprintf("%s copies from %s which looks like a package path, but no dependency satisfies it", cfg.Dockerfile, s),
				Component:   pkg.C,
				Package:     pkg,
				Error:       false,
			})
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return findings, nil
}
