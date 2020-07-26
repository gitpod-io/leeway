package linker

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"

	log "github.com/sirupsen/logrus"
	"github.com/typefox/leeway/pkg/internal/jsonmap"
	"github.com/typefox/leeway/pkg/internal/yarn"
	"github.com/typefox/leeway/pkg/leeway"
	"golang.org/x/xerrors"
)

// LinkYarnPackagesWithYarn2 uses `yarn link` to link all TS packages in-situ.
func LinkYarnPackagesWithYarn2(workspace *leeway.Workspace) error {
	var (
		pkgIdx     = make(map[string]string)
		pkgJSONIdx = make(map[string]string)
	)
	for n, p := range workspace.Packages {
		if p.Type != leeway.YarnPackage {
			continue
		}

		pkgjson, err := yarn.GetPackageJSON(p)
		if err != nil {
			return err
		}
		pkgJSONIdx[n] = pkgjson.Origin
		pkgIdx[n] = string(pkgjson.Name)
	}

	for n, p := range workspace.Packages {
		if p.Type != leeway.YarnPackage {
			continue
		}
		pkgjsonFn := pkgJSONIdx[n]

		fc, err := ioutil.ReadFile(pkgjsonFn)
		if err != nil {
			return err
		}
		var pkgjson map[string]interface{}
		err = json.Unmarshal(fc, &pkgjson)
		if err != nil {
			return err
		}

		var resolutions map[string]interface{}
		if res, ok := pkgjson["resolutions"]; ok {
			resolutions, ok = res.(map[string]interface{})
			if !ok {
				return xerrors.Errorf("%s: found resolutions but they're not a map", n)
			}
		} else {
			resolutions = make(map[string]interface{})
		}
		for _, dep := range p.GetTransitiveDependencies() {
			if dep.Type != leeway.YarnPackage {
				continue
			}

			yarnPkg, ok := pkgIdx[dep.FullName()]
			if !ok {
				log.WithField("dep", dep.FullName()).WithField("pkg", n).Warn("did not find yarn package name - linking might be broken")
				continue
			}
			resolutions[yarnPkg] = fmt.Sprintf("portal://%s", dep.C.Origin)
		}
		if len(resolutions) > 0 {
			pkgjson["resolutions"] = resolutions
		}

		fd, err := os.OpenFile(pkgjsonFn, os.O_TRUNC|os.O_WRONLY, 0644)
		if err != nil {
			return err
		}
		enc := json.NewEncoder(fd)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")
		err = enc.Encode(pkgjson)
		fd.Close()
		if err != nil {
			return err
		}

		log.WithField("pkg", n).WithField("resolutions", resolutions).Debug("linked package")
	}

	var lerr error
	for n, p := range workspace.Packages {
		if p.Type != leeway.YarnPackage {
			continue
		}

		cmd := exec.Command("yarn")
		log.WithField("pkg", n).WithField("cwd", p.C.Origin).WithField("cmd", "yarn").Debug("running yarn")
		cmd.Dir = p.C.Origin
		cmd.Stdout = os.Stdout
		cmd.Stdin = os.Stdin
		cmd.Stderr = os.Stderr
		err := cmd.Run()
		if err != nil {
			log.WithError(err).Error("error while running yarn")
			lerr = xerrors.Errorf("yarn failed for %s: %w", n, err)
		}
	}

	return lerr
}

// LinkYarnPackagesCrossWorkspace links yarn packages across yarn workspaces using relative paths
// in the dependency version. This method does not work with the yarn2 linker.
func LinkYarnPackagesCrossWorkspace(ws *leeway.Workspace) error {
	_, yarnToPkgJSON, err := yarn.MapYarnToLeeway(ws)
	if err != nil {
		return err
	}

	yarnPkgLocIdx := make(map[yarn.PackageName]string, len(yarnToPkgJSON))
	for yarnName, pkgJSON := range yarnToPkgJSON {
		origin := filepath.Dir(pkgJSON.Origin)
		if val, exists := yarnPkgLocIdx[yarnName]; exists && val != origin {
			return xerrors.Errorf("found multiple locations for \"%s\": %s and %s", yarnName, val, origin)
		}
	}

	for _, pkg := range ws.Packages {
		if pkg.Type != leeway.YarnPackage {
			continue
		}

		pkgJSON, err := yarn.GetPackageJSON(pkg)
		if err != nil {
			return err
		}
		fn := pkgJSON.Origin
		yarnPkg := pkgJSON.Name

		for _, dep := range pkg.GetDependencies() {
			if dep.Type != leeway.YarnPackage {
				continue
			}

			pjs, err := yarn.GetPackageJSON(dep)
			if err != nil {
				return err
			}
			var (
				depName    = pjs.Name
				depVersion = pjs.Version
			)
			if depName == pkgJSON.Name {
				continue
			}

			fc, err := ioutil.ReadFile(fn)
			if err != nil {
				return err
			}
			pkgJSON := &jsonmap.OrderedMap{}
			err = json.Unmarshal(fc, pkgJSON)
			if err != nil {
				return xerrors.Errorf("cannot unmarshal %s: %w", fn, err)
			}

			var depsMap *jsonmap.OrderedMap
			deps, ok := pkgJSON.Get("dependencies")
			if !ok {
				depsMap = &jsonmap.OrderedMap{}
			} else {
				depsMap, ok = deps.(*jsonmap.OrderedMap)
				if !ok {
					return xerrors.Errorf("%s: dependencies are not a map", fn)
				}
			}

			var version string
			if dep.C.W.Origin == pkg.C.W.Origin {
				// dep satisfying leeway package is in the same leeway/yarn workspace,
				// set the version directly
				version = depVersion
			} else {
				// dep satisfying leeway package is located outside of the main package's leeway/yarn workspace.
				// Use the relative location as version.
				relLoc, err := filepath.Rel(pkg.C.Origin, dep.C.Origin)
				if err != nil {
					return err
				}
				version = relLoc
			}

			log.WithFields(log.Fields{
				"pkg":       pkg.FullName(),
				"dep":       dep.FullName(),
				"yarnPkg":   yarnPkg,
				"yarnDep":   depName,
				"pkgOrigin": pkg.C.W.Origin,
				"depOrigin": dep.C.W.Origin,
				"version":   version,
			}).Debug("linking yarn dep to pkg")

			depsMap.Set(string(depName), version)
			pkgJSON.Set("dependencies", depsMap)

			fc, err = jsonmap.MarshalJSON(pkgJSON, "  ", false)
			if err != nil {
				return err
			}
			err = ioutil.WriteFile(fn, fc, 0644)
			if err != nil {
				return err
			}
		}
	}

	return nil
}
