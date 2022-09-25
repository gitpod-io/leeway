package linker

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"

	log "github.com/sirupsen/logrus"
	"golang.org/x/xerrors"

	"github.com/gitpod-io/leeway/pkg/leeway"
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

		var pkgjsonFn string
		for _, src := range p.Sources {
			if strings.HasSuffix(src, "/package.json") {
				pkgjsonFn = src
				break
			}
		}
		if pkgjsonFn == "" {
			log.WithField("pkg", n).Warn("no package.json found - skipping")
			continue
		}
		pkgJSONIdx[n] = pkgjsonFn

		fc, err := os.ReadFile(pkgjsonFn)
		if err != nil {
			return err
		}
		var pkgjson struct {
			Name string `json:"name"`
		}
		err = json.Unmarshal(fc, &pkgjson)
		if err != nil {
			return err
		}
		pkgIdx[n] = pkgjson.Name
	}

	for n, p := range workspace.Packages {
		if p.Type != leeway.YarnPackage {
			continue
		}
		pkgjsonFn := pkgJSONIdx[n]

		fc, err := os.ReadFile(pkgjsonFn)
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
