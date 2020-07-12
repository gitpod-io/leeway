package linker

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/typefox/leeway/pkg/leeway"
	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
	"golang.org/x/xerrors"
)

// LinkGoModules produces the neccesary "replace"ments in all of the package's
// go.mod files, s.t. the packages link in the workspace/work with Go's tooling in-situ.
func LinkGoModules(workspace *leeway.Workspace) error {
	mods, err := collectReplacements(workspace)
	if err != nil {
		return err
	}

	for _, p := range workspace.Packages {
		if p.Type != leeway.GoPackage {
			continue
		}

		for _, dep := range p.GetTransitiveDependencies() {
			mod, ok := mods[dep.FullName()]
			if !ok {
				log.WithField("dep", dep.FullName()).Warn("did not find go.mod for this package - linking will probably be broken")
			}

			err = linkGoModule(p, mod)
			if err != nil {
				return err
			}
		}

	}

	return nil
}

func linkGoModule(dst *leeway.Package, mod goModule) error {
	var goModFn string
	for _, f := range dst.Sources {
		if strings.HasSuffix(f, "go.mod") {
			goModFn = f
			break
		}
	}
	if goModFn == "" {
		return xerrors.Errorf("%w: go.mod not found", os.ErrNotExist)
	}

	relpath, err := filepath.Rel(filepath.Dir(goModFn), mod.OriginPath)
	if err != nil {
		return err
	}

	fc, err := ioutil.ReadFile(goModFn)
	if err != nil {
		return err
	}

	gomod, err := modfile.Parse(goModFn, fc, nil)
	if err != nil {
		return err
	}

	addReplace(gomod, module.Version{Path: mod.Name}, module.Version{Path: relpath}, true, mod.OriginPackage)
	for _, r := range mod.Replacements {
		addReplace(gomod, r.Old, r.New, false, mod.OriginPackage)
	}

	gomod.Cleanup()
	fc, err = gomod.Format()
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(goModFn, fc, 0644)
	if err != nil {
		return err
	}

	log.WithField("dst", dst.FullName()).WithField("dep", mod.Name).Info("linked Go modules")
	return nil
}

func addReplace(gomod *modfile.File, old, new module.Version, direct bool, source string) error {
	err := gomod.AddReplace(old.Path, old.Version, new.Path, new.Version)
	if err != nil {
		return err
	}

	comment := "// leeway"
	if !direct {
		comment += " indirect from " + source
	}
	for _, rep := range gomod.Replace {
		if rep.Old.Path == old.Path && rep.Old.Version == old.Version {
			rep.Syntax.Comments.Suffix = []modfile.Comment{{Token: comment, Suffix: true}}
		}
	}
	return nil
}

type goModule struct {
	Name          string
	OriginPath    string
	OriginPackage string
	Replacements  []*modfile.Replace
}

func collectReplacements(workspace *leeway.Workspace) (mods map[string]goModule, err error) {
	mods = make(map[string]goModule)
	for n, p := range workspace.Packages {
		if p.Type != leeway.GoPackage {
			continue
		}

		var goModFn string
		for _, f := range p.Sources {
			if strings.HasSuffix(f, "go.mod") {
				goModFn = f
				break
			}
		}
		if goModFn == "" {
			continue
		}

		fc, err := ioutil.ReadFile(goModFn)
		if err != nil {
			return nil, err
		}

		gomod, err := modfile.Parse(goModFn, fc, nil)
		if err != nil {
			return nil, err
		}

		var replace []*modfile.Replace
		for _, rep := range gomod.Replace {
			skip, _ := isLeewayReplace(rep)
			if !skip {
				replace = append(replace, rep)
				log.WithField("rep", rep.Old.String()).WithField("pkg", n).Debug("collecting replace")
			} else {
				log.WithField("rep", rep.Old.String()).WithField("pkg", n).Debug("ignoring leeway replace")
			}
		}

		mods[n] = goModule{
			Name:          gomod.Module.Mod.Path,
			OriginPath:    filepath.Dir(goModFn),
			OriginPackage: n,
			Replacements:  replace,
		}
	}
	return mods, nil
}

func isLeewayReplace(rep *modfile.Replace) (ok, direct bool) {
	for _, c := range rep.Syntax.Suffix {
		if strings.Contains(c.Token, "leeway") {
			ok = true
			direct = !strings.Contains(c.Token, "indirect")
			return
		}
	}

	return false, false
}
