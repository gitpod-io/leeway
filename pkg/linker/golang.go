package linker

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	log "github.com/sirupsen/logrus"
	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
	"golang.org/x/xerrors"

	"github.com/gitpod-io/leeway/pkg/leeway"
)

// LinkGoWorkspace updates a go.work file to include all Go components.
// Returns an error if `go.work` does not exist yet.
func LinkGoWorkspace(workspace *leeway.Workspace) error {
	workFN := filepath.Join(workspace.Origin, "go.work")
	if _, err := os.Stat(workFN); err != nil {
		return fmt.Errorf("not a Go workspace: %v", err)
	}

	// update workspace file
	fc, err := os.ReadFile(workFN)
	if err != nil {
		return err
	}
	workFile, err := modfile.ParseWork(workFN, fc, nil)
	if err != nil {
		return err
	}

	for _, use := range workFile.Use {
		if ok, _ := isLeewayReplace(use.Syntax); ok {
			err = workFile.DropUse(use.Path)
			if err != nil {
				return err
			}
		}
	}
	goModules := make(map[string]struct{}, len(workspace.Components))
	for _, pkg := range workspace.Packages {
		if pkg.Type != leeway.GoPackage {
			continue
		}
		fn := strings.TrimPrefix(strings.TrimPrefix(pkg.C.Origin, workspace.Origin), "/")
		goModules[fn] = struct{}{}
	}
	sortedPaths := make([]string, 0, len(workspace.Components))
	for p := range goModules {
		sortedPaths = append(sortedPaths, p)
	}
	sort.Strings(sortedPaths)
	for _, pth := range sortedPaths {
		workFile.AddNewUse(pth, "")
	}
	for _, use := range workFile.Use {
		if _, ok := goModules[use.Path]; !ok {
			continue
		}
		if use.Syntax == nil {
			continue
		}
		use.Syntax.InBlock = true
		use.Syntax.Comments.Suffix = []modfile.Comment{{Token: "// leeway", Suffix: true}}
	}
	workFile.SortBlocks()
	workFile.Cleanup()

	fc = modfile.Format(workFile.Syntax)
	err = os.WriteFile(workFN, fc, 0644)
	if err != nil {
		return err
	}

	// drop leeway replace from all go.mod files
	for _, p := range workspace.Packages {
		if p.Type != leeway.GoPackage {
			continue
		}

		err := removeLeewayReplaceRules(p)
		if err != nil {
			return err
		}
	}

	return nil
}

// LinkGoModules produces the neccesary "replace"ments in all of the package's
// go.mod files, s.t. the packages link in the workspace/work with Go's tooling in-situ.
func LinkGoModules(workspace *leeway.Workspace, target *leeway.Package) error {
	mods, err := collectReplacements(workspace)
	if err != nil {
		return err
	}

	for _, p := range workspace.Packages {
		if p.Type != leeway.GoPackage {
			continue
		}
		if target != nil && p.FullName() != target.FullName() {
			continue
		}

		var apmods []goModule
		for _, dep := range p.GetTransitiveDependencies() {
			if dep.Type != leeway.GoPackage {
				continue
			}

			mod, ok := mods[dep.FullName()]
			if !ok {
				log.WithField("dep", dep.FullName()).Warn("did not find go.mod for this package - linking will probably be broken")
				continue
			}

			apmods = append(apmods, mod)
		}

		sort.Slice(apmods, func(i, j int) bool {
			return apmods[i].Name < apmods[j].Name
		})

		err = linkGoModule(p, apmods)
		if err != nil {
			return err
		}
	}

	return nil
}

func modifyGoMod(dst *leeway.Package, mod func(goModFN string, gomod *modfile.File) error) error {
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
	fc, err := os.ReadFile(goModFn)
	if err != nil {
		return err
	}
	gomod, err := modfile.Parse(goModFn, fc, nil)
	if err != nil {
		return err
	}

	err = mod(goModFn, gomod)
	if err != nil {
		return err
	}
	gomod.Cleanup()

	fc, err = gomod.Format()
	if err != nil {
		return err
	}

	err = os.WriteFile(goModFn, fc, 0644)
	if err != nil {
		return err
	}

	return nil
}

func linkGoModule(dst *leeway.Package, mods []goModule) error {
	err := removeLeewayReplaceRules(dst)
	if err != nil {
		return err
	}

	return modifyGoMod(dst, func(goModFN string, gomod *modfile.File) error {
		for _, mod := range mods {
			relpath, err := filepath.Rel(filepath.Dir(goModFN), mod.OriginPath)
			if err != nil {
				return err
			}

			err = addReplace(gomod, module.Version{Path: mod.Name}, module.Version{Path: relpath}, true, mod.OriginPackage)
			if err != nil {
				return err
			}
			log.WithField("dst", dst.FullName()).WithField("dep", mod.Name).Debug("linked Go modules")
		}
		for _, mod := range mods {
			for _, r := range mod.Replacements {
				err = addReplace(gomod, r.Old, r.New, false, mod.OriginPackage)
				if err != nil {
					return err
				}
			}
		}

		return nil
	})
}

func removeLeewayReplaceRules(dst *leeway.Package) error {
	return modifyGoMod(dst, func(_ string, gomod *modfile.File) error {
		for _, rep := range gomod.Replace {
			if ok, tpe := isLeewayReplace(rep.Syntax); !ok || tpe == leewayReplaceIgnore {
				continue
			}

			log.WithField("replace", rep).Debug("dropping replace")
			err := gomod.DropReplace(rep.Old.Path, rep.Old.Version)
			if err != nil {
				return err
			}
		}
		return nil
	})
}

func addReplace(gomod *modfile.File, old, new module.Version, direct bool, source string) error {
	for _, rep := range gomod.Replace {
		if rep.Old.Path != old.Path || rep.Old.Version != old.Version {
			continue
		}
		if ok, tpe := isLeewayReplace(rep.Syntax); ok && tpe != leewayReplaceIgnore {
			err := gomod.DropReplace(old.Path, old.Version)
			if err != nil {
				return err
			}

			continue
		}

		// replacement already exists - cannot replace
		return xerrors.Errorf("replacement for %s exists already, but was not added by leeway", old.String())
	}

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
			rep.Syntax.InBlock = true
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

		fc, err := os.ReadFile(goModFn)
		if err != nil {
			return nil, err
		}

		gomod, err := modfile.Parse(goModFn, fc, nil)
		if err != nil {
			return nil, err
		}

		var replace []*modfile.Replace
		for _, rep := range gomod.Replace {
			skip, _ := isLeewayReplace(rep.Syntax)
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

type leewayReplaceType int

const (
	leewayReplaceDirect leewayReplaceType = iota
	leewayReplaceIndirect
	leewayReplaceIgnore
)

func isLeewayReplace(rep *modfile.Line) (ok bool, tpe leewayReplaceType) {
	if rep == nil {
		return false, leewayReplaceIgnore
	}
	for _, c := range rep.Suffix {
		if strings.Contains(c.Token, "leeway") {
			ok = true

			if strings.Contains(c.Token, " indirect ") {
				tpe = leewayReplaceIndirect
			} else if strings.Contains(c.Token, " ignore ") {
				tpe = leewayReplaceIgnore
			} else {
				tpe = leewayReplaceDirect
			}

			return
		}
	}

	return false, leewayReplaceDirect
}
