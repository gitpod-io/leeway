package leeway

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"
	"golang.org/x/xerrors"
)

// WorkdirLayout describes the layout of the working dir a script gets executed in
type WorkdirLayout string

const (
	// WorkdirOrigin means the script is executed in the original location of the component where it's defined,
	// in the original workspace.
	WorkdirOrigin WorkdirLayout = "origin"

	// WorkdirPackages replicates the structure leeway produces during a package build based on the script's dependencies.
	WorkdirPackages WorkdirLayout = "packages"
)

// ScriptType defines the type a script is of
type ScriptType string

const (
	// BashScript means the script is executed by bash.
	// The shebang is added automatically.
	BashScript ScriptType = "bash"
)

// Script is an executable, uncacheable unit that does not result in build artefacts
type Script struct {
	C *Component

	Name          string        `yaml:"name"`
	Description   string        `yaml:"description"`
	Dependencies  []string      `yaml:"deps"`
	Environment   []string      `yaml:"env"`
	WorkdirLayout WorkdirLayout `yaml:"workdir"`
	Type          ScriptType    `yaml:"type"`
	Script        string        `yaml:"script"`

	dependencies []*Package
}

// FullName returns the packages fully qualified name (component:package)
func (p *Script) FullName() string {
	return fmt.Sprintf("%s:%s", p.C.Name, p.Name)
}

// link connects resolves the references to the dependencies
func (p *Script) link(idx map[string]*Package) error {
	p.dependencies = make([]*Package, len(p.Dependencies))
	for i, dep := range p.Dependencies {
		var ok bool
		p.dependencies[i], ok = idx[dep]
		if !ok {
			return PackageNotFoundErr{dep}
		}
	}
	return nil
}

// GetDependencies returns the linked package dependencies or nil if not linked yet
func (p *Script) GetDependencies() []*Package {
	return p.dependencies
}

// FilesystemSafeName returns a string that is safe to use in a Unix filesystem as directory or filename
func (p *Script) FilesystemSafeName() string {
	pkgdir := p.FullName()
	pkgdir = strings.Replace(pkgdir, "/", "-", -1)
	pkgdir = strings.Replace(pkgdir, ":", "--", -1)
	// components in the workspace root would otherwise start with - which breaks a lot of shell commands
	pkgdir = strings.TrimLeft(pkgdir, "-")
	return pkgdir
}

// Run executes the script
func (p *Script) Run(opts ...BuildOption) error {
	options, err := applyBuildOpts(opts)
	if err != nil {
		return err
	}
	buildCtx, err := newBuildContext(options)

	if len(p.dependencies) > 0 {
		err = Build(&Package{
			C:            p.C,
			dependencies: p.dependencies,
			packageInternal: packageInternal{
				Name:        fmt.Sprintf("%s-dpes", p.Name),
				Environment: p.Environment,
				Ephemeral:   true,
				Type:        GenericPackage,
			},
			Config: GenericPkgConfig{},
		}, withBuildContext(buildCtx))
		if err != nil {
			return err
		}
	}

	tdir, deplocs, err := p.synthesizePackagesWorkdir(buildCtx)
	if err != nil {
		return err
	}

	paths := make([]string, 0, len(deplocs))
	for _, pth := range deplocs {
		paths = append(paths, pth)
	}

	var wd string
	switch p.WorkdirLayout {
	case WorkdirPackages:
		wd = tdir
	case WorkdirOrigin:
		fallthrough
	default:
		wd = p.C.Origin
	}

	var (
		env = append(os.Environ(), p.Environment...)
		pa  bool
	)
	for i, e := range env {
		if !strings.HasPrefix(e, "PATH=") {
			continue
		}
		pa = true

		if strings.TrimPrefix(e, "PATH=") != "" {
			e += ":"
		}
		e += strings.Join(paths, ":")
		env[i] = e
	}
	if !pa {
		env = append(env, fmt.Sprintf("PATH=%s", strings.Join(paths, ":")))
	}
	for n, pth := range deplocs {
		env = append(env, fmt.Sprintf("%s=%s", strings.ToUpper(n), pth))
	}

	// execute script
	switch p.Type {
	case BashScript:
		err = executeBashScript(p.Script, wd, env)
	default:
		return xerrors.Errorf("unknown script type: %s", p.Type)
	}

	return nil
}

func (p *Script) synthesizePackagesWorkdir(buildCtx *buildContext) (path string, bins map[string]string, err error) {
	path, err = ioutil.TempDir(buildCtx.buildDir, fmt.Sprintf("script-%s-*", p.FilesystemSafeName()))
	if err != nil {
		return
	}

	bins = make(map[string]string, len(p.dependencies))
	for _, dep := range p.dependencies {
		br, exists := buildCtx.LocalCache.Location(dep)
		if !exists {
			err = xerrors.Errorf("dependency %s is not built", dep.FullName())
			return
		}

		loc := filepath.Join(path, dep.FilesystemSafeName())
		err = os.MkdirAll(loc, 0755)
		if err != nil {
			return
		}

		var out []byte
		cmd := exec.Command("tar", "xzf", br)
		cmd.Dir = loc
		out, err = cmd.CombinedOutput()
		if err != nil {
			err = xerrors.Errorf("cannot unarchive build result for %s: %s", dep.FullName(), string(out))
			return
		}

		bins[dep.FilesystemSafeName()] = loc
	}

	return
}

func executeBashScript(script string, wd string, env []string) error {
	f, err := ioutil.TempFile("", "*.sh")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())

	_, err = f.WriteString("#!/bin/bash\n")
	if err != nil {
		return err
	}
	f.WriteString(script)
	if err != nil {
		return err
	}
	f.Close()

	log.WithField("env", env).Debug("running bash script")

	cmd := exec.Command("bash", f.Name())
	cmd.Env = env
	cmd.Dir = wd
	cmd.Stdin = os.Stdin
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	return cmd.Run()
}
