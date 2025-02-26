package leeway

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

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
	if err != nil {
		return err
	}

	unresolvedArgs, err := findUnresolvedArgumentsInScript(p)
	if err != nil {
		return err
	}
	if len(unresolvedArgs) != 0 {
		var msg string
		for _, arg := range unresolvedArgs {
			cleanArg := strings.TrimSuffix(strings.TrimPrefix(arg, "${"), "}")
			msg += fmt.Sprintf("cannot run script with unresolved argument \"%s\": use -D%s=value to set the argument\n\n", arg, cleanArg)
		}
		return xerrors.Errorf(msg)
	}

	if len(p.dependencies) > 0 {
		err = Build(&Package{
			C:            p.C,
			dependencies: p.dependencies,
			PackageInternal: PackageInternal{
				Name:        fmt.Sprintf("%s-deps", p.Name),
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

	// Create the packages workdir for PATH and dependencies
	packagesWd, err := p.synthesizePackagesWorkdir(p.dependencies, buildCtx)
	if err != nil {
		return err
	}

	// Determine the actual working directory based on WorkdirLayout
	var wd string
	if p.WorkdirLayout == WorkdirOrigin {
		// Use the original component location
		wd = p.C.Origin
	} else {
		// Use the synthesized packages workdir
		wd = packagesWd
	}

	// Build a list of paths to add to PATH
	var pathsToAdd []string
	pathsToAdd = append(pathsToAdd, packagesWd)

	// Add each dependency's directory to the PATH
	for _, dep := range p.dependencies {
		depPath := filepath.Join(packagesWd, dep.FilesystemSafeName())
		pathsToAdd = append(pathsToAdd, depPath)
	}

	// Join all paths with colon
	pathAddition := strings.Join(pathsToAdd, ":")

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
		e += pathAddition
		env[i] = e
	}
	if !pa {
		env = append(env, fmt.Sprintf("PATH=%s", pathAddition))
	}

	// execute script
	switch p.Type {
	case BashScript:
		return executeBashScript(p.Script, wd, env)
	}

	return xerrors.Errorf("unknown script type: %s", p.Type)
}

// FindUnresolvedArguments finds any still unresolved build arguments in a set of packages
func findUnresolvedArgumentsInScript(script *Script) ([]string, error) {
	args := buildArgRegexp.FindAll([]byte(script.Script), -1)
	vars := make(map[string]struct{}, len(args))
	for _, arg := range args {
		vars[string(arg)] = struct{}{}
	}

	var res []string
	for v := range vars {
		res = append(res, v)
	}
	return res, nil
}

func (p *Script) synthesizePackagesWorkdir(deps []*Package, buildctx *buildContext) (string, error) {
	wd, err := os.MkdirTemp("", "leeway-script-*")
	if err != nil {
		return "", err
	}

	for _, dep := range deps {
		br, exists := buildctx.LocalCache.Location(dep)
		if !exists {
			return "", PkgNotBuiltErr{dep}
		}

		tgt := filepath.Join(wd, dep.FilesystemSafeName())
		err = os.MkdirAll(tgt, 0755)
		if err != nil {
			return "", err
		}

		// Construct tar command arguments directly
		args := []string{}

		// Add --sparse on Linux
		if runtime.GOOS == "linux" {
			args = append(args, "--sparse")
		}

		// Extract operation
		args = append(args, "-x", "-f", br)

		// Add -z if the file is gzipped
		if strings.HasSuffix(br, ".gz") || strings.HasSuffix(br, ".tgz") {
			args = append(args, "-z")
		}

		cmd := exec.Command("tar", args...)
		cmd.Dir = tgt
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		err = cmd.Run()
		if err != nil {
			return "", err
		}
	}

	return wd, nil
}

func executeBashScript(script string, wd string, env []string) error {
	f, err := os.CreateTemp("", "*.sh")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())

	_, err = f.WriteString("#!/bin/bash\n")
	if err != nil {
		return err
	}
	_, err = f.WriteString(script)
	if err != nil {
		return err
	}
	f.Close()

	log.WithField("env", env).WithField("wd", wd).Debug("running bash script")

	cmd := exec.Command("bash", f.Name())
	cmd.Env = env
	cmd.Dir = wd
	cmd.Stdin = os.Stdin
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout

	err = cmd.Run()
	if exiterr, ok := err.(*exec.ExitError); ok {
		if status, ok := exiterr.Sys().(syscall.WaitStatus); ok {
			return xerrors.Errorf("failed with exit code %d", status.ExitStatus())
		}
	}
	return err
}
