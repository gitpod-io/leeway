package vet

import (
	"encoding/json"
	"fmt"
	"sort"

	log "github.com/sirupsen/logrus"
	"golang.org/x/xerrors"

	"github.com/gitpod-io/leeway/pkg/leeway"
)

type checkFunc struct {
	info CheckInfo

	runPkg func(pkg *leeway.Package) ([]Finding, error)
	runCmp func(pkg *leeway.Component) ([]Finding, error)
}

func (cf *checkFunc) Info() CheckInfo {
	return cf.info
}

func (cf *checkFunc) Init(leeway.Workspace) error {
	return nil
}

func (cf *checkFunc) RunPkg(pkg *leeway.Package) ([]Finding, error) {
	if cf.runPkg == nil {
		return nil, xerrors.Errorf("not a package check")
	}
	return cf.runPkg(pkg)
}

func (cf *checkFunc) RunCmp(pkg *leeway.Component) ([]Finding, error) {
	if cf.runCmp == nil {
		return nil, xerrors.Errorf("has no component check")
	}
	return cf.runCmp(pkg)
}

// PackageCheck produces a new check for a leeway package
func PackageCheck(name, desc string, tpe leeway.PackageType, chk func(pkg *leeway.Package) ([]Finding, error)) Check {
	return &checkFunc{
		info: CheckInfo{
			Name:          fmt.Sprintf("%s:%s", tpe, name),
			Description:   desc,
			AppliesToType: &tpe,
			PackageCheck:  true,
		},
		runPkg: chk,
	}
}

// ComponentCheck produces a new check for a leeway component
func ComponentCheck(name, desc string, chk func(pkg *leeway.Component) ([]Finding, error)) Check {
	return &checkFunc{
		info: CheckInfo{
			Name:         fmt.Sprintf("component:%s", name),
			Description:  desc,
			PackageCheck: false,
		},
		runCmp: chk,
	}
}

// Check implements a vet check
type Check interface {
	Info() CheckInfo

	Init(ws leeway.Workspace) error
	RunPkg(pkg *leeway.Package) ([]Finding, error)
	RunCmp(pkg *leeway.Component) ([]Finding, error)
}

// CheckInfo describes a check
type CheckInfo struct {
	Name          string
	Description   string
	PackageCheck  bool
	AppliesToType *leeway.PackageType
}

// Finding describes a check finding. If the package is nil, the finding applies to the component
type Finding struct {
	Check       string
	Component   *leeway.Component
	Package     *leeway.Package
	Description string
	Error       bool
}

// MarshalJSON marshals a finding to JSON
func (f Finding) MarshalJSON() ([]byte, error) {
	var p struct {
		Check       string `json:"check"`
		Component   string `json:"component"`
		Package     string `json:"package,omitempty"`
		Description string `json:"description,omitempty"`
		Error       bool   `json:"error"`
	}
	p.Check = f.Check
	p.Component = f.Component.Name
	if f.Package != nil {
		p.Package = f.Package.FullName()
	}
	p.Description = f.Description
	p.Error = f.Error

	return json.Marshal(p)
}

var _checks = make(map[string]Check)

func register(c Check) {
	cn := c.Info().Name
	if _, exists := _checks[cn]; exists {
		panic(fmt.Sprintf("check %s is already registered", cn))
	}
	_checks[cn] = c
}

// Checks returns a list of all available checks
func Checks() []Check {
	l := make([]Check, 0, len(_checks))
	for _, c := range _checks {
		l = append(l, c)
	}
	sort.Slice(l, func(i, j int) bool { return l[i].Info().Name < l[j].Info().Name })
	return l
}

// RunOpt modifies the run behaviour
type RunOpt func(*runOptions)

type runOptions struct {
	Packages   StringSet
	Components StringSet
	Checks     []string
}

// StringSet identifies a string as part of a set
type StringSet map[string]struct{}

// OnPackages makes run check these packages only
func OnPackages(n StringSet) RunOpt {
	return func(r *runOptions) {
		r.Packages = n
	}
}

// OnComponents makes run check these components only
func OnComponents(n StringSet) RunOpt {
	return func(r *runOptions) {
		r.Components = n
	}
}

// WithChecks runs these checks only
func WithChecks(n []string) RunOpt {
	return func(r *runOptions) {
		r.Checks = n
	}
}

// Run runs all checks on all packages
func Run(workspace leeway.Workspace, options ...RunOpt) ([]Finding, []error) {
	var opts runOptions
	for _, o := range options {
		o(&opts)
	}

	var checks []Check
	if len(opts.Checks) == 0 {
		checks = make([]Check, 0, len(_checks))
		for _, c := range _checks {
			checks = append(checks, c)
		}
	} else {
		log.WithField("checks", opts.Checks).Debug("running selected checks only")
		for _, cn := range opts.Checks {
			c, ok := _checks[cn]
			if !ok {
				return nil, []error{xerrors.Errorf("check %s not found", cn)}
			}
			checks = append(checks, c)
		}
	}
	for _, check := range checks {
		err := check.Init(workspace)
		if err != nil {
			return nil, []error{fmt.Errorf("init %s: %w", check.Info().Name, err)}
		}
	}

	var (
		findings []Finding
		errs     []error

		runCompCheck = func(c Check, comp *leeway.Component) {
			info := c.Info()
			if info.PackageCheck {
				return
			}

			log.WithField("check", info.Name).WithField("cmp", comp.Name).Debug("running component check")
			f, err := c.RunCmp(comp)
			if err != nil {
				errs = append(errs, fmt.Errorf("[%s] %s: %w", info.Name, comp.Name, err))
				return
			}
			for i := range f {
				f[i].Check = info.Name
			}
			findings = append(findings, f...)
		}
		runPkgCheck = func(c Check, pkg *leeway.Package) {
			info := c.Info()
			if !info.PackageCheck {
				return
			}

			if info.AppliesToType != nil && *info.AppliesToType != pkg.Type {
				return
			}

			log.WithField("check", info.Name).WithField("pkg", pkg.FullName()).Debug("running package check")
			f, err := c.RunPkg(pkg)
			if err != nil {
				errs = append(errs, fmt.Errorf("[%s] %s: %w", info.Name, pkg.FullName(), err))
				return
			}
			for i := range f {
				f[i].Check = info.Name
			}
			findings = append(findings, f...)
		}
	)

	if len(opts.Components) > 0 {
		for n, comp := range workspace.Components {
			if _, ok := opts.Components[n]; !ok {
				continue
			}

			for _, check := range checks {
				runCompCheck(check, comp)
			}
		}
	} else if len(opts.Packages) > 0 {
		for n, pkg := range workspace.Packages {
			if _, ok := opts.Packages[n]; !ok {
				continue
			}

			for _, check := range checks {
				runPkgCheck(check, pkg)
			}
		}
	} else {
		for _, check := range checks {
			for _, comp := range workspace.Components {
				runCompCheck(check, comp)
			}

			for _, pkg := range workspace.Packages {
				runPkgCheck(check, pkg)
			}
		}
	}

	return findings, errs
}
