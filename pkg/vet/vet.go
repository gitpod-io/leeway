package vet

import (
	"encoding/json"
	"fmt"
	"sort"

	log "github.com/sirupsen/logrus"
	"github.com/typefox/leeway/pkg/leeway"
	"golang.org/x/xerrors"
)

// Check implements a vet check
type Check struct {
	Name          string
	Description   string
	AppliesToType *leeway.PackageType

	RunPkg func(pkg *leeway.Package) ([]Finding, error)
	RunCmp func(pkg *leeway.Component) ([]Finding, error)
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
	if _, exists := _checks[c.Name]; exists {
		panic(fmt.Sprintf("check %s is already registered", c.Name))
	}
	_checks[c.Name] = c
}

// Checks returns a list of all available checks
func Checks() []Check {
	l := make([]Check, 0, len(_checks))
	for _, c := range _checks {
		l = append(l, c)
	}
	sort.Slice(l, func(i, j int) bool { return l[i].Name < l[j].Name })
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

	var (
		findings []Finding
		errs     []error

		runCompCheck = func(c Check, comp *leeway.Component) {
			if c.RunCmp == nil {
				return
			}

			log.WithField("check", c.Name).WithField("cmp", comp.Name).Debug("running component check")
			f, err := c.RunCmp(comp)
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", comp.Name, err))
				return
			}
			for i := range f {
				f[i].Check = c.Name
			}
			findings = append(findings, f...)
		}
		runPkgCheck = func(c Check, pkg *leeway.Package) {
			if c.RunPkg == nil {
				return
			}
			if c.AppliesToType != nil && *c.AppliesToType != pkg.Type {
				return
			}

			log.WithField("check", c.Name).WithField("pkg", pkg.FullName()).Debug("running package check")
			f, err := c.RunPkg(pkg)
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", pkg.FullName(), err))
				return
			}
			for i := range f {
				f[i].Check = c.Name
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
