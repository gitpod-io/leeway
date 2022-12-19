package cmd

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"text/template"
	"time"

	"github.com/creack/pty"
	"github.com/gookit/color"
	"github.com/segmentio/textio"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/gitpod-io/leeway/pkg/leeway"
)

// execCmd represents the version command
var execCmd = &cobra.Command{
	Use:   "exec <cmd>",
	Short: "Executes a command in the workspace directories, sorted by package dependencies",
	Long: `Executes a command in the workspace directories, sorted by package dependencies.
This command can all packages in a workspace, or a single package as starting point, and can traverse
and filter its dependency tree. For each matching package leeway will execute the specified command in
the package component's origin. Prior to executing the command it is interpreted as Go template with
the following struct as parameters:

type TemplateParameter struct {
	Component *leeway.Component
	Package   *leeway.Package
	Dir       string
	Name      string
}

To avoid executing the command in the same directory multiple times (e.g. when a component has multiple
matching packages), use --components which selects the components isntead of the packages.

Example use:
  # list all component directories of all yarn packages:
  leeway exec --filter-type yarn -- pwd

  # run go get in all Go packages
  leeway exec --filter-type go -- go get -v ./...

  # execute go build in all direct Go dependencies when any of the relevant source files changes:
  leeway exec --package some/other:package --dependencies --filter-type go --parallel --watch -- go build

  # run tsc watch for all dependent yarn packages (once per component origin):
  leeway exec --package some/other:package --transitive-dependencies --filter-type yarn --parallel -- tsc -w --preserveWatchOutput

  # print all Go packages in the workspace
  leeway exec  --filter-type go --plain -- echo "{{.Package.FullName}}"
`,
	Args: cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		ws, err := getWorkspace()
		if err != nil {
			log.WithError(err).Fatal("cannot load workspace")
		}

		var pkgs map[*leeway.Package]struct{}
		if len(execOpts.Package) == 0 {
			pkgs = make(map[*leeway.Package]struct{}, len(ws.Packages))
			for _, p := range ws.Packages {
				pkgs[p] = struct{}{}
			}
		} else {
			pkgs = make(map[*leeway.Package]struct{}, len(execOpts.Package))
			for _, pn := range execOpts.Package {
				pn := absPackageName(ws, pn)
				p, ok := ws.Packages[pn]
				if !ok {
					log.WithField("package", pn).Fatal("package not found")
				}
				pkgs[p] = struct{}{}
			}
		}

		if execOpts.TransitiveDependencies {
			for p := range pkgs {
				for _, dep := range p.GetTransitiveDependencies() {
					pkgs[dep] = struct{}{}
				}
			}
		} else if execOpts.Dependencies {
			for p := range pkgs {
				for _, dep := range p.GetDependencies() {
					pkgs[dep] = struct{}{}
				}
			}
		}

		if execOpts.TransitiveDependants {
			for p := range pkgs {
				for _, dep := range p.TransitiveDependants() {
					pkgs[dep] = struct{}{}
				}
			}
		} else if execOpts.Dependants {
			for p := range pkgs {
				for _, dep := range p.Dependants() {
					pkgs[dep] = struct{}{}
				}
			}
		}

		if len(execOpts.FilterType) > 0 {
			for pkg := range pkgs {
				var found bool
				for _, t := range execOpts.FilterType {
					if string(pkg.Type) == t {
						found = true
						break
					}
				}
				if found {
					continue
				}

				delete(pkgs, pkg)
			}
		}

		spkgs := make([]*leeway.Package, 0, len(pkgs))
		for p := range pkgs {
			spkgs = append(spkgs, p)
		}
		leeway.TopologicalSort(spkgs)

		locs := make([]commandExecLocation, 0, len(spkgs))
		if execOpts.Components {
			idx := make(map[string]struct{})
			for _, p := range spkgs {
				fn := p.C.Origin
				if _, ok := idx[fn]; ok {
					continue
				}
				idx[fn] = struct{}{}
				locs = append(locs, commandExecLocation{
					Component: p.C,
					Dir:       fn,
					Name:      p.C.Name,
				})
			}
		} else {
			for _, p := range spkgs {
				locs = append(locs, commandExecLocation{
					Component: p.C,
					Dir:       p.C.Origin,
					Package:   p,
					Name:      p.FullName(),
				})
			}
		}

		if execOpts.Watch {
			err := executeCommandInLocations(args, locs)
			if err != nil {
				log.Error(err)
			}

			evt, errs := leeway.WatchSources(context.Background(), spkgs, 2*time.Second)
			for {
				select {
				case <-evt:
					err := executeCommandInLocations(args, locs)
					if err != nil {
						log.Error(err)
					}
				case err = <-errs:
					log.Fatal(err)
				}
			}
		}
		err = executeCommandInLocations(args, locs)
		if err != nil {
			log.WithError(err).Fatal("cannot execut command")
		}
	},
}

// commandExecLocation is used to execute a command in a particular location.
// Note: This struct also serves as input for the command template.
type commandExecLocation struct {
	Component *leeway.Component
	Package   *leeway.Package
	Dir       string
	Name      string
}

func executeCommandInLocations(tplCmd []string, locs []commandExecLocation) error {
	var wg sync.WaitGroup
	for _, loc := range locs {
		execCmd := make([]string, 0, len(tplCmd))
		if execOpts.DontTemplate {
			execCmd = tplCmd
		} else {
			tpl := template.New("command")
			for _, c := range tplCmd {
				cmdTplSeg, err := tpl.Parse(c)
				if err != nil {
					return fmt.Errorf("cannot parse command template \"%s\" in %v: %w", c, tplCmd, err)
				}
				buf := bytes.NewBuffer(nil)
				err = cmdTplSeg.Execute(buf, loc)
				if err != nil {
					return fmt.Errorf("cannot execute command template \"%s\" in %v: %w", c, tplCmd, err)
				}
				execCmd = append(execCmd, buf.String())
			}
		}

		if loc.Package != nil {
			log.WithField("dir", loc.Dir).WithField("pkg", loc.Package.FullName()).Debugf("running %q", execCmd)
		} else {
			log.WithField("dir", loc.Dir).Debugf("running %q", execCmd)
		}

		cmd := exec.Command(execCmd[0], execCmd[1:]...)
		cmd.Dir = loc.Dir

		if execOpts.Plain {
			cmd.Stdout = os.Stdout
			cmd.Stdin = os.Stdin
			cmd.Stderr = os.Stderr
			err := cmd.Start()
			if err != nil {
				return fmt.Errorf("execution failed in %s (%s): %w", loc.Name, loc.Dir, err)
			}
		} else {
			prefix := color.Gray.Render(fmt.Sprintf("[%s] ", loc.Name))

			ptmx, err := pty.Start(cmd)
			if err != nil {
				return fmt.Errorf("execution failed in %s (%s): %w", loc.Name, loc.Dir, err)
			}
			_ = pty.InheritSize(ptmx, os.Stdin)
			defer ptmx.Close()

			//nolint:errcheck
			go io.Copy(textio.NewPrefixWriter(os.Stdout, prefix), ptmx)
			//nolint:errcheck
			go io.Copy(ptmx, os.Stdin)
		}

		if execOpts.Parallel {
			wg.Add(1)
			go func() {
				defer wg.Done()

				err := cmd.Wait()
				if err != nil {
					log.Errorf("execution failed in %s (%s): %v", loc.Name, loc.Dir, err)
				}
			}()
		} else {
			err := cmd.Wait()
			if err != nil {
				return fmt.Errorf("execution failed in %s (%s): %v", loc.Name, loc.Dir, err)
			}
		}
	}
	if execOpts.Parallel {
		wg.Wait()
	}

	return nil
}

var execOpts struct {
	Package                []string
	Dependencies           bool
	TransitiveDependencies bool
	Dependants             bool
	TransitiveDependants   bool
	Components             bool
	FilterType             []string
	Watch                  bool
	Parallel               bool
	Plain                  bool
	DontTemplate           bool
}

func init() {
	rootCmd.AddCommand(execCmd)

	execCmd.Flags().StringArrayVar(&execOpts.Package, "package", nil, "select a package by name")
	execCmd.Flags().BoolVar(&execOpts.Dependencies, "dependencies", false, "select package dependencies")
	execCmd.Flags().BoolVar(&execOpts.TransitiveDependencies, "transitive-dependencies", false, "select transitive package dependencies")
	execCmd.Flags().BoolVar(&execOpts.Dependants, "dependants", false, "select package dependants")
	execCmd.Flags().BoolVar(&execOpts.TransitiveDependants, "transitive-dependants", false, "select transitive package dependants")
	execCmd.Flags().BoolVar(&execOpts.Components, "components", false, "select the package's components (e.g. instead of selecting three packages from the same component, execute just once in the component origin)")
	execCmd.Flags().StringArrayVar(&execOpts.FilterType, "filter-type", nil, "only select packages of this type")
	execCmd.Flags().BoolVar(&execOpts.Watch, "watch", false, "Watch source files and re-execute on change")
	execCmd.Flags().BoolVar(&execOpts.Parallel, "parallel", false, "Start all executions in parallel independent of their order")
	execCmd.Flags().BoolVar(&execOpts.Plain, "plain", false, "Produce plain output with out a prefix. Useful for generating scripts")
	execCmd.Flags().BoolVar(&execOpts.DontTemplate, "dont-template", false, "Don't treat the command as a Go template but use it in verbatim")
	execCmd.Flags().SetInterspersed(true)
}
