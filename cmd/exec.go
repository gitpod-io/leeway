package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"

	"github.com/creack/pty"
	"github.com/gookit/color"
	"github.com/segmentio/textio"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/typefox/leeway/pkg/leeway"
)

// execCmd represents the version command
var execCmd = &cobra.Command{
	Use:   "exec <package> cmd",
	Short: "Executes a command in all matching packages in sorted by their dependencies.",
	Long: `Executes a command in all matching packages in sorted by their dependencies.
This command requires a single package as starting point, and can traverse and filter its dependency tree.
For each matching package leeway will execute the specified command in the package component's origin.
To avoid executing the command in the same directory multiple times (e.g. when a component has multiple
matching packages), use --components which selects the components isntead of the packages.

Example use:
  # list all component directories of all transitive dependencies which are typescript packages:
  leeway exec some/other:package --transitive-dependencies --filter-type typescript -- pwd
  
  # execute go build in all direct Go dependencies when any of the relevant source files changes:
  leeway exec some/other:package --dependencies --filter-type go --parallel --watch -- go build
  
  # run go get in all transitively dependend Go packages
  leeway exec some/other:package --transitive-dependencies --filter-type go -- go get -v ./...
  
  # run tsc watch for all dependent typescript packages (once per component origin):
  leeway exec some/other:package --transitive-dependencies --filter-type typescript --parallel -- tsc -w --preserveWatchOutput
`,
	Args: cobra.MinimumNArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		var (
			includeDeps, _      = cmd.Flags().GetBool("dependencies")
			includeTransDeps, _ = cmd.Flags().GetBool("transitive-dependencies")
			components, _       = cmd.Flags().GetBool("components")
			filterType, _       = cmd.Flags().GetStringArray("filter-type")
			watch, _            = cmd.Flags().GetBool("watch")
			parallel, _         = cmd.Flags().GetBool("parallel")
		)
		_, pkg, _, _ := getTarget(args, false)
		if pkg == nil {
			log.Fatal("build needs a package")
		}

		type loc struct {
			Component *leeway.Component
			Package   *leeway.Package
			Dir       string
			Name      string
		}
		selectDirectories := func() ([]loc, []*leeway.Package) {
			pkgs := []*leeway.Package{pkg}
			if includeTransDeps {
				pkgs = append(pkgs, pkg.GetTransitiveDependencies()...)
			} else if includeDeps {
				pkgs = append(pkgs, pkg.GetDependencies()...)
			}

			if len(filterType) > 0 {
				ores := pkgs
				pkgs = make([]*leeway.Package, 0)
				for _, pkg := range ores {
					var found bool
					for _, t := range filterType {
						if string(pkg.Type) == t {
							found = true
							break
						}
					}
					if !found {
						continue
					}

					pkgs = append(pkgs, pkg)
				}
			}
			leeway.TopologicalSort(pkgs)

			res := make([]loc, 0, len(pkgs))
			if components {
				idx := make(map[string]struct{})
				for _, p := range pkgs {
					fn := p.C.Origin
					if _, ok := idx[fn]; ok {
						continue
					}
					idx[fn] = struct{}{}
					res = append(res, loc{
						Component: p.C,
						Dir:       fn,
						Name:      p.C.Name,
					})
				}
			} else {
				for _, p := range pkgs {
					res = append(res, loc{
						Component: p.C,
						Dir:       p.C.Origin,
						Package:   p,
						Name:      p.FullName(),
					})
				}
			}

			return res, pkgs
		}

		var wg sync.WaitGroup
		execute := func(locs []loc) error {
			execCmd := args[1:]
			for _, loc := range locs {
				if loc.Package != nil {
					log.WithField("dir", loc.Dir).WithField("pkg", loc.Package.FullName()).Infof("running %q", execCmd)
				} else {
					log.WithField("dir", loc.Dir).Infof("running %q", execCmd)
				}
				prefix := color.Gray.Render(fmt.Sprintf("[%s] ", loc.Name))

				cmd := exec.Command(execCmd[0], execCmd[1:]...)
				cmd.Dir = loc.Dir
				ptmx, err := pty.Start(cmd)
				if err != nil {
					return fmt.Errorf("execution failed in %s (%s): %w", loc.Name, loc.Dir, err)
				}
				pty.InheritSize(ptmx, os.Stdin)
				defer ptmx.Close()

				go io.Copy(textio.NewPrefixWriter(os.Stdout, prefix), ptmx)
				go io.Copy(ptmx, os.Stdin)
				if parallel {
					wg.Add(1)
					go func() {
						defer wg.Done()

						err = cmd.Wait()
						if err != nil {
							log.Errorf("execution failed in %s (%s): %v", loc.Name, loc.Dir, err)
						}
					}()
				} else {
					err = cmd.Wait()
					if err != nil {
						return fmt.Errorf("execution failed in %s (%s): %v", loc.Name, loc.Dir, err)
					}
				}
			}
			if parallel {
				wg.Wait()
			}

			return nil
		}

		if watch {
			locs, pkgs := selectDirectories()
			err := execute(locs)
			if err != nil {
				log.Error(err)
			}

			evt, errs := leeway.WatchSources(context.Background(), pkgs)
			for {
				select {
				case <-evt:
					err := execute(locs)
					if err != nil {
						log.Error(err)
					}
				case err = <-errs:
					log.Fatal(err)
				}
			}
		}

		locs, _ := selectDirectories()
		execute(locs)
	},
}

type readWriter struct {
	io.Reader
	io.Writer
}

func init() {
	rootCmd.AddCommand(execCmd)

	execCmd.Flags().Bool("dependencies", false, "select package dependencies")
	execCmd.Flags().Bool("transitive-dependencies", false, "select transitive package dependencies")
	execCmd.Flags().Bool("components", false, "select the package's components (e.g. instead of selecting three packages from the same component, execute just once in the component origin)")
	execCmd.Flags().StringArray("filter-type", nil, "only select packages of this type")
	execCmd.Flags().Bool("watch", false, "Watch source files and re-execute on change")
	execCmd.Flags().Bool("parallel", false, "Start all executions in parallel independent of their order")
	execCmd.Flags().SetInterspersed(true)
}
