package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/creack/pty"
	"github.com/gookit/color"
	"github.com/segmentio/textio"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"

	"github.com/gitpod-io/leeway/pkg/leeway"
)

// execCmd represents the version command
var execCmd = &cobra.Command{
	Use:   "exec <cmd>",
	Short: "Executes a command in the workspace directories, sorted by package dependencies",
	Long: `Executes a command in the workspace directories, sorted by package dependencies.
This command can use a single package as starting point, and can traverse and filter its dependency tree.
For each matching package leeway will execute the specified command in the package component's origin.
To avoid executing the command in the same directory multiple times (e.g. when a component has multiple
matching packages), use --components which selects the components isntead of the packages.

Example use:
  # list all component directories of all yarn packages:
  leeway exec --filter-type yarn -- pwd

  # run go get in all Go packages
  leeway exec --filter-type go -- go get -v ./...

  # list all Go packages in the workspace
  leeway exec --filter-type go --raw-output -- echo {}

  # execute go build in all direct Go dependencies when any of the relevant source files changes:
  leeway exec --package some/other:package --dependencies --filter-type go --parallel --watch -- go build

  # run tsc watch for all dependent yarn packages (once per component origin):
  leeway exec --package some/other:package --transitive-dependencies --filter-type yarn --parallel -- tsc -w --preserveWatchOutput
`,
	Args: cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		var (
			packages, _               = cmd.Flags().GetStringArray("package")
			includeDeps, _            = cmd.Flags().GetBool("dependencies")
			includeTransDeps, _       = cmd.Flags().GetBool("transitive-dependencies")
			includeDependants, _      = cmd.Flags().GetBool("dependants")
			includeTransDependants, _ = cmd.Flags().GetBool("transitive-dependants")
			components, _             = cmd.Flags().GetBool("components")
			filterType, _             = cmd.Flags().GetStringArray("filter-type")
			filterName, _             = cmd.Flags().GetString("filter-name")
			watch, _                  = cmd.Flags().GetBool("watch")
			parallel, _               = cmd.Flags().GetBool("parallel")
			rawOutput, _              = cmd.Flags().GetBool("raw-output")
			cacheKey, _               = cmd.Flags().GetString("cache-key")
			maxConcurrentTasks, _     = cmd.Flags().GetUint("max-concurrent-tasks")
		)

		ws, err := getWorkspace()
		if err != nil {
			log.WithError(err).Fatal("cannot load workspace")
		}

		var pkgs map[*leeway.Package]struct{}
		if len(packages) == 0 {
			pkgs = make(map[*leeway.Package]struct{}, len(ws.Packages))
			for _, p := range ws.Packages {
				pkgs[p] = struct{}{}
			}
		} else {
			pkgs = make(map[*leeway.Package]struct{}, len(packages))
			for _, pn := range packages {
				pn := absPackageName(ws, pn)
				p, ok := ws.Packages[pn]
				if !ok {
					log.WithField("package", pn).Fatal("package not found")
				}
				pkgs[p] = struct{}{}
			}
		}

		if includeTransDeps {
			for p := range pkgs {
				for _, dep := range p.GetTransitiveDependencies() {
					pkgs[dep] = struct{}{}
				}
			}
		} else if includeDeps {
			for p := range pkgs {
				for _, dep := range p.GetDependencies() {
					pkgs[dep] = struct{}{}
				}
			}
		}

		if includeTransDependants {
			for p := range pkgs {
				for _, dep := range p.TransitiveDependants() {
					pkgs[dep] = struct{}{}
				}
			}
		} else if includeDependants {
			for p := range pkgs {
				for _, dep := range p.Dependants() {
					pkgs[dep] = struct{}{}
				}
			}
		}

		if len(filterType) > 0 {
			for pkg := range pkgs {
				var found bool
				for _, t := range filterType {
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

		if filterName != "" {
			filterExpr, err := regexp.Compile(filterName)
			if err != nil {
				log.WithError(err).Fatal("invalid filter-name expression")
			}
			for pkg := range pkgs {
				if filterExpr.MatchString(pkg.FullName()) {
					continue
				}

				log.WithField("package", pkg.FullName()).Debug("filtering out due to filter-name")
				delete(pkgs, pkg)
			}
		}

		spkgs := make([]*leeway.Package, 0, len(pkgs))
		for p := range pkgs {
			spkgs = append(spkgs, p)
		}
		leeway.TopologicalSort(spkgs)

		locs := make([]commandExecLocation, 0, len(spkgs))
		if components {
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

		var parallelism int
		if parallel {
			parallelism = int(maxConcurrentTasks)
		} else {
			parallelism = -1
			if maxConcurrentTasks > 0 {
				log.Warn("max-concurrent-tasks is ignored when not running in parallel")
			}
		}

		if watch {
			err := executeCommandInLocations(args, locs, noExecCache{}, parallelism, rawOutput)
			if err != nil {
				log.Error(err)
			}

			evt, errs := leeway.WatchSources(context.Background(), spkgs, 2*time.Second)
			for {
				select {
				case <-evt:
					err := executeCommandInLocations(args, locs, noExecCache{}, parallelism, rawOutput)
					if err != nil {
						log.Error(err)
					}
				case err = <-errs:
					log.Fatal(err)
				}
			}
		}

		var cache execCache = noExecCache{}
		if cacheKey != "" {
			localCacheLoc := os.Getenv(leeway.EnvvarCacheDir)
			if localCacheLoc == "" {
				localCacheLoc = filepath.Join(os.TempDir(), "cache")
			}
			loc := filepath.Join(localCacheLoc, cacheKey)
			log.WithField("loc", loc).Debug("using filesystem exec cache")

			cache = filesystemExecCache(loc)
		}

		err = executeCommandInLocations(args, locs, cache, parallelism, rawOutput)
		if err != nil {
			log.WithError(err).Fatal("cannot execut command")
		}
	},
}

type commandExecLocation struct {
	Component *leeway.Component
	Package   *leeway.Package
	Dir       string
	Name      string
}

func executeCommandInLocations(rawExecCmd []string, locs []commandExecLocation, cache execCache, parallelism int, rawOutput bool) error {
	var eg errgroup.Group
	if parallelism > 0 {
		eg.SetLimit(parallelism)
	}

	for _, loc := range locs {
		if ok, _ := cache.NeedsExecution(context.Background(), loc); !ok {
			continue
		}

		execCmd := make([]string, len(rawExecCmd))
		for i, c := range rawExecCmd {
			if loc.Package == nil {
				execCmd[i] = strings.ReplaceAll(c, "{}", loc.Component.Name)
			} else {
				execCmd[i] = strings.ReplaceAll(c, "{}", loc.Package.FullName())
			}
		}

		if loc.Package != nil {
			log.WithField("dir", loc.Dir).WithField("pkg", loc.Package.FullName()).Debugf("running %q", execCmd)
		} else {
			log.WithField("dir", loc.Dir).Debugf("running %q", execCmd)
		}
		prefix := color.Gray.Render(fmt.Sprintf("[%s] ", loc.Name))
		if rawOutput {
			prefix = ""
		}

		cmd := exec.Command(execCmd[0], execCmd[1:]...)
		cmd.Dir = loc.Dir
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
		if parallelism > -1 {
			loc := loc
			eg.Go(func() error {
				err := cmd.Wait()
				if err == nil {
					err = cache.MarkExecuted(context.Background(), loc)
					if err != nil {
						log.WithError(err).Warn("cannot mark package as executed")
					}
				} else {
					log.Errorf("execution failed in %s (%s): %v", loc.Name, loc.Dir, err)
				}
				return nil
			})
		} else {
			err = cmd.Wait()
			if err == nil {
				err = cache.MarkExecuted(context.Background(), loc)
				if err != nil {
					log.WithError(err).Warn("cannot mark package as executed")
				}
			} else {
				return fmt.Errorf("execution failed in %s (%s): %v", loc.Name, loc.Dir, err)
			}
		}
	}
	if parallelism > -1 {
		_ = eg.Wait()
	}

	return nil
}

func init() {
	rootCmd.AddCommand(execCmd)

	execCmd.Flags().StringArray("package", nil, "select a package by name")
	execCmd.Flags().Bool("dependencies", false, "select package dependencies")
	execCmd.Flags().Bool("transitive-dependencies", false, "select transitive package dependencies")
	execCmd.Flags().Bool("dependants", false, "select package dependants")
	execCmd.Flags().Bool("transitive-dependants", false, "select transitive package dependants")
	execCmd.Flags().Bool("components", false, "select the package's components (e.g. instead of selecting three packages from the same component, execute just once in the component origin)")
	execCmd.Flags().StringArray("filter-type", nil, "only select packages of this type")
	execCmd.Flags().String("filter-name", "", "only select packages matching this name regular expression")
	execCmd.Flags().Bool("watch", false, "Watch source files and re-execute on change")
	execCmd.Flags().Bool("parallel", false, "Start all executions in parallel independent of their order")
	execCmd.Flags().Bool("raw-output", false, "Produce output without package prefix")
	execCmd.Flags().String("cache-key", "", "Specify a cache key to provide package-cache like execution behaviour")
	execCmd.Flags().UintP("max-concurrent-tasks", "j", 0, "Maximum number of concurrent tasks - 0 means unlimited")
	execCmd.Flags().SetInterspersed(true)
}

type execCache interface {
	NeedsExecution(ctx context.Context, loc commandExecLocation) (bool, error)
	MarkExecuted(ctx context.Context, loc commandExecLocation) error
}

type noExecCache struct{}

func (noExecCache) MarkExecuted(ctx context.Context, loc commandExecLocation) error { return nil }
func (noExecCache) NeedsExecution(ctx context.Context, loc commandExecLocation) (bool, error) {
	return true, nil
}

type filesystemExecCache string

func (c filesystemExecCache) MarkExecuted(ctx context.Context, loc commandExecLocation) error {
	err := os.MkdirAll(string(c), 0755)
	if err != nil {
		return err
	}
	fn, err := c.filename(loc)
	if err != nil {
		return err
	}
	f, err := os.Create(string(fn))
	if err != nil {
		return err
	}
	f.Close()
	log.WithField("name", fn).Debug("marked executed")
	return nil
}

func (c filesystemExecCache) filename(loc commandExecLocation) (string, error) {
	var id string
	if loc.Package != nil {
		v, err := loc.Package.Version()
		if err != nil {
			return "", err
		}
		id = v
	} else if loc.Component != nil {
		id = leeway.FilesystemSafeName(loc.Component.Name)
	} else if loc.Dir != "" {
		id = leeway.FilesystemSafeName(loc.Dir)
	} else if loc.Name != "" {
		id = loc.Name
	}

	return filepath.Join(string(c), fmt.Sprintf("%s.executed", id)), nil
}

func (c filesystemExecCache) NeedsExecution(ctx context.Context, loc commandExecLocation) (bool, error) {
	fn, err := c.filename(loc)
	if err != nil {
		return false, err
	}
	_, err = os.Stat(fn)
	if os.IsNotExist(err) {
		return true, nil
	}
	return false, err
}
