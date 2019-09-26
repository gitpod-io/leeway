package cmd

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/typefox/leeway/pkg/leeway"
	"gopkg.in/yaml.v2"
)

// describeCmd represents the describe command
var describeCmd = &cobra.Command{
	Use:   "describe <component|package>",
	Short: "Describes a single component or package",
	Args:  cobra.MaximumNArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 2 {
			cmdname := args[0]
			var subcmd *cobra.Command
			for _, c := range cmd.Commands() {
				if c.Name() == cmdname {
					cmd = c
					break
				}
			}

			if subcmd == nil {
				log.Fatalf("unknown command %s", cmdname)
			}

			subcmd.SetArgs(args[1:])
			err := subcmd.Execute()
			if err != nil {
				log.Fatal(err)
			}
			return
		}

		comp, pkg, exists := getTarget(args)
		if !exists {
			return
		}
		if pkg != nil {
			describePackage(pkg)
			return
		}

		describeComponent(comp)
	},
}

func getTarget(args []string) (comp leeway.Component, pkg *leeway.Package, exists bool) {
	workspace, err := getWorkspace()
	if err != nil {
		log.Fatal(err)
	}
	log.WithField("origin", workspace.Origin).Debug("found workspace")

	var target string
	if len(args) == 0 {
		target = workspace.DefaultTarget
	} else {
		target = args[0]
	}
	if target == "" {
		log.Fatal("no target")
		return
	}

	if strings.HasPrefix(target, ".:") {
		wd, err := os.Getwd()
		if err != nil {
			log.Fatal(err)
		}

		// This uses seperate trims and is not part of origin to support BUILD files in the workspace root.
		// In that case there's no "/" left over at the origin.
		cn := strings.TrimPrefix(wd, workspace.Origin)
		cn = strings.TrimPrefix(cn, "/")

		pn := strings.TrimPrefix(target, ".:")

		target = fmt.Sprintf("%s:%s", cn, pn)
	}

	if isPkg := strings.Contains(target, ":"); isPkg {
		pkg, exists = workspace.Packages[target]
		if !exists {
			log.Fatalf("package \"%s\" does not exist", target)
			return
		}
	} else {
		comp, exists = workspace.Components[target]
		if !exists {
			log.Fatalf("component \"%s\" does not exist", target)
			return
		}
	}

	return
}

func describePackage(pkg *leeway.Package) {
	manifest, err := pkg.ContentManifest()
	if err != nil {
		log.Fatal(err)
	}
	version, err := pkg.Version()
	if err != nil {
		log.Fatal(err)
	}

	deps := make([]string, len(pkg.GetDependencies()))
	for i, dep := range pkg.GetDependencies() {
		version, _ := dep.Version()
		deps[i] = fmt.Sprintf("\t%s\t%s\n", dep.FullName(), version)
	}
	sort.Slice(deps, func(i, j int) bool { return deps[i] < deps[j] })

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	defer w.Flush()

	fmt.Fprintf(w, "Name:\t%s\n", pkg.FullName())
	fmt.Fprintf(w, "Version:\t%s\t\n", version)
	fmt.Fprintf(w, "Configuration:\n%s", describeConfig(pkg.Config))
	if len(pkg.ArgumentDependencies) > 0 {
		fmt.Fprintf(w, "Version Relevant Arguments:\n")
		for _, argdep := range pkg.ArgumentDependencies {
			fmt.Fprintf(w, "\t%s\n", argdep)
		}
	}
	if len(pkg.Environment) > 0 {
		fmt.Fprintf(w, "Build Environment Variables:\n")
		for _, env := range pkg.Environment {
			fmt.Fprintf(w, "\t%s\n", env)
		}
	}
	if len(pkg.Dependencies) > 0 {
		fmt.Fprintf(w, "Dependencies:\n")
		for _, dep := range deps {
			fmt.Fprint(w, dep)
		}
	}
	if len(pkg.Sources) > 0 {
		fmt.Fprintf(w, "Sources:\n")
		for _, src := range manifest {
			segs := strings.Split(src, ":")
			name := segs[0]
			version := segs[1]
			fmt.Fprintf(w, "\t%s\t%s\n", name, version)
		}
	}
}

func describeComponent(comp leeway.Component) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	defer w.Flush()

	fmt.Fprintf(w, "Name:\t%s\n", comp.Name)
	fmt.Fprintf(w, "Origin:\t%s\n", comp.Origin)
	fmt.Fprintf(w, "Packages:\t\n")
	for _, pkg := range comp.Packages {
		fmt.Fprintf(w, "\t%s\n", pkg.Name)
	}
}

func describeConfig(cfg leeway.PackageConfig) string {
	fc, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Sprintf("\t!! cannot present: %v !!", err)
	}

	cfgmap := make(map[string]interface{})
	err = yaml.Unmarshal(fc, &cfgmap)
	if err != nil {
		return fmt.Sprintf("\t!! cannot present: %v !!", err)
	}

	var res string
	for k, v := range cfgmap {
		res += fmt.Sprintf("\t%s:\t%v\n", k, v)
	}
	return res
}

func init() {
	rootCmd.AddCommand(describeCmd)
	describeCmd.Flags().StringP("format", "f", "default", "the description format. Valid choices are: default, tree, dot, manifest")
}
