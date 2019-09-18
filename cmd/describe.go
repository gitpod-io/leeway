package cmd

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/disiqueira/gotree"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/typefox/leeway/pkg/leeway"
	"gopkg.in/yaml.v2"
)

var printDepTree bool
var printDepGraph bool

// describeCmd represents the describe command
var describeCmd = &cobra.Command{
	Use:   "describe <component|package>",
	Short: "Describes a single component or package",
	Args:  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if printDepTree && printDepGraph {
			log.Fatal("--tree and --dot are exclusive. Choose one or the other.")
		}

		workspace, err := getWorkspace()
		if err != nil {
			log.Fatal(err)
		}

		var target string
		if len(args) == 0 {
			target = workspace.DefaultTarget
		} else {
			target = args[0]
		}
		if target == "" {
			log.Fatal("no target")
		}

		if isPkg := strings.Contains(target, ":"); isPkg {
			pkg, exists := workspace.Packages[target]
			if !exists {
				log.Fatalf("package \"%s\" does not exist", target)
				return
			}

			if printDepTree {
				err = printDependencyTree(pkg)
				if err != nil {
					log.Fatal(err)
				}
				return
			} else if printDepGraph {
				err = printDependencyGraph(pkg)
				if err != nil {
					log.Fatal(err)
				}
				return
			}
			describePackage(pkg)
		} else {
			comp, exists := workspace.Components[target]
			if !exists {
				log.Fatalf("component \"%s\" does not exist", target)
				return
			}

			if printDepTree {
				log.Fatal("--tree only makes sense for packages")
			}
			if printDepGraph {
				log.Fatal("--tree only makes sense for packages")
			}
			describeComponent(comp)
		}
	},
}

func printDependencyTree(pkg *leeway.Package) error {
	var print func(parent gotree.Tree, pkg *leeway.Package)
	print = func(parent gotree.Tree, pkg *leeway.Package) {
		n := parent.Add(pkg.FullName())
		for _, dep := range pkg.GetDependencies() {
			print(n, dep)
		}
	}

	tree := gotree.New("WORKSPACE")
	print(tree, pkg)
	_, err := fmt.Println(tree.Print())
	return err
}

func printDependencyGraph(pkg *leeway.Package) error {
	allpkg := append(pkg.GetTransitiveDependencies(), pkg)

	fmt.Println("digraph G {")
	for _, p := range allpkg {
		ver, err := p.Version()
		if err != nil {
			return err
		}
		fmt.Printf("  p%s [label=\"%s\"];\n", ver, p.FullName())
	}
	for _, p := range allpkg {
		ver, err := p.Version()
		if err != nil {
			return err
		}

		for _, dep := range p.GetDependencies() {
			depver, err := dep.Version()
			if err != nil {
				return err
			}
			fmt.Printf("  p%s -> p%s;\n", ver, depver)
		}
	}
	fmt.Println("}")

	return nil
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
	fmt.Fprintf(w, "Dependencies:\n")
	for _, dep := range deps {
		fmt.Fprint(w, dep)
	}
	fmt.Fprintf(w, "Sources:\n")
	for _, src := range manifest {
		segs := strings.Split(src, ":")
		name := strings.TrimPrefix(segs[0], pkg.C.Origin+"/")
		version := segs[1]
		fmt.Fprintf(w, "\t%s\t%s\n", name, version)
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
	describeCmd.Flags().BoolVar(&printDepTree, "tree", false, "print the dependency tree of a package")
	describeCmd.Flags().BoolVar(&printDepGraph, "dot", false, "print the dependency graph as Graphviz DOT")
}
