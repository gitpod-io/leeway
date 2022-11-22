package cmd

import (
	"fmt"

	"github.com/gookit/color"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/gitpod-io/leeway/pkg/leeway"
)

// describeDependenciesCmd represents the describeDot command
var describeDependenciesCmd = &cobra.Command{
	Use:   "dependencies",
	Short: "Describes the depenencies package on the console, in Graphviz's dot format or as interactive website",
	RunE: func(cmd *cobra.Command, args []string) error {
		var pkgs []*leeway.Package
		if len(args) > 0 {
			_, pkg, _, _ := getTarget(args, false)
			if pkg == nil {
				log.Fatal("graphview needs a package")
			}
			pkgs = []*leeway.Package{pkg}
		} else {
			ws, err := getWorkspace()
			if err != nil {
				log.Fatal(err)
			}

			allpkgs := ws.Packages
			for _, p := range allpkgs {
				for _, d := range p.GetDependencies() {
					delete(allpkgs, d.FullName())
				}
			}
			for _, p := range allpkgs {
				pkgs = append(pkgs, p)
			}
		}

		if dot, _ := cmd.Flags().GetBool("dot"); dot {
			return printDepGraphAsDot(pkgs)
		} else {
			for _, pkg := range pkgs {
				printDepTree(pkg, 0)
			}
		}

		return nil
	},
}

func printDepTree(pkg *leeway.Package, indent int) {
	var tpe string
	switch pkg.Type {
	case leeway.DockerPackage:
		tpe = "docker"
	case leeway.GenericPackage:
		tpe = "generic"
	case leeway.GoPackage:
		tpe = "go"
	case leeway.YarnPackage:
		tpe = "yarn"
	}

	fmt.Printf("%*s%s %s\n", indent, "", color.Gray.Sprintf("[%7s]", tpe), pkg.FullName())
	for _, p := range pkg.GetDependencies() {
		printDepTree(p, indent+4)
	}
}

func printDepGraphAsDot(pkgs []*leeway.Package) error {
	var (
		nodes = make(map[string]string)
		edges []string
	)

	for _, pkg := range pkgs {
		allpkg := append(pkg.GetTransitiveDependencies(), pkg)
		for _, p := range allpkg {
			ver, err := p.Version()
			if err != nil {
				return err
			}
			if _, exists := nodes[ver]; exists {
				continue
			}
			nodes[ver] = fmt.Sprintf("p%s [label=\"%s\"];", ver, p.FullName())
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
				edges = append(edges, fmt.Sprintf("p%s -> p%s;", ver, depver))
			}
		}
	}

	fmt.Println("digraph G {")
	for _, n := range nodes {
		fmt.Printf("  %s\n", n)
	}
	for _, e := range edges {
		fmt.Printf("  %s\n", e)
	}
	fmt.Println("}")
	return nil
}

func init() {
	describeCmd.AddCommand(describeDependenciesCmd)

	describeDependenciesCmd.Flags().Bool("dot", false, "produce Graphviz dot output")
}
