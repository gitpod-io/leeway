package cmd

import (
	"fmt"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// describeDotCmd represents the describeDot command
var describeDotCmd = &cobra.Command{
	Use:   "dot",
	Short: "Prints the depenency graph of a package as Graphviz dot",
	RunE: func(cmd *cobra.Command, args []string) error {
		_, pkg, _ := getTarget(args)
		if pkg == nil {
			log.Fatal("dot needs a package")
		}

		allpkg := append(pkg.GetTransitiveDependencies(), pkg)
		nodeidx := make(map[string]struct{})

		fmt.Println("digraph G {")
		for _, p := range allpkg {
			ver, err := p.Version()
			if err != nil {
				return err
			}
			if _, exists := nodeidx[ver]; exists {
				continue
			}
			nodeidx[ver] = struct{}{}

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
	},
}

func init() {
	describeCmd.AddCommand(describeDotCmd)
}
