package cmd

import (
	"fmt"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/gitpod-io/leeway/pkg/leeway"
)

// describeDependantsCmd represents the describeDot command
var describeDependantsCmd = &cobra.Command{
	Use:   "dependants",
	Short: "Describes the dependants package on the console",
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
				for _, d := range p.Dependants() {
					delete(allpkgs, d.FullName())
				}
			}
			for _, p := range allpkgs {
				pkgs = append(pkgs, p)
			}
		}

		transitive, _ := cmd.Flags().GetBool("transitive")
		for _, pkg := range pkgs {
			var deps []*leeway.Package
			if transitive {
				deps = pkg.TransitiveDependants()
			} else {
				deps = pkg.Dependants()
			}
			for _, d := range deps {
				fmt.Println(d.FullName())
			}
		}

		return nil
	},
}

func init() {
	describeCmd.AddCommand(describeDependantsCmd)
	describeDependantsCmd.Flags().BoolP("transitive", "t", false, "Print transitive dependants")
}
