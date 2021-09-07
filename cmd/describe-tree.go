package cmd

import (
	"fmt"

	"github.com/disiqueira/gotree"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/gitpod-io/leeway/pkg/leeway"
)

// describeTreeCmd represents the describeTree command
var describeTreeCmd = &cobra.Command{
	Use:   "tree",
	Short: "Prints the depepency tree of a package",
	Run: func(cmd *cobra.Command, args []string) {
		_, pkg, _, _ := getTarget(args, false)
		if pkg == nil {
			log.Fatal("tree needs a package")
		}

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
		if err != nil {
			log.Fatal(err)
		}
	},
}

func init() {
	describeCmd.AddCommand(describeTreeCmd)
}
