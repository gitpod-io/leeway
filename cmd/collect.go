package cmd

import (
	"fmt"
	"os"
	"sort"
	"text/tabwriter"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// collectCmd represents the collect command
var collectCmd = &cobra.Command{
	Use:   "collect",
	Short: "Collects all packages in a workspace",
	Run: func(cmd *cobra.Command, args []string) {
		workspace, err := getWorkspace()
		if err != nil {
			log.Fatal(err)
		}

		var pkgs []string
		for _, comp := range workspace.Components {
			for _, pkg := range comp.Packages {
				version, err := pkg.Version()
				if err != nil {
					version = "ERROR: " + err.Error()
				}

				pkgs = append(pkgs, fmt.Sprintf("%s\t%s\n", pkg.FullName(), version))
			}
		}

		sort.Slice(pkgs, func(i, j int) bool { return pkgs[i] < pkgs[j] })

		tw := tabwriter.NewWriter(os.Stdout, 1, 8, 2, ' ', 0)
		for _, pkg := range pkgs {
			fmt.Fprint(tw, pkg)
		}
		tw.Flush()
	},
}

func init() {
	rootCmd.AddCommand(collectCmd)
	// collectCmd.Flags().Bool("dot", false, "print dependency graph as Graphviz dot")
}
