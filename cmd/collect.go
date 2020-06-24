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
)

// collectCmd represents the collect command
var collectCmd = &cobra.Command{
	Use:   "collect [packages|components|files]",
	Short: "Collects all packages in a workspace",
	Args:  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		workspace, err := getWorkspace()
		if err != nil {
			log.Fatal(err)
		}

		nameOnly, _ := cmd.Flags().GetBool("name-only")
		var tpe string
		if len(args) > 0 {
			tpe = args[0]
		}

		selectStr, _ := cmd.Flags().GetString("select")
		var selector func(c leeway.Component) bool
		segs := strings.Split(selectStr, "=")
		if len(selectStr) == 0 {
			selector = func(c leeway.Component) bool {
				return true
			}
		} else if len(segs) == 1 {
			selector = func(c leeway.Component) bool {
				_, ok := c.Constants[segs[0]]
				return ok
			}
		} else if len(segs) == 2 {
			selector = func(c leeway.Component) bool {
				return c.Constants[segs[0]] == segs[1]
			}
		} else {
			log.Fatal("selector must either be a constant name or const=value")
		}

		var res []string
		for _, comp := range workspace.Components {
			if !selector(comp) {
				continue
			}

			if tpe == "component" {
				res = append(res, comp.Name)
				continue
			}

			for _, pkg := range comp.Packages {
				version, err := pkg.Version()
				if err != nil {
					version = "ERROR: " + err.Error()
				}

				if tpe == "files" {
					res = append(res, pkg.Sources...)
					continue
				}

				if nameOnly {
					res = append(res, pkg.FullName())
					continue
				}

				res = append(res, fmt.Sprintf("%s\t%s", pkg.FullName(), version))
			}
		}

		sort.Slice(res, func(i, j int) bool { return res[i] < res[j] })

		tw := tabwriter.NewWriter(os.Stdout, 1, 8, 2, ' ', 0)
		for _, pkg := range res {
			fmt.Fprintln(tw, pkg)
		}
		tw.Flush()
	},
}

func init() {
	rootCmd.AddCommand(collectCmd)
	// collectCmd.Flags().Bool("dot", false, "print dependency graph as Graphviz dot")
	collectCmd.Flags().Bool("name-only", false, "Prints the package name only")
	collectCmd.Flags().StringP("select", "l", "", "Filters packages by component constants (e.g. `-l foo` finds all packages whose components have a foo constant and `-l foo=bar` only prints packages whose components have a foo=bar constant)")
}
