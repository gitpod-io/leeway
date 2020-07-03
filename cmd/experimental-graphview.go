// +build linux

package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/typefox/leeway/pkg/graphview"
	"github.com/typefox/leeway/pkg/leeway"
)

// graphviewCmd represents the mount command
var graphviewCmd = &cobra.Command{
	Use:   "graphview [package]",
	Short: "[experimental] Serves a web-based view of a package's dependencies",
	Args:  cobra.MaximumNArgs(1),
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

		addr, _ := cmd.Flags().GetString("addr")
		log.WithField("addr", addr).Info("serving dependency graph view")

		go func() {
			browser := os.Getenv("BROWSER")
			if browser == "" {
				return
			}

			time.Sleep(2 * time.Second)
			taddr := addr
			if strings.HasPrefix(taddr, ":") {
				taddr = fmt.Sprintf("localhost%s", addr)
			}
			taddr = fmt.Sprintf("http://%s", taddr)
			exec.Command(browser, taddr).Start()
		}()

		log.Fatal(graphview.Serve(addr, pkgs...))

		return nil
	},
}

func init() {
	addExperimentalCommand(rootCmd, graphviewCmd)

	graphviewCmd.Flags().String("addr", ":8080", "address to serve the graphview on")
}
