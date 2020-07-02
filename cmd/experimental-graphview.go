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
)

// graphviewCmd represents the mount command
var graphviewCmd = &cobra.Command{
	Use:   "graphview <package>",
	Short: "[experimental] Serves a web-based view of a package's dependencies",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		_, pkg, _, _ := getTarget(args, false)
		if pkg == nil {
			log.Fatal("graphview needs a package")
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

		log.Fatal(graphview.Serve(pkg, addr))

		return nil
	},
}

func init() {
	addExperimentalCommand(rootCmd, graphviewCmd)

	graphviewCmd.Flags().String("addr", ":8080", "address to serve the graphview on")
}
