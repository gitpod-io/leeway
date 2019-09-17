package cmd

import (
	log "github.com/sirupsen/logrus"

	"github.com/spf13/cobra"
	"github.com/typefox/gitpod/leeway/pkg/leeway"
)

// buildCmd represents the build command
var buildCmd = &cobra.Command{
	Use:   "build [targetPackage]",
	Short: "Builds a package",
	Args:  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
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

		pkg, exists := workspace.Packages[target]
		if !exists {
			log.Fatalf("package \"%s\" not found", target)
			return
		}

		cacheMode, _ := cmd.Flags().GetString("cache")
		cache := getRemoteCache()
		if cacheMode != "remote" {
			cache = leeway.NoRemoteCache{}
		}
		useLocalCache := cacheMode != "none"

		err = leeway.Build(pkg, useLocalCache, cache)
		if err != nil {
			log.Fatal(err)
		}
	},
}

func init() {
	rootCmd.AddCommand(buildCmd)
	buildCmd.Flags().StringP("cache", "c", "remote", "Configures the caching behaviour: none=no caching, local=local caching only, remote=use all configured caches")
}
