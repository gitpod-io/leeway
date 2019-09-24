package cmd

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/typefox/leeway/pkg/leeway"
	"github.com/typefox/leeway/pkg/remotereporter"
	"google.golang.org/grpc"
)

// buildCmd represents the build command
var buildCmd = &cobra.Command{
	Use:   "build [targetPackage]",
	Short: "Builds a package",
	Args:  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		_, pkg, _ := getTarget(args)
		if pkg == nil {
			log.Fatal("tree needs a package")
		}

		cacheMode, _ := cmd.Flags().GetString("cache")
		log.WithField("cacheMode", cacheMode).Debug("configuring caches")
		remoteCache := getRemoteCache()
		if cacheMode != "remote" {
			remoteCache = leeway.NoRemoteCache{}
		}
		var (
			localCacheLoc string
			err           error
		)
		if cacheMode == "none" {
			localCacheLoc, err = ioutil.TempDir("", "leeway")
			if err != nil {
				log.Fatal(err)
			}
		} else {
			localCacheLoc = os.Getenv(leeway.EnvvarCacheDir)
			if localCacheLoc == "" {
				localCacheLoc = filepath.Join(os.TempDir(), "cache")
			}
		}
		log.WithField("location", localCacheLoc).Debug("set up local cache")
		localCache, err := leeway.NewFilesystemCache(localCacheLoc)
		if err != nil {
			log.Fatal(err)
		}

		dryrun, err := cmd.Flags().GetBool("dry-run")
		if err != nil {
			log.Fatal(err)
		}

		log.Debugf("this is leeway version %s", version)

		var reporter leeway.Reporter = leeway.NewConsoleReporter()
		if rrep := os.Getenv(EnvvarRemoteReporter); rrep != "" {
			remoterep, err := remotereporter.NewRemoteReporter(rrep, grpc.WithInsecure(), grpc.WithTimeout(5*time.Second))
			if err != nil {
				log.Fatal(err)
			}

			reporter = &leeway.CompositeReporter{
				Children: []leeway.Reporter{
					reporter,
					remoterep,
				},
			}
		}

		err = leeway.Build(pkg,
			leeway.WithLocalCache(localCache),
			leeway.WithRemoteCache(remoteCache),
			leeway.WithDryRun(dryrun),
			leeway.WithReporter(reporter),
		)
		if err != nil {
			log.Fatal(err)
		}
	},
}

func init() {
	rootCmd.AddCommand(buildCmd)
	buildCmd.Flags().StringP("cache", "c", "remote", "Configures the caching behaviour: none=no caching, local=local caching only, remote=use all configured caches")
	buildCmd.Flags().Bool("dry-run", false, "don't actually build but stop after showing what would need to be built")
}
