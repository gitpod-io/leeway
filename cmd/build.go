package cmd

import (
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/gookit/color"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/typefox/leeway/pkg/leeway"
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

		cm, _ := cmd.Flags().GetString("cache")
		log.WithField("cacheMode", cm).Debug("configuring caches")
		cacheLevel := leeway.CacheLevel(cm)

		remoteCache := getRemoteCache()
		if cacheLevel == leeway.CacheNone || cacheLevel == leeway.CacheLocal {
			remoteCache = leeway.NoRemoteCache{}
		}
		if cacheLevel == leeway.CacheRemotePush {
			remoteCache = &pushOnlyRemoteCache{C: remoteCache}
		}
		var (
			localCacheLoc string
			err           error
		)
		if cacheLevel == leeway.CacheNone {
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

		var planOutlet io.Writer
		if plan, _ := cmd.Flags().GetString("dump-plan"); plan != "" {
			if plan == "-" {
				planOutlet = os.Stderr
			} else {
				f, err := os.OpenFile(plan, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
				if err != nil {
					log.Fatal(err)
				}
				defer f.Close()

				planOutlet = f
			}
		}

		werftlog, err := cmd.Flags().GetBool("werft")
		if err != nil {
			log.Fatal(err)
		}
		var reporter leeway.Reporter
		if werftlog {
			reporter = leeway.NewWerftReporter()
		} else {
			reporter = leeway.NewConsoleReporter()
		}

		err = leeway.Build(pkg,
			leeway.WithLocalCache(localCache),
			leeway.WithRemoteCache(remoteCache),
			leeway.WithDryRun(dryrun),
			leeway.WithBuildPlan(planOutlet),
			leeway.WithReporter(reporter),
		)
		if err != nil {
			log.Fatal(err)
		}

		save, _ := cmd.Flags().GetString("save")
		if save != "" {
			br, exists := localCache.Location(pkg)
			if !exists {
				log.Fatal("build result is not in local cache despite just being built. Something's wrong with the cache.")
			}

			fout, err := os.OpenFile(save, os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
				log.WithError(err).Fatal("cannot open result file for writing")
			}
			fin, err := os.OpenFile(br, os.O_RDONLY, 0644)
			if err != nil {
				fout.Close()
				log.WithError(err).Fatal("cannot copy build result")
			}

			_, err = io.Copy(fout, fin)
			fout.Close()
			fin.Close()
			if err != nil {
				log.WithError(err).Fatal("cannot copy build result")
			}

			fmt.Printf("\n💾  saving build result to %s\n", color.Cyan.Render(save))
		}

		serve, _ := cmd.Flags().GetString("serve")
		if serve != "" {
			br, exists := localCache.Location(pkg)
			if !exists {
				log.Fatal("build result is not in local cache despite just being built. Something's wrong with the cache.")
			}

			tmp, err := ioutil.TempDir("", "leeway_serve")
			if err != nil {
				log.WithError(err).Fatal("cannot serve build result")
			}

			cmd := exec.Command("tar", "xzf", br)
			cmd.Dir = tmp
			_, err = cmd.CombinedOutput()
			if err != nil {
				log.WithError(err).Fatal("cannot serve build result")
			}

			fmt.Printf("\n📢  serving build result on %s\n", color.Cyan.Render(serve))
			err = http.ListenAndServe(serve, http.FileServer(http.Dir(tmp)))
			if err != nil {
				log.Fatal(err)
			}
		}
	},
}

func init() {
	cacheDefault := os.Getenv("LEEWAY_DEFAULT_CACHE_LEVEL")
	if cacheDefault == "" {
		cacheDefault = "remote"
	}

	rootCmd.AddCommand(buildCmd)
	buildCmd.Flags().StringP("cache", "c", cacheDefault, "Configures the caching behaviour: none=no caching, local=local caching only, push-remote=push to remote cache only but don't download, remote=use all configured caches")
	buildCmd.Flags().Bool("dry-run", false, "Don't actually build but stop after showing what would need to be built")
	buildCmd.Flags().String("serve", "", "After a successful build this starts a webserver on the given address serving the build result (e.g. --serve localhost:8080)")
	buildCmd.Flags().String("save", "", "After a successful build this saves the build result as tar.gz file in the local filesystem (e.g. --save build-result.tar.gz)")
	buildCmd.Flags().String("dump-plan", "", "Writes the build plan as JSON to a file. Use \"-\" to write the build plan to stderr.")
	buildCmd.Flags().Bool("werft", false, "Produce werft CI compatible output")
}

type pushOnlyRemoteCache struct {
	C leeway.RemoteCache
}

func (c *pushOnlyRemoteCache) Download(dst leeway.Cache, pkgs []*leeway.Package) error {
	return nil
}

func (c *pushOnlyRemoteCache) Upload(src leeway.Cache, pkgs []*leeway.Package) error {
	return c.Upload(src, pkgs)
}
