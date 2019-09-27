package cmd

import (
	"fmt"
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

const (
	cacheNone       = "none"
	cacheLocal      = "local"
	cacheRemote     = "remote"
	cacheRemotePush = "remote-push"
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
		if cacheMode == cacheNone || cacheMode == cacheLocal {
			remoteCache = leeway.NoRemoteCache{}
		}
		if cacheMode == cacheRemotePush {
			remoteCache = &pushOnlyRemoteCache{C: remoteCache}
		}
		var (
			localCacheLoc string
			err           error
		)
		if cacheMode == cacheNone {
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

		err = leeway.Build(pkg,
			leeway.WithLocalCache(localCache),
			leeway.WithRemoteCache(remoteCache),
			leeway.WithDryRun(dryrun),
		)
		if err != nil {
			log.Fatal(err)
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
	rootCmd.AddCommand(buildCmd)
	buildCmd.Flags().StringP("cache", "c", "remote", "Configures the caching behaviour: none=no caching, local=local caching only, push-remote=push to remote cache only but don't download, remote=use all configured caches")
	buildCmd.Flags().Bool("dry-run", false, "Don't actually build but stop after showing what would need to be built")
	buildCmd.Flags().String("serve", "", "After a successful build this starts a webserver on the given address serving the build result (e.g. --serve localhost:8080)")
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
