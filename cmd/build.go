package cmd

import (
	"context"
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
		_, pkg, _, _ := getTarget(args, false)
		if pkg == nil {
			log.Fatal("build needs a package")
		}
		opts, localCache := getBuildOpts(cmd)

		var (
			watch, _ = cmd.Flags().GetBool("watch")
			save, _  = cmd.Flags().GetString("save")
			serve, _ = cmd.Flags().GetString("serve")
		)
		if watch {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			err := leeway.Build(pkg, opts...)
			if err != nil {
				log.Fatal(err)
			}
			ctx, cancel = context.WithCancel(context.Background())
			if save != "" {
				saveBuildResult(ctx, save, localCache, pkg)
			}
			if serve != "" {
				go serveBuildResult(ctx, serve, localCache, pkg)
			}

			evt, errs := leeway.WatchSources(context.Background(), append(pkg.GetTransitiveDependencies(), pkg))
			for {
				select {
				case <-evt:
					_, pkg, _, _ := getTarget(args, false)
					err := leeway.Build(pkg, opts...)
					if err == nil {
						cancel()
						ctx, cancel = context.WithCancel(context.Background())
						if save != "" {
							saveBuildResult(ctx, save, localCache, pkg)
						}
						if serve != "" {
							go serveBuildResult(ctx, serve, localCache, pkg)
						}
					} else {
						log.Error(err)
					}
				case err = <-errs:
					log.Fatal(err)
				}
			}
		}

		err := leeway.Build(pkg, opts...)
		if err != nil {
			log.Fatal(err)
		}
		if save != "" {
			saveBuildResult(context.Background(), save, localCache, pkg)
		}
		if serve != "" {
			serveBuildResult(context.Background(), serve, localCache, pkg)
		}
	},
}

func serveBuildResult(ctx context.Context, addr string, localCache *leeway.FilesystemCache, pkg *leeway.Package) {
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
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.WithError(err).WithField("output", string(out)).Fatal("cannot serve build result")
	}

	if ctx.Err() != nil {
		return
	}

	fmt.Printf("\n📢  serving build result on %s\n", color.Cyan.Render(addr))
	server := &http.Server{Addr: addr, Handler: http.FileServer(http.Dir(tmp))}
	go func() {
		err = server.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()
	<-ctx.Done()
	err = server.Close()
	if err != nil {
		log.WithError(err).Error("cannot close server")
	}
}

func saveBuildResult(ctx context.Context, loc string, localCache *leeway.FilesystemCache, pkg *leeway.Package) {
	br, exists := localCache.Location(pkg)
	if !exists {
		log.Fatal("build result is not in local cache despite just being built. Something's wrong with the cache.")
	}

	fout, err := os.OpenFile(loc, os.O_CREATE|os.O_WRONLY, 0644)
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

	fmt.Printf("\n💾  saving build result to %s\n", color.Cyan.Render(loc))
}

func init() {
	rootCmd.AddCommand(buildCmd)

	addBuildFlags(buildCmd)
	buildCmd.Flags().String("serve", "", "After a successful build this starts a webserver on the given address serving the build result (e.g. --serve localhost:8080)")
	buildCmd.Flags().String("save", "", "After a successful build this saves the build result as tar.gz file in the local filesystem (e.g. --save build-result.tar.gz)")
	buildCmd.Flags().Bool("watch", false, "Watch source files and re-build on change")
}

func addBuildFlags(cmd *cobra.Command) {
	cacheDefault := os.Getenv("LEEWAY_DEFAULT_CACHE_LEVEL")
	if cacheDefault == "" {
		cacheDefault = "remote"
	}

	cmd.Flags().StringP("cache", "c", cacheDefault, "Configures the caching behaviour: none=no caching, local=local caching only, remote-pull=download from remote but never upload, remote-push=push to remote cache only but don't download, remote=use all configured caches")
	cmd.Flags().StringSlice("add-remote-cache", []string{}, "Configures additional (pull-only) remote caches")
	cmd.Flags().Bool("dry-run", false, "Don't actually build but stop after showing what would need to be built")
	cmd.Flags().String("dump-plan", "", "Writes the build plan as JSON to a file. Use \"-\" to write the build plan to stderr.")
	cmd.Flags().Bool("werft", false, "Produce werft CI compatible output")
	cmd.Flags().Bool("dont-test", false, "Disable all package-level tests (defaults to false)")
}

func getBuildOpts(cmd *cobra.Command) ([]leeway.BuildOption, *leeway.FilesystemCache) {
	cm, _ := cmd.Flags().GetString("cache")
	log.WithField("cacheMode", cm).Debug("configuring caches")
	cacheLevel := leeway.CacheLevel(cm)

	remoteCache := getRemoteCache()
	switch cacheLevel {
	case leeway.CacheNone, leeway.CacheLocal:
		remoteCache = leeway.NoRemoteCache{}
	case leeway.CacheRemotePull:
		remoteCache = &pullOnlyRemoteCache{C: remoteCache}
	case leeway.CacheRemotePush:
		remoteCache = &pushOnlyRemoteCache{C: remoteCache}
	case leeway.CacheRemote:
	default:
		log.Fatalf("invalid cache level: %s", cacheLevel)
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

	var arcs []leeway.RemoteCache
	additionalRemoteCaches, _ := cmd.Flags().GetStringSlice("add-remote-cache")
	for _, arc := range additionalRemoteCaches {
		arcs = append(arcs, &pullOnlyRemoteCache{
			C: leeway.GSUtilRemoteCache{
				BucketName: arc,
			},
		})
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

	dontTest, err := cmd.Flags().GetBool("dont-test")
	if err != nil {
		log.Fatal(err)
	}

	return []leeway.BuildOption{
		leeway.WithLocalCache(localCache),
		leeway.WithRemoteCache(remoteCache),
		leeway.WithAdditionalRemoteCaches(arcs),
		leeway.WithDryRun(dryrun),
		leeway.WithBuildPlan(planOutlet),
		leeway.WithReporter(reporter),
		leeway.WithDontTest(dontTest),
	}, localCache
}

type pushOnlyRemoteCache struct {
	C leeway.RemoteCache
}

func (c *pushOnlyRemoteCache) Download(dst leeway.Cache, pkgs []*leeway.Package) error {
	return nil
}

func (c *pushOnlyRemoteCache) Upload(src leeway.Cache, pkgs []*leeway.Package) error {
	return c.C.Upload(src, pkgs)
}

type pullOnlyRemoteCache struct {
	C leeway.RemoteCache
}

func (c *pullOnlyRemoteCache) Download(dst leeway.Cache, pkgs []*leeway.Package) error {
	return c.C.Download(dst, pkgs)
}

func (c *pullOnlyRemoteCache) Upload(src leeway.Cache, pkgs []*leeway.Package) error {
	return nil
}
