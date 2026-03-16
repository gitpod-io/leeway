package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/gitpod-io/leeway/pkg/leeway"
	"github.com/gitpod-io/leeway/pkg/leeway/cache"
	"github.com/gitpod-io/leeway/pkg/leeway/cache/local"
)

const (
	// ExitChangedUnchanged indicates the package is cached and does not need a rebuild.
	ExitChangedUnchanged = 0
	// ExitChangedNeedsRebuild indicates the package has changed and needs a rebuild.
	ExitChangedNeedsRebuild = 1
	// ExitChangedError indicates an error occurred while checking.
	ExitChangedError = 2
)

// describeChangedCmd checks whether a package has changed by looking up its
// current version hash in the local and remote caches. If the version exists
// in either cache the package is unchanged (exit 0); otherwise it has changed
// and needs a rebuild (exit 1). Errors exit with code 2.
var describeChangedCmd = &cobra.Command{
	Use:   "changed <package>",
	Short: "Checks whether a package needs to be rebuilt by consulting the cache",
	Long: `Computes the version hash of a package and checks whether a build artifact
for that version already exists in the local or remote cache.

Exit codes:
  0 - package is cached (unchanged, no rebuild needed)
  1 - package is not cached (changed, needs rebuild)
  2 - an error occurred

This is useful for CI branching decisions:

  if leeway describe changed my-component:my-package; then
    echo "unchanged, skipping build"
  else
    echo "changed, rebuilding"
    leeway build my-component:my-package
  fi`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		_, pkg, _, exists := getTarget(args, false)
		if !exists {
			os.Exit(ExitChangedError)
		}
		if pkg == nil {
			log.Error("changed requires a package, not a component")
			os.Exit(ExitChangedError)
		}

		version, err := pkg.Version()
		if err != nil {
			log.WithError(err).Error("cannot compute package version")
			os.Exit(ExitChangedError)
		}

		// Check local cache
		localCacheLoc := os.Getenv(leeway.EnvvarCacheDir)
		if localCacheLoc == "" {
			localCacheLoc = filepath.Join(os.TempDir(), "leeway", "cache")
		}
		localCache, err := local.NewFilesystemCache(localCacheLoc)
		if err != nil {
			log.WithError(err).Error("cannot set up local cache")
			os.Exit(ExitChangedError)
		}

		if _, found := localCache.Location(pkg); found {
			fmt.Printf("%s\t%s\tcached locally\n", pkg.FullName(), version)
			os.Exit(ExitChangedUnchanged)
		}

		// Check remote cache
		remoteCache := getRemoteCacheFromEnv()
		remote, err := remoteCache.ExistingPackages(context.Background(), []cache.Package{pkg})
		if err != nil {
			log.WithError(err).Error("cannot check remote cache")
			os.Exit(ExitChangedError)
		}

		if _, found := remote[pkg]; found {
			fmt.Printf("%s\t%s\tcached remotely\n", pkg.FullName(), version)
			os.Exit(ExitChangedUnchanged)
		}

		fmt.Printf("%s\t%s\tchanged\n", pkg.FullName(), version)
		os.Exit(ExitChangedNeedsRebuild)
	},
}

func init() {
	describeCmd.AddCommand(describeChangedCmd)
}
