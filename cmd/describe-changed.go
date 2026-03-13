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

// describeChangedCmd checks whether a package has changed by looking up its
// current version hash in the local and remote caches. If the version exists
// in either cache the package is unchanged (exit 0); otherwise it has changed
// and needs a rebuild (exit 1).
var describeChangedCmd = &cobra.Command{
	Use:   "changed <package>",
	Short: "Checks whether a package needs to be rebuilt by consulting the cache",
	Long: `Computes the version hash of a package and checks whether a build artifact
for that version already exists in the local or remote cache.

Exits with code 0 if the package is cached (unchanged), or code 1 if it is not
(changed / needs rebuild). This is useful for CI branching decisions:

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
			return
		}
		if pkg == nil {
			log.Fatal("changed requires a package, not a component")
		}

		version, err := pkg.Version()
		if err != nil {
			log.WithError(err).Fatal("cannot compute package version")
		}

		// Check local cache
		localCacheLoc := os.Getenv(leeway.EnvvarCacheDir)
		if localCacheLoc == "" {
			localCacheLoc = filepath.Join(os.TempDir(), "leeway", "cache")
		}
		localCache, err := local.NewFilesystemCache(localCacheLoc)
		if err != nil {
			log.WithError(err).Fatal("cannot set up local cache")
		}

		if _, found := localCache.Location(pkg); found {
			fmt.Printf("%s\t%s\tcached locally\n", pkg.FullName(), version)
			os.Exit(0)
		}

		// Check remote cache
		remoteCache := getRemoteCacheFromEnv()
		remote, err := remoteCache.ExistingPackages(context.Background(), []cache.Package{pkg})
		if err != nil {
			log.WithError(err).Warn("cannot check remote cache, assuming changed")
			fmt.Printf("%s\t%s\tchanged\n", pkg.FullName(), version)
			os.Exit(1)
		}

		if _, found := remote[pkg]; found {
			fmt.Printf("%s\t%s\tcached remotely\n", pkg.FullName(), version)
			os.Exit(0)
		}

		fmt.Printf("%s\t%s\tchanged\n", pkg.FullName(), version)
		os.Exit(1)
	},
}

func init() {
	describeCmd.AddCommand(describeChangedCmd)
}
