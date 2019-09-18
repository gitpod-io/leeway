package cmd

import (
	"fmt"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/typefox/leeway/pkg/leeway"
	"golang.org/x/xerrors"
)

const (
	// EnvvarWorkspaceRoot names the environment variable we check for the workspace root path
	EnvvarWorkspaceRoot = "LEEWAY_WORKSPACE_ROOT"

	// EnvvarRemoteCacheBucket configures a GCP bucket name. This enables the use of GSUtilRemoteStorage
	EnvvarRemoteCacheBucket = "LEEWAY_REMOTE_CACHE_BUCKET"
)

var (
	workspace string
	buildArgs []string
	verbose   bool
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "leeway",
	Short: "A caching meta-build system",
	Long: `Leeway is a heavily caching build system for Go, Typescript and Docker projects. It knows three core concepts:
  Workspace: the workspace is the root of all operations. All component names are relative to this path. No relevant
             file must be placed outside the workspace. The workspace root is marked with a WORKSPACE file.
  Component: a component is single piece of standalone software. Every folder in the workspace which contains a BUILD file
             is a component. Components are identifed by their path relative to the workspace root.
  Package:   packages are the buildable unit in leeway. Every component can define multiple packages in its build file.
             Packages are identified by their name prefixed with the component name, e.g. some-component:pkg

Configuration
Leeway is configured exclusively through the WORKSPACE/BUILD files and environment variables. The following environment
variables have an effect on leeway:
  LEEWAY_WORKSPACE_ROOT       Contains the path where to look for a WORKSPACE file. Can also be set using --workspace.
  LEEWAY_REMOTE_CACHE_BUCKET  Enables remote caching using GCP buckets. Set this variable to the bucket name used for caching.
                              When this variable is set, leeway expects "gsutil" in the path configured and authenticated so
							  that it can work with the bucket.
  LEEWAY_CACHE_DIR            Location of the local build cache. The directory does not have to exist yet.
  LEEWAY_BUILD_DIR            Working location of leeway (i.e. where the actual builds happen). This location will see heavy I/O
                              which makes it advisable to place this on a fast SSD or in RAM.
`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		if verbose {
			log.SetLevel(log.DebugLevel)
		}
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	workspaceRoot := os.Getenv(EnvvarWorkspaceRoot)
	if workspaceRoot == "" {
		workspaceRoot = "."
	}

	rootCmd.PersistentFlags().StringVarP(&workspace, "workspace", "w", workspaceRoot, "Workspace root")
	rootCmd.PersistentFlags().StringArrayVarP(&buildArgs, "build-arg", "D", []string{}, "pass arguments to BUILD files")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "enables verbose logging")
}

func getWorkspace() (leeway.Workspace, error) {
	args, err := getBuildArgs()
	if err != nil {
		return leeway.Workspace{}, err
	}

	return leeway.FindWorkspace(workspace, args)
}

func getBuildArgs() (leeway.Arguments, error) {
	if len(buildArgs) == 0 {
		return nil, nil
	}

	res := make(leeway.Arguments)
	for _, arg := range buildArgs {
		segs := strings.Split(arg, "=")
		if len(segs) < 2 {
			return nil, xerrors.Errorf("invalid build argument (format is key=value): %s", arg)
		}
		res[segs[0]] = strings.Join(segs[1:], "=")
	}
	return res, nil
}

func getRemoteCache() leeway.RemoteCache {
	remoteCacheBucket := os.Getenv(EnvvarRemoteCacheBucket)
	if remoteCacheBucket != "" {
		return leeway.GSUtilRemoteCache{
			BucketName: remoteCacheBucket,
		}
	}

	return leeway.NoRemoteCache{}
}
