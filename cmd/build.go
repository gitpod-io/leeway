package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/gitpod-io/leeway/pkg/leeway"
	"github.com/gitpod-io/leeway/pkg/leeway/cache"
	"github.com/gitpod-io/leeway/pkg/leeway/cache/local"
	"github.com/gitpod-io/leeway/pkg/leeway/cache/remote"
	"github.com/gitpod-io/leeway/pkg/leeway/telemetry"
	"github.com/gookit/color"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// CleanupFunc is a function that performs cleanup operations and must be deferred
type CleanupFunc func()

// buildCmd represents the build command
var buildCmd = &cobra.Command{
	Use:   "build [targetPackage]",
	Short: "Builds a package",
	Long: `Builds a package and all its dependencies.

Docker Export Mode:
  By default, Docker packages with 'image' configuration push directly to registries.
  Use --docker-export-to-cache to export images to cache instead (enables SLSA L3).

  The LEEWAY_DOCKER_EXPORT_TO_CACHE environment variable sets the default for the flag.

Examples:
  # Build with Docker export mode enabled (CLI flag)
  leeway build --docker-export-to-cache :myapp

  # Build with Docker export mode enabled (environment variable)
  LEEWAY_DOCKER_EXPORT_TO_CACHE=true leeway build :myapp

  # Disable export mode even if env var is set
  leeway build --docker-export-to-cache=false :myapp`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		err := build(cmd, args)
		if err != nil {
			log.Fatal(err)
		}
		return nil
	},
}

func build(cmd *cobra.Command, args []string) error {
	_, pkg, _, _ := getTarget(args, false)
	if pkg == nil {
		return errors.New("build needs a package")
	}
	opts, localCache, shutdown := getBuildOpts(cmd)
	defer shutdown()

	var (
		watch, _ = cmd.Flags().GetBool("watch")
		save, _  = cmd.Flags().GetString("save")
		serve, _ = cmd.Flags().GetString("serve")
	)
	if watch {
		err := leeway.Build(pkg, opts...)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithCancel(context.Background())
		if save != "" {
			err = saveBuildResult(ctx, save, localCache, pkg)
			if err != nil {
				return err
			}
		}
		if serve != "" {
			go serveBuildResult(ctx, serve, localCache, pkg)
		}

		evt, errs := leeway.WatchSources(context.Background(), append(pkg.GetTransitiveDependencies(), pkg), 2*time.Second)
		for {
			select {
			case <-evt:
				_, pkg, _, _ := getTarget(args, false)
				err := leeway.Build(pkg, opts...)
				if err == nil {
					cancel()
					ctx, cancel = context.WithCancel(context.Background())
					if save != "" {
						err = saveBuildResult(ctx, save, localCache, pkg)
						if err != nil {
							cancel()
							return err
						}
					}
					if serve != "" {
						go serveBuildResult(ctx, serve, localCache, pkg)
					}
				} else {
					log.Error(err)
				}
			case err = <-errs:
				cancel()
				return err
			}
		}
	}

	err := leeway.Build(pkg, opts...)
	if err != nil {
		return err
	}
	if save != "" {
		err = saveBuildResult(context.Background(), save, localCache, pkg)
		if err != nil {
			return err
		}
	}
	if serve != "" {
		serveBuildResult(context.Background(), serve, localCache, pkg)
	}
	return nil
}

func serveBuildResult(ctx context.Context, addr string, localCache cache.LocalCache, pkg *leeway.Package) {
	br, exists := localCache.Location(pkg)
	if !exists {
		log.Fatal("build result is not in local cache despite just being built. Something's wrong with the cache.")
	}

	tmp, err := os.MkdirTemp("", "leeway_serve")
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

func saveBuildResult(ctx context.Context, loc string, localCache cache.LocalCache, pkg *leeway.Package) error {
	br, exists := localCache.Location(pkg)
	if !exists {
		return errors.New("build result is not in local cache despite just being built. Something's wrong with the cache.")
	}

	fout, err := os.OpenFile(loc, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("cannot open result file for writing: %w", err)
	}
	fin, err := os.OpenFile(br, os.O_RDONLY, 0644)
	if err != nil {
		fout.Close()
		return fmt.Errorf("cannot copy build result: %w", err)
	}

	_, err = io.Copy(fout, fin)
	fout.Close()
	fin.Close()
	if err != nil {
		return fmt.Errorf("cannot copy build result: %w", err)
	}

	fmt.Printf("\n💾  saving build result to %s\n", color.Cyan.Render(loc))
	return nil
}

func init() {
	rootCmd.AddCommand(buildCmd)

	addBuildFlags(buildCmd)
	buildCmd.Flags().String("serve", "", "After a successful build this starts a webserver on the given address serving the build result (e.g. --serve localhost:8080)")
	buildCmd.Flags().String("save", "", "After a successful build this saves the build result as tar.gz file in the local filesystem (e.g. --save build-result.tar.gz)")
	buildCmd.Flags().Bool("watch", false, "Watch source files and re-build on change")

}

func addBuildFlags(cmd *cobra.Command) {
	cacheDefault := os.Getenv(EnvvarDefaultCacheLevel)
	if cacheDefault == "" {
		cacheDefault = "remote"
	}

	// Never use all CPUs, leave one free for other processes
	cpus := runtime.NumCPU()
	if cpus > 2 {
		cpus--
	}

	cmd.Flags().StringP("cache", "c", cacheDefault, "Configures the caching behaviour: none=no caching, local=local caching only, remote-pull=download from remote but never upload, remote-push=push to remote cache only but don't download, remote=use all configured caches")
	cmd.Flags().Bool("dry-run", false, "Don't actually build but stop after showing what would need to be built")
	cmd.Flags().String("dump-plan", "", "Writes the build plan as JSON to a file. Use \"-\" to write the build plan to stderr.")
	cmd.Flags().Bool("werft", false, "Produce werft CI compatible output")
	cmd.Flags().Bool("dont-test", false, "Disable all package-level tests (defaults to false)")
	cmd.Flags().Bool("dont-compress", false, "Disable compression of build artifacts (defaults to false)")
	cmd.Flags().Bool("jailed-execution", false, "Run all build commands using runc (defaults to false)")
	cmd.Flags().UintP("max-concurrent-tasks", "j", uint(cpus), "Limit the number of max concurrent build tasks - set to 0 to disable the limit")
	cmd.Flags().String("coverage-output-path", "", "Output path where test coverage file will be copied after running tests")
	cmd.Flags().Bool("disable-coverage", false, "Disable test coverage collection (defaults to false)")
	cmd.Flags().StringToString("docker-build-options", nil, "Options passed to all 'docker build' commands")
	cmd.Flags().Bool("slsa-cache-verification", false, "Enable SLSA verification for cached artifacts")
	cmd.Flags().String("slsa-source-uri", "", "Expected source URI for SLSA verification (required when verification enabled)")
	cmd.Flags().Bool("slsa-require-attestation", false, "Require SLSA attestations (missing/invalid → build locally)")
	cmd.Flags().Bool("in-flight-checksums", false, "Enable checksumming of cache artifacts to prevent TOCTU attacks")
	cmd.Flags().String("report", "", "Generate a HTML report after the build has finished. (e.g. --report myreport.html)")
	cmd.Flags().String("report-segment", os.Getenv(EnvvarSegmentKey), "Report build events to segment using the segment key (defaults to $LEEWAY_SEGMENT_KEY)")
	cmd.Flags().Bool("report-github", os.Getenv("GITHUB_OUTPUT") != "", "Report package build success/failure to GitHub Actions using the GITHUB_OUTPUT environment variable")
	cmd.Flags().Bool("fixed-build-dir", true, "Use a fixed build directory for each package, instead of based on the package version, to better utilize caches based on absolute paths (defaults to true)")
	cmd.Flags().Bool("docker-export-to-cache", false, "Export Docker images to cache instead of pushing directly (enables SLSA L3 compliance)")
	cmd.Flags().String("otel-endpoint", os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"), "OpenTelemetry OTLP endpoint URL for tracing (defaults to $OTEL_EXPORTER_OTLP_ENDPOINT)")
	cmd.Flags().Bool("otel-insecure", os.Getenv("OTEL_EXPORTER_OTLP_INSECURE") == "true", "Disable TLS for OTLP endpoint (for local development only, defaults to $OTEL_EXPORTER_OTLP_INSECURE)")
	cmd.Flags().String("trace-parent", os.Getenv("TRACEPARENT"), "W3C Trace Context traceparent header for distributed tracing (defaults to $TRACEPARENT)")
	cmd.Flags().String("trace-state", os.Getenv("TRACESTATE"), "W3C Trace Context tracestate header for distributed tracing (defaults to $TRACESTATE)")
}

func getBuildOpts(cmd *cobra.Command) ([]leeway.BuildOption, cache.LocalCache, CleanupFunc) {
	// Track if user explicitly set LEEWAY_DOCKER_EXPORT_TO_CACHE before workspace loading.
	// This allows us to distinguish:
	// - User set explicitly: High priority (overrides package config)
	// - Workspace auto-set: Low priority (package config can override)
	dockerExportEnvSet := false
	dockerExportEnvValue := false
	if envVal := os.Getenv(EnvvarDockerExportToCache); envVal != "" {
		dockerExportEnvSet = true
		dockerExportEnvValue = (envVal == "true" || envVal == "1")
		log.WithField("value", envVal).Debug("User explicitly set LEEWAY_DOCKER_EXPORT_TO_CACHE before workspace loading")
	}

	cm, _ := cmd.Flags().GetString("cache")
	log.WithField("cacheMode", cm).Debug("configuring caches")
	cacheLevel := leeway.CacheLevel(cm)

	remoteCache := getRemoteCache(cmd)
	switch cacheLevel {
	case leeway.CacheNone, leeway.CacheLocal:
		remoteCache = remote.NewNoRemoteCache()
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
		localCacheLoc, err = os.MkdirTemp("", "leeway")
		if err != nil {
			log.Fatal(err)
		}
	} else {
		localCacheLoc = os.Getenv(leeway.EnvvarCacheDir)
		if localCacheLoc == "" {
			localCacheLoc = filepath.Join(os.TempDir(), "leeway", "cache")
		}
	}
	// Ensure cache directory exists with proper permissions
	if err := os.MkdirAll(localCacheLoc, 0755); err != nil {
		log.WithError(err).Fatal("failed to create cache directory")
	}
	log.WithField("location", localCacheLoc).Debug("set up local cache")
	localCache, err := local.NewFilesystemCache(localCacheLoc)
	if err != nil {
		log.Fatal(err)
	}

	dryrun, err := cmd.Flags().GetBool("dry-run")
	if err != nil {
		log.Fatal(err)
	}

	log.Debugf("this is leeway version %s", leeway.Version)

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

	var reporter leeway.CompositeReporter
	reporter = append(reporter, leeway.NewConsoleReporter())

	if werftlog, err := cmd.Flags().GetBool("werft"); err != nil {
		log.Fatal(err)
	} else if werftlog {
		reporter = append(reporter, leeway.NewWerftReporter())
	}
	if report, err := cmd.Flags().GetString("report"); err != nil {
		log.Fatal(err)
	} else if report != "" {
		reporter = append(reporter, leeway.NewHTMLReporter(report))
	}
	if segmentkey, err := cmd.Flags().GetString("report-segment"); err != nil {
		log.Fatal(err)
	} else if segmentkey != "" {
		reporter = append(reporter, leeway.NewSegmentReporter(segmentkey))
	}
	if github, err := cmd.Flags().GetBool("report-github"); err != nil {
		log.Fatal(err)
	} else if github {
		reporter = append(reporter, leeway.NewGitHubReporter())
	}

	// Initialize OpenTelemetry reporter if endpoint is configured
	var tracerProvider *sdktrace.TracerProvider
	var otelShutdown func()
	if otelEndpoint, err := cmd.Flags().GetString("otel-endpoint"); err != nil {
		log.Fatal(err)
	} else if otelEndpoint != "" {
		// Set leeway version for telemetry
		telemetry.SetLeewayVersion(leeway.Version)

		// Get insecure flag
		otelInsecure, err := cmd.Flags().GetBool("otel-insecure")
		if err != nil {
			log.Fatal(err)
		}

		// Initialize tracer with the provided endpoint and TLS configuration
		tp, err := telemetry.InitTracer(context.Background(), otelEndpoint, otelInsecure)
		if err != nil {
			log.WithError(err).Warn("failed to initialize OpenTelemetry tracer")
		} else {
			tracerProvider = tp

			// Parse trace context if provided
			traceParent, _ := cmd.Flags().GetString("trace-parent")
			traceState, _ := cmd.Flags().GetString("trace-state")

			parentCtx := context.Background()
			if traceParent != "" {
				if err := telemetry.ValidateTraceParent(traceParent); err != nil {
					log.WithError(err).Warn("invalid trace-parent format")
				} else {
					ctx, err := telemetry.ParseTraceContext(traceParent, traceState)
					if err != nil {
						log.WithError(err).Warn("failed to parse trace context")
					} else {
						parentCtx = ctx
					}
				}
			}

			// Create OTel reporter
			tracer := otel.Tracer("leeway")
			reporter = append(reporter, leeway.NewOTelReporter(tracer, parentCtx))

			// Create shutdown function
			otelShutdown = func() {
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if err := telemetry.Shutdown(shutdownCtx, tracerProvider); err != nil {
					log.WithError(err).Warn("failed to shutdown tracer provider")
				}
			}
		}
	}

	dontTest, err := cmd.Flags().GetBool("dont-test")
	if err != nil {
		log.Fatal(err)
	}

	maxConcurrentTasks, err := cmd.Flags().GetUint("max-concurrent-tasks")
	if err != nil {
		log.Fatal(err)
	}

	coverageOutputPath, _ := cmd.Flags().GetString("coverage-output-path")
	if coverageOutputPath != "" {
		_ = os.MkdirAll(coverageOutputPath, 0644)
	}

	disableCoverage, _ := cmd.Flags().GetBool("disable-coverage")

	var dockerBuildOptions leeway.DockerBuildOptions
	dockerBuildOptions, err = cmd.Flags().GetStringToString("docker-build-options")
	if err != nil {
		log.Fatal(err)
	}

	jailedExecution, err := cmd.Flags().GetBool("jailed-execution")
	if err != nil {
		log.Fatal(err)
	}

	dontCompress, err := cmd.Flags().GetBool("dont-compress")
	if err != nil {
		log.Fatal(err)
	}

	fixedBuildDir, err := cmd.Flags().GetBool("fixed-build-dir")
	if err != nil {
		log.Fatal(err)
	}

	// Get in-flight checksums setting (env var as default, CLI flag overrides)
	inFlightChecksumsDefault := os.Getenv(EnvvarEnableInFlightChecksums) == "true"
	inFlightChecksums, err := cmd.Flags().GetBool("in-flight-checksums")
	if err != nil {
		log.Fatal(err)
	}
	// If flag wasn't explicitly set, use environment variable
	if !cmd.Flags().Changed("in-flight-checksums") {
		inFlightChecksums = inFlightChecksumsDefault
	}

	// Get docker export to cache setting - CLI flag takes highest precedence
	dockerExportToCache := false
	dockerExportSet := false

	if cmd.Flags().Changed("docker-export-to-cache") {
		// Flag was explicitly set by user - this takes precedence over everything
		dockerExportToCache, err = cmd.Flags().GetBool("docker-export-to-cache")
		if err != nil {
			log.Fatal(err)
		}
		dockerExportSet = true
	}

	// Create a no-op shutdown function if otelShutdown is nil
	if otelShutdown == nil {
		otelShutdown = func() {}
	}

	return []leeway.BuildOption{
		leeway.WithLocalCache(localCache),
		leeway.WithRemoteCache(remoteCache),
		leeway.WithDryRun(dryrun),
		leeway.WithBuildPlan(planOutlet),
		leeway.WithReporter(reporter),
		leeway.WithDontTest(dontTest),
		leeway.WithMaxConcurrentTasks(int64(maxConcurrentTasks)),
		leeway.WithCoverageOutputPath(coverageOutputPath),
		leeway.WithDockerBuildOptions(&dockerBuildOptions),
		leeway.WithJailedExecution(jailedExecution),
		leeway.WithCompressionDisabled(dontCompress),
		leeway.WithFixedBuildDir(fixedBuildDir),
		leeway.WithDisableCoverage(disableCoverage),
		leeway.WithInFlightChecksums(inFlightChecksums),
		leeway.WithDockerExportToCache(dockerExportToCache, dockerExportSet),
		leeway.WithDockerExportEnv(dockerExportEnvValue, dockerExportEnvSet),
	}, localCache, otelShutdown
}

type pushOnlyRemoteCache struct {
	C cache.RemoteCache
}

func (c *pushOnlyRemoteCache) ExistingPackages(ctx context.Context, pkgs []cache.Package) (map[cache.Package]struct{}, error) {
	return c.C.ExistingPackages(ctx, pkgs)
}

func (c *pushOnlyRemoteCache) Download(ctx context.Context, dst cache.LocalCache, pkgs []cache.Package) map[string]cache.DownloadResult {
	// Push-only cache doesn't download anything
	results := make(map[string]cache.DownloadResult)
	for _, pkg := range pkgs {
		results[pkg.FullName()] = cache.DownloadResult{Status: cache.DownloadStatusNotFound}
	}
	return results
}

func (c *pushOnlyRemoteCache) Upload(ctx context.Context, src cache.LocalCache, pkgs []cache.Package) error {
	return c.C.Upload(ctx, src, pkgs)
}

func (c *pushOnlyRemoteCache) UploadFile(ctx context.Context, filePath string, key string) error {
	return c.C.UploadFile(ctx, filePath, key)
}

func (c *pushOnlyRemoteCache) HasFile(ctx context.Context, key string) (bool, error) {
	return c.C.HasFile(ctx, key)
}

type pullOnlyRemoteCache struct {
	C cache.RemoteCache
}

func (c *pullOnlyRemoteCache) ExistingPackages(ctx context.Context, pkgs []cache.Package) (map[cache.Package]struct{}, error) {
	return c.C.ExistingPackages(ctx, pkgs)
}

func (c *pullOnlyRemoteCache) Download(ctx context.Context, dst cache.LocalCache, pkgs []cache.Package) map[string]cache.DownloadResult {
	return c.C.Download(ctx, dst, pkgs)
}

func (c *pullOnlyRemoteCache) Upload(ctx context.Context, src cache.LocalCache, pkgs []cache.Package) error {
	return nil
}

func (c *pullOnlyRemoteCache) UploadFile(ctx context.Context, filePath string, key string) error {
	return nil
}

func (c *pullOnlyRemoteCache) HasFile(ctx context.Context, key string) (bool, error) {
	return c.C.HasFile(ctx, key)
}

func getRemoteCacheFromEnv() cache.RemoteCache {
	return getRemoteCache(nil)
}

// parseSLSAConfig parses SLSA configuration from CLI flags and environment variables
func parseSLSAConfig(cmd *cobra.Command) (*cache.SLSAConfig, error) {
	// Get SLSA verification settings from environment variables (defaults)
	slsaVerificationEnabled := os.Getenv(EnvvarSLSACacheVerification) == "true"
	slsaSourceURI := os.Getenv(EnvvarSLSASourceURI)
	requireAttestation := os.Getenv(EnvvarSLSARequireAttestation) == "true"

	// CLI flags override environment variables (if cmd is provided)
	if cmd != nil {
		if cmd.Flags().Changed("slsa-cache-verification") {
			if flagValue, err := cmd.Flags().GetBool("slsa-cache-verification"); err == nil {
				slsaVerificationEnabled = flagValue
			}
		}
		if cmd.Flags().Changed("slsa-source-uri") {
			if flagValue, err := cmd.Flags().GetString("slsa-source-uri"); err == nil && flagValue != "" {
				slsaSourceURI = flagValue
			}
		}
		if cmd.Flags().Changed("slsa-require-attestation") {
			if flagValue, err := cmd.Flags().GetBool("slsa-require-attestation"); err == nil {
				requireAttestation = flagValue
			}
		}
	}

	// If verification is disabled, return nil
	if !slsaVerificationEnabled {
		return nil, nil
	}

	// Validation: source URI is required when verification is enabled
	if slsaSourceURI == "" {
		return nil, fmt.Errorf("--slsa-source-uri is required when using --slsa-cache-verification")
	}

	return &cache.SLSAConfig{
		Verification:       true,
		SourceURI:          slsaSourceURI,
		TrustedRoots:       []string{"https://fulcio.sigstore.dev"},
		RequireAttestation: requireAttestation,
	}, nil
}

func getRemoteCache(cmd *cobra.Command) cache.RemoteCache {
	remoteCacheBucket := os.Getenv(EnvvarRemoteCacheBucket)
	remoteStorage := os.Getenv(EnvvarRemoteCacheStorage)

	// Parse SLSA configuration
	slsaConfig, err := parseSLSAConfig(cmd)
	if err != nil {
		log.Fatalf("SLSA configuration error: %v", err)
	}

	if remoteCacheBucket != "" {
		config := &cache.RemoteConfig{
			BucketName: remoteCacheBucket,
			SLSA:       slsaConfig,
		}

		switch remoteStorage {
		case "GCP":
			if slsaConfig != nil && slsaConfig.Verification {
				log.Warn("SLSA verification not yet supported with GCP storage, verification disabled")
				config.SLSA = nil
			}
			return remote.NewGSUtilCache(config)
		case "AWS":
			// AWS supports SLSA verification
			rc, err := remote.NewS3Cache(config)
			if err != nil {
				log.Fatalf("cannot access remote S3 cache: %v", err)
			}
			return rc
		default:
			if slsaConfig != nil && slsaConfig.Verification {
				log.Warn("SLSA verification not yet supported with GCP storage, verification disabled")
				config.SLSA = nil
			}
			return remote.NewGSUtilCache(config)
		}
	}

	return remote.NewNoRemoteCache()
}
