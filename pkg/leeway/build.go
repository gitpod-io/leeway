package leeway

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/common"
	log "github.com/sirupsen/logrus"
	"golang.org/x/mod/modfile"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/semaphore"
	"golang.org/x/xerrors"
	"gopkg.in/yaml.v3"

	"github.com/gitpod-io/leeway/pkg/leeway/cache"
	"github.com/gitpod-io/leeway/pkg/leeway/cache/remote"
)

// PkgNotBuiltErr is used when a package's dependency hasn't been built yet
type PkgNotBuiltErr struct {
	Package *Package
}

func (p PkgNotBuiltErr) Error() string {
	return fmt.Sprintf("package \"%s\" is not built", p.Package.FullName())
}

// PackageBuildStatus denotes the status of a package during build
type PackageBuildStatus string

const (
	// PackageNotBuiltYet means that the package has not been built yet
	PackageNotBuiltYet PackageBuildStatus = "not-built-yet"
	// PackageBuilding means we're building this package at the moment
	PackageBuilding PackageBuildStatus = "building"
	// PackageBuilt means the package has been built and exists in the local cache already
	PackageBuilt PackageBuildStatus = "built-locally"
	// PackageDownloaded means the package was downloaded from the remote cache as part of this build
	PackageDownloaded PackageBuildStatus = "downloaded"
	// PackageInRemoteCache means the package has been built but currently only exists in the remote cache
	PackageInRemoteCache PackageBuildStatus = "built-remotely"
)

type buildContext struct {
	buildOptions
	buildDir   string
	buildID    string
	leewayHash string

	mu                 sync.Mutex
	newlyBuiltPackages map[string]*Package

	pkgLockCond *sync.Cond
	pkgLocks    map[string]struct{}
	buildLimit  *semaphore.Weighted
}

const (
	// EnvvarCacheDir names the environment variable we take the cache dir location from
	EnvvarCacheDir = "LEEWAY_CACHE_DIR"

	// EnvvarBuildDir names the environment variable we take the build dir location from
	EnvvarBuildDir = "LEEWAY_BUILD_DIR"

	// EnvvarYarnMutex configures the mutex flag leeway will pass to yarn.
	// See https://yarnpkg.com/lang/en/docs/cli/#toc-concurrency-and-mutex for possible values.
	// Defaults to "network".
	EnvvarYarnMutex = "LEEWAY_YARN_MUTEX"

	// dockerImageNamesFiles is the name of the file store in poushed Docker build artifacts
	// which contains the names of the Docker images we just pushed
	dockerImageNamesFiles = "imgnames.txt"

	// dockerMetadataFile is the name of the file we YAML seralize the DockerPkgConfig.Metadata field to
	// when building Docker images. We use this mechanism to produce the version manifest as part of the Gitpod build.
	dockerMetadataFile = "metadata.yaml"
)

var (
	compressor = "gzip"
)

func init() {
	pigz, err := exec.LookPath("pigz")
	if err == nil {
		compressor = pigz
	}
}

// buildProcessVersions contain the current version of the respective build processes.
// Increment this value if you change any of the build procedures.
var buildProcessVersions = map[PackageType]int{
	YarnPackage:    7,
	GoPackage:      2,
	DockerPackage:  3,
	GenericPackage: 1,
}

func newBuildContext(options buildOptions) (ctx *buildContext, err error) {
	if options.context != nil {
		return options.context, nil
	}

	buildDir := os.Getenv(EnvvarBuildDir)
	if buildDir == "" {
		buildDir = filepath.Join(os.TempDir(), "leeway", "build")
	}

	// Ensure cache directory exists with proper permissions
	if err := os.MkdirAll(buildDir, 0755); err != nil {
		log.WithError(err).Fatal("failed to create build directory")
	}

	var buildLimit *semaphore.Weighted
	if options.MaxConcurrentTasks > 0 {
		buildLimit = semaphore.NewWeighted(options.MaxConcurrentTasks)
	}

	b := make([]byte, 4)
	_, err = rand.Read(b)
	if err != nil {
		return nil, xerrors.Errorf("cannot produce random build ID: %w", err)
	}
	buildID := fmt.Sprintf("%d-%x", time.Now().UnixNano(), b)

	selfFN, err := os.Executable()
	if err != nil {
		return nil, xerrors.Errorf("cannot compute hash of myself: %w", err)
	}
	self, err := os.Open(selfFN)
	if err != nil {
		return nil, xerrors.Errorf("cannot compute hash of myself: %w", err)
	}
	defer self.Close()
	leewayHash := sha256.New()
	_, err = io.Copy(leewayHash, self)
	if err != nil {
		return nil, xerrors.Errorf("cannot compute hash of myself: %w", err)
	}

	ctx = &buildContext{
		buildOptions:       options,
		buildDir:           buildDir,
		buildID:            buildID,
		newlyBuiltPackages: make(map[string]*Package),
		pkgLockCond:        sync.NewCond(&sync.Mutex{}),
		pkgLocks:           make(map[string]struct{}),
		buildLimit:         buildLimit,
		leewayHash:         hex.EncodeToString(leewayHash.Sum(nil)),
	}

	err = os.MkdirAll(buildDir, 0755)
	if err != nil {
		return nil, err
	}
	return ctx, nil
}

func (c *buildContext) BuildDir() string {
	return c.buildDir
}

// ObtainBuildLock attempts to obtain the exclusive permission to build a package.
// If someone else is already building this package, this function blocks until that's done.
// When the returned haveLock is true, the caller is expected to build the package and upon finishing to call ReleaseBuildLock.
// If haveLock is false, no build or lock release must be performed.
func (c *buildContext) ObtainBuildLock(p *Package) (haveLock bool) {
	key := p.FullName()

	c.pkgLockCond.L.Lock()
	if _, ok := c.pkgLocks[key]; !ok {
		// no one's holding the lock at the moment
		c.pkgLocks[key] = struct{}{}
		c.pkgLockCond.L.Unlock()
		return true
	}

	// someone else has the lock - wait for that to finish
	for _, ok := c.pkgLocks[key]; ok; _, ok = c.pkgLocks[key] {
		log.WithField("package", key).Debug("waiting for package to be built")
		c.pkgLockCond.Wait()
	}
	c.pkgLockCond.L.Unlock()
	return false
}

// ReleaseBuildLock signals the end of a package build
func (c *buildContext) ReleaseBuildLock(p *Package) {
	key := p.FullName()

	c.pkgLockCond.L.Lock()
	delete(c.pkgLocks, key)
	c.pkgLockCond.Broadcast()
	c.pkgLockCond.L.Unlock()
}

// LimitConcurrentBuilds blocks until there is a free slot to acutally build.
// This function effectively limits the number of concurrent builds.
// We do not do this limiting as part of the build lock, because that would block
// dependencies from getting build. Hence, it's important to call this function
// once all dependencies have been built.
//
// All callers must release the build limiter using ReleaseConcurrentBuild()
func (c *buildContext) LimitConcurrentBuilds() {
	if c.buildLimit == nil {
		return
	}

	_ = c.buildLimit.Acquire(context.Background(), 1)
}

// ReleaseConcurrentBuild releases a previously acquired concurrent build limiting token
func (c *buildContext) ReleaseConcurrentBuild() {
	if c.buildLimit == nil {
		return
	}

	c.buildLimit.Release(1)
}

// RegisterNewlyBuilt adds a new package to the list of packages built in this context
func (c *buildContext) RegisterNewlyBuilt(p *Package) error {
	ver, err := p.Version()
	if err != nil {
		return err
	}

	c.mu.Lock()
	c.newlyBuiltPackages[ver] = p
	c.mu.Unlock()
	return nil
}

func (c *buildContext) GetNewPackagesForCache() []*Package {
	res := make([]*Package, 0, len(c.newlyBuiltPackages))
	c.mu.Lock()
	for _, pkg := range c.newlyBuiltPackages {
		if pkg.Ephemeral {
			continue
		}
		res = append(res, pkg)
	}
	c.mu.Unlock()
	return res
}

type buildOptions struct {
	LocalCache             cache.LocalCache
	RemoteCache            cache.RemoteCache
	AdditionalRemoteCaches []cache.RemoteCache
	Reporter               Reporter
	DryRun                 bool
	BuildPlan              io.Writer
	DontCompress           bool
	DontTest               bool
	MaxConcurrentTasks     int64
	CoverageOutputPath     string
	DockerBuildOptions     *DockerBuildOptions
	JailedExecution        bool

	context *buildContext
}

// DockerBuildOptions are options passed to "docker build"
type DockerBuildOptions map[string]string

// BuildOption configures the build behaviour
type BuildOption func(*buildOptions) error

// WithLocalCache configures the local cache
func WithLocalCache(cache cache.LocalCache) BuildOption {
	return func(opts *buildOptions) error {
		opts.LocalCache = cache
		return nil
	}
}

// WithRemoteCache configures the remote cache
func WithRemoteCache(cache cache.RemoteCache) BuildOption {
	return func(opts *buildOptions) error {
		opts.RemoteCache = cache
		return nil
	}
}

// WithReporter sets the reporter which is notified about the build progress
func WithReporter(reporter Reporter) BuildOption {
	return func(opts *buildOptions) error {
		opts.Reporter = reporter
		return nil
	}
}

// WithDryRun marks this build as dry run
func WithDryRun(dryrun bool) BuildOption {
	return func(opts *buildOptions) error {
		opts.DryRun = dryrun
		return nil
	}
}

// WithBuildPlan writes the build plan as JSON to the writer
func WithBuildPlan(out io.Writer) BuildOption {
	return func(opts *buildOptions) error {
		opts.BuildPlan = out
		return nil
	}
}

// WithDontTest disables package-level tests
func WithDontTest(dontTest bool) BuildOption {
	return func(opts *buildOptions) error {
		opts.DontTest = dontTest
		return nil
	}
}

// WithMaxConcurrentTasks limits the number of concurrent tasks during the build
func WithMaxConcurrentTasks(n int64) BuildOption {
	return func(opts *buildOptions) error {
		if n < 0 {
			return xerrors.Errorf("maxConcurrentTasks must be >= 0")
		}
		opts.MaxConcurrentTasks = n

		return nil
	}
}

// WithCoverageOutputPath configures coverage output directory
func WithCoverageOutputPath(output string) BuildOption {
	return func(opts *buildOptions) error {
		opts.CoverageOutputPath = output
		return nil
	}
}

// WithDockerBuildOptions are passed to "docker build"
func WithDockerBuildOptions(dockerBuildOpts *DockerBuildOptions) BuildOption {
	return func(opts *buildOptions) error {
		opts.DockerBuildOptions = dockerBuildOpts
		return nil
	}
}

// WithJailedExecution runs all commands in a runc jail
func WithJailedExecution(jailedExecution bool) BuildOption {
	return func(opts *buildOptions) error {
		opts.JailedExecution = jailedExecution
		return nil
	}
}

func WithCompressionDisabled(dontCompress bool) BuildOption {
	return func(opts *buildOptions) error {
		opts.DontCompress = dontCompress
		return nil
	}
}

func withBuildContext(ctx *buildContext) BuildOption {
	return func(opts *buildOptions) error {
		opts.context = ctx
		opts.LocalCache = opts.context.LocalCache
		return nil
	}
}

func applyBuildOpts(opts []BuildOption) (buildOptions, error) {
	options := buildOptions{
		Reporter:    NewConsoleReporter(),
		RemoteCache: remote.NewNoRemoteCache(),
		DryRun:      false,
	}
	for _, opt := range opts {
		err := opt(&options)
		if err != nil {
			return options, err
		}
	}
	if options.LocalCache == nil {
		return options, xerrors.Errorf("cannot build without local cache. Use WithLocalCache() to configure one")
	}

	return options, nil
}

// Build builds the packages in the order they're given. It's the callers responsibility to ensure the dependencies are built
// in order.
func Build(pkg *Package, opts ...BuildOption) (err error) {
	options, err := applyBuildOpts(opts)
	if err != nil {
		return err
	}
	ctx, err := newBuildContext(options)
	if err != nil {
		return err
	}

	err = checkForCpCompatibility()
	if err != nil {
		return err
	}

	requirements := pkg.GetTransitiveDependencies()
	allpkg := append(requirements, pkg)

	pkgsInLocalCache := make(map[*Package]struct{})
	var pkgsToCheckRemoteCache []*Package
	for _, p := range allpkg {
		if p.Ephemeral {
			// Ephemeral packages will always need to be build
			continue
		}

		if _, exists := ctx.LocalCache.Location(p); exists {
			pkgsInLocalCache[p] = struct{}{}
			continue
		}

		pkgsToCheckRemoteCache = append(pkgsToCheckRemoteCache, p)
	}

	pkgsToCheckRemoteCacheCache := toPackageInterface(pkgsToCheckRemoteCache)
	pkgsInRemoteCache, err := ctx.RemoteCache.ExistingPackages(context.Background(), pkgsToCheckRemoteCacheCache)
	if err != nil {
		return err
	}

	pkgsInRemoteCacheMap := toPackageMap(pkgsInRemoteCache)

	pkgsWillBeDownloaded := make(map[*Package]struct{})
	pkg.packagesToDownload(pkgsInLocalCache, pkgsInRemoteCacheMap, pkgsWillBeDownloaded)

	pkgstatus := make(map[*Package]PackageBuildStatus)
	unresolvedArgs := make(map[string][]string)
	for _, dep := range allpkg {
		_, existsInLocalCache := pkgsInLocalCache[dep]
		_, existsInRemoteCache := pkgsInRemoteCache[dep]
		_, willBeDownloaded := pkgsWillBeDownloaded[dep]
		if dep.Ephemeral {
			// ephemeral packages are never built at the beginning of a build
			pkgstatus[dep] = PackageNotBuiltYet
		} else if existsInLocalCache {
			pkgstatus[dep] = PackageBuilt
		} else if willBeDownloaded {
			pkgstatus[dep] = PackageDownloaded
		} else if existsInRemoteCache {
			pkgstatus[dep] = PackageInRemoteCache
		} else {
			pkgstatus[dep] = PackageNotBuiltYet
		}

		if pkgstatus[dep] != PackageNotBuiltYet {
			continue
		}

		ua, err := FindUnresolvedArguments(dep)
		if err != nil {
			return err
		}
		for _, arg := range ua {
			pkgs, ok := unresolvedArgs[arg]
			if !ok {
				pkgs = []string{}
			}
			pkgs = append(pkgs, dep.FullName())
			unresolvedArgs[arg] = pkgs
		}
	}

	pkgsToDownload := make([]*Package, 0, len(pkgsWillBeDownloaded))
	for p := range pkgsWillBeDownloaded {
		pkgsToDownload = append(pkgsToDownload, p)
	}

	// Convert []*Package to []cache.Package
	pkgsToDownloadCache := make([]cache.Package, len(pkgsToDownload))
	for i, p := range pkgsToDownload {
		pkgsToDownloadCache[i] = p
	}

	err = ctx.RemoteCache.Download(context.Background(), ctx.LocalCache, pkgsToDownloadCache)
	if err != nil {
		return err
	}

	ctx.Reporter.BuildStarted(pkg, pkgstatus)
	defer func(err *error) {
		ctx.Reporter.BuildFinished(pkg, *err)
	}(&err)

	if len(unresolvedArgs) != 0 {
		var msg string
		for arg, pkgs := range unresolvedArgs {
			cleanArg := strings.TrimSuffix(strings.TrimPrefix(arg, "${"), "}")
			msg += fmt.Sprintf("cannot build with unresolved argument \"%s\": use -D%s=value to set the argument\n\t%s appears in %s\n\n", arg, cleanArg, arg, strings.Join(pkgs, ", "))
		}
		return xerrors.Errorf(msg)
	}

	if ctx.BuildPlan != nil {
		log.Debug("writing build plan")
		err = writeBuildPlan(ctx.BuildPlan, pkg, pkgstatus)
		if err != nil {
			return err
		}
	}

	if ctx.DryRun {
		// This is a dry-run. We've prepared everything for the build but do not execute the build itself.
		return nil
	}

	buildErr := pkg.build(ctx)

	pkgsToUpload := ctx.GetNewPackagesForCache()
	// Convert []*Package to []cache.Package
	pkgsToUploadCache := make([]cache.Package, len(pkgsToUpload))
	for i, p := range pkgsToUpload {
		pkgsToUploadCache[i] = p
	}

	cacheErr := ctx.RemoteCache.Upload(context.Background(), ctx.LocalCache, pkgsToUploadCache)

	if buildErr != nil {
		// We deliberately swallow the target pacakge build error as that will have already been reported using the reporter.
		return xerrors.Errorf("build failed")
	}
	if cacheErr != nil {
		return cacheErr
	}

	return nil
}

func writeBuildPlan(out io.Writer, pkg *Package, status map[*Package]PackageBuildStatus) error {
	// BuildStep is a list of packages that can be built in parallel
	type BuildStep []string

	var walk func(pkg *Package, idx map[*Package]int, depth int)
	walk = func(pkg *Package, idx map[*Package]int, depth int) {
		if status[pkg] == PackageBuilt {
			return
		}

		td := depth
		if idx[pkg] > td {
			td = idx[pkg]
		}
		idx[pkg] = td

		for _, dep := range pkg.GetDependencies() {
			walk(dep, idx, depth+1)
		}
	}

	idx := make(map[*Package]int)
	walk(pkg, idx, 0)

	var md int
	for _, d := range idx {
		if d > md {
			md = d
		}
	}
	log.WithField("maxDepth", md).Debug("built plan")
	steps := make([]BuildStep, md+1)
	for pkg, depth := range idx {
		steps[md-depth] = append(steps[md-depth], pkg.FullName())
	}

	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	err := enc.Encode(steps)
	if err != nil {
		return err
	}

	return nil
}

func (p *Package) buildDependencies(buildctx *buildContext) error {
	deps := p.GetDependencies()
	if deps == nil {
		return xerrors.Errorf("package \"%s\" is not linked", p.FullName())
	}

	// No dependencies means nothing to build
	if len(deps) == 0 {
		return nil
	}

	// Use errgroup to simplify error handling and synchronization
	g := new(errgroup.Group)

	for _, dep := range deps {
		// Capture the dependency in a local variable to avoid closure issues
		d := dep
		g.Go(func() error {
			return d.build(buildctx)
		})
	}

	// Wait for all goroutines to complete, returning the first error encountered
	return g.Wait()
}

func (p *Package) build(buildctx *buildContext) error {
	// Try to obtain lock for building this package
	doBuild := buildctx.ObtainBuildLock(p)
	if !doBuild {
		// Another goroutine is already building this package
		return nil
	}
	defer buildctx.ReleaseBuildLock(p)

	// Get package version
	version, err := p.Version()
	if err != nil {
		return err
	}

	// Build dependencies first
	if err := p.buildDependencies(buildctx); err != nil {
		return err
	}

	// Skip if package is already built (except for ephemeral packages)
	if _, alreadyBuilt := buildctx.LocalCache.Location(p); !p.Ephemeral && alreadyBuilt {
		log.WithField("package", p.FullName()).Debug("already built")
		return nil
	}

	// Initialize package build report
	pkgRep := &PackageBuildReport{
		phaseEnter: make(map[PackageBuildPhase]time.Time),
		phaseDone:  make(map[PackageBuildPhase]time.Time),
		Phases:     []PackageBuildPhase{PackageBuildPhasePrep},
	}
	pkgRep.phaseEnter[PackageBuildPhasePrep] = time.Now()

	// Notify reporter that package build is starting
	buildctx.Reporter.PackageBuildStarted(p)

	// Ensure we notify reporter when build finishes
	defer func() {
		pkgRep.Error = err
		buildctx.Reporter.PackageBuildFinished(p, pkgRep)
	}()

	// Prepare build directory
	builddir := filepath.Join(buildctx.BuildDir(), p.FilesystemSafeName()+"."+version)
	if err := prepareDirectory(builddir); err != nil {
		return err
	}

	// Copy source files if needed
	if err := copySources(p, builddir); err != nil {
		return err
	}

	// Acquire build resources
	buildctx.LimitConcurrentBuilds()
	defer buildctx.ReleaseConcurrentBuild()

	// Build the package based on its type
	var (
		result, _ = buildctx.LocalCache.Location(p)
		bld       *packageBuild
		sources   fileset
	)

	switch p.Type {
	case YarnPackage:
		bld, err = p.buildYarn(buildctx, builddir, result)
	case GoPackage:
		bld, err = p.buildGo(buildctx, builddir, result)
	case DockerPackage:
		bld, err = p.buildDocker(buildctx, builddir, result)
	case GenericPackage:
		bld, err = p.buildGeneric(buildctx, builddir, result)
	default:
		return xerrors.Errorf("cannot build package type: %s", p.Type)
	}

	if err != nil {
		return err
	}

	// Handle provenance if enabled
	now := time.Now()
	if p.C.W.Provenance.Enabled {
		if sources, err = computeFileset(builddir); err != nil {
			return err
		}
	}

	// Execute build phases
	for _, phase := range []PackageBuildPhase{
		PackageBuildPhasePrep,
		PackageBuildPhasePull,
		PackageBuildPhaseLint,
		PackageBuildPhaseTest,
		PackageBuildPhaseBuild,
	} {
		if err := executeBuildPhase(buildctx, p, builddir, bld, phase, pkgRep); err != nil {
			return err
		}
	}

	// Handle provenance subjects
	if p.C.W.Provenance.Enabled {
		if err := handleProvenance(p, buildctx, builddir, bld, sources, now); err != nil {
			return err
		}
	}

	// Handle test coverage if available
	if bld.TestCoverage != nil {
		coverage, funcsWithoutTest, funcsWithTest, err := bld.TestCoverage()
		if err != nil {
			return err
		}
		pkgRep.TestCoverageAvailable = true
		pkgRep.TestCoveragePercentage = coverage
		pkgRep.FunctionsWithoutTest = funcsWithoutTest
		pkgRep.FunctionsWithTest = funcsWithTest
	}

	// Package the build results
	if len(bld.Commands[PackageBuildPhasePackage]) > 0 {
		if err := executeCommandsForPackage(buildctx, p, builddir, bld.Commands[PackageBuildPhasePackage]); err != nil {
			return err
		}
	}

	// Register newly built package
	return buildctx.RegisterNewlyBuilt(p)
}

func prepareDirectory(dir string) error {
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		if err := os.RemoveAll(dir); err != nil {
			return err
		}
	}
	return os.MkdirAll(dir, 0755)
}

func copySources(p *Package, builddir string) error {
	if len(p.Sources) == 0 {
		return nil
	}

	var parentedFiles, notParentedFiles []string
	prefix := p.C.Origin + "/"

	for _, src := range p.Sources {
		if strings.HasPrefix(src, prefix) {
			parentedFiles = append(parentedFiles, strings.TrimPrefix(src, prefix))
		} else {
			notParentedFiles = append(notParentedFiles, src)
		}
	}

	if len(parentedFiles) > 0 {
		args := append([]string{"--parents"}, parentedFiles...)
		args = append(args, builddir)
		if err := run(nil, p, nil, p.C.Origin, "cp", args...); err != nil {
			return err
		}
	}

	if len(notParentedFiles) > 0 {
		args := append(notParentedFiles, builddir)
		if err := run(nil, p, nil, p.C.Origin, "cp", args...); err != nil {
			return err
		}
	}

	return nil
}

func executeBuildPhase(buildctx *buildContext, p *Package, builddir string, bld *packageBuild, phase PackageBuildPhase, pkgRep *PackageBuildReport) error {
	cmds := bld.Commands[phase]
	if len(cmds) == 0 {
		return nil
	}

	if phase != PackageBuildPhasePrep {
		pkgRep.phaseEnter[phase] = time.Now()
		pkgRep.Phases = append(pkgRep.Phases, phase)
	}

	log.WithField("phase", phase).WithField("package", p.FullName()).WithField("commands", bld.Commands[phase]).Debug("running commands")

	err := executeCommandsForPackage(buildctx, p, builddir, cmds)
	pkgRep.phaseDone[phase] = time.Now()

	return err
}

func handleProvenance(p *Package, buildctx *buildContext, builddir string, bld *packageBuild, sources fileset, now time.Time) error {
	var (
		subjects  []in_toto.Subject
		resultDir = builddir
		err       error
	)

	if bld.Subjects != nil {
		subjects, err = bld.Subjects()
	} else if bld.PostBuild != nil {
		subjects, resultDir, err = bld.PostBuild(sources)
	} else {
		var postBuild fileset
		postBuild, err = computeFileset(builddir)
		if err != nil {
			return err
		}
		subjects, err = postBuild.Sub(sources).Subjects(builddir)
	}
	if err != nil {
		return err
	}

	return writeProvenance(p, buildctx, resultDir, subjects, now)
}

// Collects the minimal set of packages to download from the remote cache
// That is, a package will only be downloaded if it is needed to perform a build.
//
// Note: toDownload is a map to avoid having duplicates.
func (p *Package) packagesToDownload(inLocalCache map[*Package]struct{}, inRemoteCache map[*Package]struct{}, toDownload map[*Package]struct{}) {
	_, existsInLocalCache := inLocalCache[p]
	_, existsInRemoteCache := inRemoteCache[p]

	if existsInLocalCache {
		// If the package is already in the local cache then we don't need to download it or any of its dependencies
		// The assumption here is that if the package exists locally, then we have already performed a build of the package
		// so any required dependencies are already present in the cache too.
		return
	}

	if existsInRemoteCache {
		// If the package is in the remote cache then we want to download it
		toDownload[p] = struct{}{}

		// If we don't download the package is going to be built (missing in local cache)
		// // For Generic and Docker packages we can short-circuit here.
		// // For Yarn and Go we can not, see comment below for details.
		// switch p.Type {
		// case GenericPackage, DockerPackage:
		// 	return
		// }
	}

	var deps []*Package
	switch p.Type {
	// For Go and Yarn packages we need all transitive dependencies of a component to be available on disk
	// to perform a build.
	//
	// Example: components/ee/agent-smith:app depends on components/gitpod-protocol/go:lib
	// 			components/gitpod-protocol/go:lib depends on components/gitpod-protocol:gitpod-schema
	// 			To build components/ee/agent-smith:app it is not enough to just download components/gitpod-protocol/go:lib
	// 			as we also need components/gitpod-protocol:gitpod-schema to be available on disk to perform the build.
	case YarnPackage, GoPackage:
		deps = p.GetTransitiveDependencies()
	// For Generic and Docker packages it is sufficient to have the direct dependencies.
	case GenericPackage, DockerPackage:
		deps = p.GetDependencies()
	}

	for _, p := range deps {
		p.packagesToDownload(inLocalCache, inRemoteCache, toDownload)
	}
}

type PackageBuildPhase string

const (
	PackageBuildPhasePrep    PackageBuildPhase = "prep"
	PackageBuildPhasePull    PackageBuildPhase = "pull"
	PackageBuildPhaseLint    PackageBuildPhase = "lint"
	PackageBuildPhaseTest    PackageBuildPhase = "test"
	PackageBuildPhaseBuild   PackageBuildPhase = "build"
	PackageBuildPhasePackage PackageBuildPhase = "package"
)

type packageBuild struct {
	Commands map[PackageBuildPhase][][]string

	// If PostBuild is not nil but Subjects is, PostBuild is used
	// to compute the post build fileset for provenance subject computation.
	PostBuild func(sources fileset) (subj []in_toto.Subject, absResultDir string, err error)
	// If Subjects is not nil it's used to compute the provenance subjects of the
	// package build. This field takes precedence over PostBuild
	Subjects func() ([]in_toto.Subject, error)

	// If TestCoverage is not nil it's used to compute the test coverage of the package build.
	// This function is expected to return a value between 0 and 100.
	// If the package build does not have any tests, this function must return 0.
	// If the package build has tests but the test coverage cannot be computed, this function must return an error.
	// This function is guaranteed to be called after the test phase has finished.
	TestCoverage testCoverageFunc
}

type testCoverageFunc func() (coverage, funcsWithoutTest, funcsWithTest int, err error)

const (
	getYarnLockScript = `#!/bin/bash
set -Eeuo pipefail

export DIR=$(realpath $(dirname "${BASH_SOURCE[0]}"))

sed 's?resolved "file://.*/?resolved "file://'$DIR'/?g' $DIR/content_yarn.lock
`

	installScript = `#!/bin/bash
set -Eeuo pipefail

export DIR=$(dirname "${BASH_SOURCE[0]}")

cp $DIR/installer-package.json package.json
$DIR/get_yarn_lock.sh > yarn.lock

mkdir -p _temp_yarn_cache
yarn install --frozenlockfile --prod --cache-folder _temp_yarn_cache
rm -r yarn.lock _temp_yarn_cache
`

	installerPackageJSONTemplate = `{"name":"local","version":"%s","license":"UNLICENSED","dependencies":{"%s":"%s"}}`
)

// buildYarn implements the build process for Yarn packages.
// If you change anything in this process that's not backwards compatible, make sure you increment buildProcessVersions accordingly.
func (p *Package) buildYarn(buildctx *buildContext, wd, result string) (bld *packageBuild, err error) {
	cfg, ok := p.Config.(YarnPkgConfig)
	if !ok {
		return nil, xerrors.Errorf("package should have yarn config")
	}

	var (
		fn           = filepath.Join(p.C.Origin, "package.json")
		pkgjsonFound bool
	)
	for _, src := range p.Sources {
		if src == fn {
			pkgjsonFound = true
			break
		}
	}
	if !pkgjsonFound {
		return nil, xerrors.Errorf("%s: yarn packages must have a package.json", p.FullName())
	}

	version, err := p.Version()
	if err != nil {
		return nil, err
	}

	var commands = make(map[PackageBuildPhase][][]string)
	if cfg.Packaging == YarnOfflineMirror {
		err := os.Mkdir(filepath.Join(wd, "_mirror"), 0755)
		if err != nil {
			return nil, err
		}

		commands[PackageBuildPhasePrep] = append(commands[PackageBuildPhasePrep], [][]string{
			{"sh", "-c", "echo yarn-offline-mirror \"./_mirror\" > .yarnrc"},
		}...)
	}

	// We don't check if ephemeral packages in the transitive dependency tree have been built,
	// as they may be too far down the tree to trigger a build (e.g. their parent may be built already).
	// Hence, we need to ensure all direct dependencies on ephemeral packages have been built.
	for _, deppkg := range p.GetDependencies() {
		_, ok := buildctx.LocalCache.Location(deppkg)
		if deppkg.Ephemeral && !ok {
			return nil, PkgNotBuiltErr{deppkg}
		}
	}

	pkgYarnLock := "pkg-yarn.lock"
	for _, deppkg := range p.GetTransitiveDependencies() {
		if deppkg.Ephemeral {
			continue
		}

		builtpkg, ok := buildctx.LocalCache.Location(deppkg)
		if !ok {
			return nil, PkgNotBuiltErr{deppkg}
		}

		tgt := p.BuildLayoutLocation(deppkg)
		if cfg.Packaging == YarnOfflineMirror {
			fn := fmt.Sprintf("%s.tar.gz", tgt)
			commands[PackageBuildPhasePrep] = append(commands[PackageBuildPhasePrep], []string{"cp", builtpkg, filepath.Join("_mirror", fn)})
			builtpkg = filepath.Join(wd, "_mirror", fn)
		}

		var isTSLibrary bool
		if deppkg.Type == YarnPackage {
			cfg, ok := deppkg.Config.(YarnPkgConfig)
			if ok && cfg.Packaging == YarnLibrary {
				isTSLibrary = true
			}
		}
		if isTSLibrary {
			// make previously built package availabe through yarn lock
			commands[PackageBuildPhasePrep] = append(commands[PackageBuildPhasePrep], []string{"sh", "-c", fmt.Sprintf("tar Ozfx %s package/%s | sed '/resolved /c\\  resolved \"file://%s\"' >> yarn.lock", builtpkg, pkgYarnLock, builtpkg)})
		} else {
			untarCmd, err := BuildUnTarCommand(
				WithInputFile(builtpkg),
				WithTargetDir(tgt),
				WithAutoDetectCompression(true),
			)
			if err != nil {
				return nil, err
			}

			commands[PackageBuildPhasePrep] = append(commands[PackageBuildPhasePrep], [][]string{
				{"mkdir", tgt},
				untarCmd,
			}...)
		}
	}

	pkgJSONFilename := filepath.Join(wd, "package.json")
	var packageJSON map[string]interface{}
	fc, err := os.ReadFile(pkgJSONFilename)
	if err != nil {
		return nil, xerrors.Errorf("cannot patch package.json of yarn package: %w", err)
	}
	err = json.Unmarshal(fc, &packageJSON)
	if err != nil {
		return nil, xerrors.Errorf("cannot patch package.json of yarn package: %w", err)
	}
	var modifiedPackageJSON bool
	if cfg.Packaging == YarnLibrary {
		// We can't modify the `yarn pack` generated tar file without runnign the risk of yarn blocking when attempting to unpack it again. Thus, we must include the pkgYarnLock in the npm
		// package we're building. To this end, we modify the package.json of the source package.
		var packageJSONFiles []interface{}
		if rfs, ok := packageJSON["files"]; ok {
			fs, ok := rfs.([]interface{})
			if !ok {
				return nil, xerrors.Errorf("invalid package.json: files section is not a list of strings")
			}
			packageJSONFiles = fs
		}
		packageJSONFiles = append(packageJSONFiles, pkgYarnLock)
		if p.C.W.Provenance.Enabled {
			packageJSONFiles = append(packageJSONFiles, provenanceBundleFilename)
		}
		packageJSON["files"] = packageJSONFiles

		modifiedPackageJSON = true
	}
	if cfg.Packaging == YarnApp {
		// We have to give this package a unique version to make sure we do not "poison" the yarn cache with this particular application version.
		// The yarn package name and leeway package name do not have to be the same which makes it possible to "reuse" the npm package name for
		// different things. This yarn cache can't handle that.
		packageJSON["version"] = fmt.Sprintf("0.0.0-%s", version)

		modifiedPackageJSON = true
	}
	if modifiedPackageJSON {
		fc, err = json.Marshal(packageJSON)
		if err != nil {
			return nil, xerrors.Errorf("cannot patch package.json of yarn package: %w", err)
		}
		err = os.WriteFile(pkgJSONFilename, fc, 0644)
		if err != nil {
			return nil, xerrors.Errorf("cannot patch package.json of yarn package: %w", err)
		}
	}
	pkgname, ok := packageJSON["name"].(string)
	if !ok {
		return nil, xerrors.Errorf("name is not a string, but %v", pkgname)
	}
	pkgversion := packageJSON["version"]
	if pkgname == "" || pkgversion == "" {
		return nil, xerrors.Errorf("name or version in package.json must not be empty")
	}

	// At this point we have all dependencies in place, a the correct package.json,
	// and we're just short of running yarn install. Good point to do other prep work.
	commands[PackageBuildPhasePrep] = append(commands[PackageBuildPhasePrep], p.PreparationCommands...)

	// The yarn cache cannot handly conccurency proplery and needs to be looked.
	// Make sure that all our yarn install calls lock the yarn cache.
	yarnMutex := os.Getenv(EnvvarYarnMutex)
	if yarnMutex == "" {
		log.Debugf("%s is not set, defaulting to \"network\"", EnvvarYarnMutex)
		yarnMutex = "network"
	}
	yarnCache := filepath.Join(buildctx.BuildDir(), fmt.Sprintf("yarn-cache-%s", buildctx.buildID))
	if len(cfg.Commands.Install) == 0 {
		commands[PackageBuildPhasePull] = append(commands[PackageBuildPhasePull], []string{"yarn", "install", "--mutex", yarnMutex, "--cache-folder", yarnCache})
	} else {
		commands[PackageBuildPhasePull] = append(commands[PackageBuildPhasePull], cfg.Commands.Install)
	}
	if len(cfg.Commands.Build) == 0 {
		commands[PackageBuildPhaseBuild] = append(commands[PackageBuildPhaseBuild], []string{"yarn", "build"})
	} else {
		commands[PackageBuildPhaseBuild] = append(commands[PackageBuildPhaseBuild], cfg.Commands.Build)
	}
	if !cfg.DontTest && !buildctx.DontTest {
		if len(cfg.Commands.Test) == 0 {
			commands[PackageBuildPhaseTest] = append(commands[PackageBuildPhaseTest], []string{"yarn", "test"})
		} else {
			commands[PackageBuildPhaseTest] = append(commands[PackageBuildPhaseTest], cfg.Commands.Test)
		}
	}

	res := &packageBuild{
		Commands: commands,
	}

	// let's prepare for packaging
	var (
		pkgCommands [][]string
		resultDir   string
	)
	if cfg.Packaging == YarnOfflineMirror {
		builtinScripts := map[string]string{
			"get_yarn_lock.sh":       getYarnLockScript,
			"install.sh":             installScript,
			"installer-package.json": fmt.Sprintf(installerPackageJSONTemplate, version, pkgname, pkgversion),
		}
		for fn, script := range builtinScripts {
			err = os.WriteFile(filepath.Join(wd, "_mirror", fn), []byte(script), 0755)
			if err != nil {
				return nil, err
			}
		}

		dst := filepath.Join("_mirror", fmt.Sprintf("%s.tar.gz", p.FilesystemSafeName()))
		pkgCommands = append(pkgCommands, [][]string{
			{"sh", "-c", fmt.Sprintf("yarn generate-lock-entry --resolved file://./%s > _mirror/content_yarn.lock", dst)},
			{"sh", "-c", "cat yarn.lock >> _mirror/content_yarn.lock"},
			{"yarn", "pack", "--filename", dst},
			BuildTarCommand(
				WithOutputFile(result),
				WithWorkingDir("_mirror"),
				WithCompression(!buildctx.DontCompress),
			),
		}...)
		resultDir = "_mirror"
	} else if cfg.Packaging == YarnLibrary {
		pkgCommands = append(pkgCommands, [][]string{
			{"sh", "-c", fmt.Sprintf("yarn generate-lock-entry --resolved file://%s > %s", result, pkgYarnLock)},
			{"yarn", "pack", "--filename", result},
		}...)
	} else if cfg.Packaging == YarnApp {
		err := os.Mkdir(filepath.Join(wd, "_pkg"), 0755)
		if err != nil {
			return nil, err
		}
		err = os.WriteFile(filepath.Join(wd, "_pkg", "package.json"), []byte(fmt.Sprintf(installerPackageJSONTemplate, version, pkgname, pkgversion)), 0755)
		if err != nil {
			return nil, err
		}

		pkg := filepath.Join(wd, "package.tar.tz")
		pkgCommands = append(pkgCommands, [][]string{
			{"sh", "-c", fmt.Sprintf("yarn generate-lock-entry --resolved file://%s > %s", pkg, pkgYarnLock)},
			{"yarn", "pack", "--filename", pkg},
			{"sh", "-c", fmt.Sprintf("cat yarn.lock %s > _pkg/yarn.lock", pkgYarnLock)},
			{"yarn", "--cwd", "_pkg", "install", "--prod", "--frozen-lockfile"},
			BuildTarCommand(
				WithOutputFile(result),
				WithWorkingDir("_pkg"),
				WithCompression(!buildctx.DontCompress),
			),
		}...)
		resultDir = "_pkg"
	} else if cfg.Packaging == YarnArchive {
		pkgCommands = append(pkgCommands, BuildTarCommand(
			WithOutputFile(result),
			WithCompression(!buildctx.DontCompress),
		))
	} else {
		return nil, xerrors.Errorf("unknown Yarn packaging: %s", cfg.Packaging)
	}
	res.Commands[PackageBuildPhasePackage] = pkgCommands
	res.PostBuild = func(sources fileset) (subjects []in_toto.Subject, absResultDir string, err error) {
		ignoreNodeModules := func(fn string) bool { return strings.Contains(fn, "node_modules/") }
		fn := filepath.Join(wd, resultDir)
		postBuild, err := computeFileset(fn, ignoreNodeModules)
		if err != nil {
			return nil, fn, err
		}
		subjects, err = postBuild.Sub(sources).Subjects(fn)
		absResultDir = filepath.Join(wd, resultDir)
		return
	}

	return res, nil
}

// buildGo implements the build process for Go packages.
// If you change anything in this process that's not backwards compatible, make sure you increment buildProcessVersions accordingly.
func (p *Package) buildGo(buildctx *buildContext, wd, result string) (res *packageBuild, err error) {
	cfg, ok := p.Config.(GoPkgConfig)
	if !ok {
		return nil, xerrors.Errorf("package should have Go config")
	}

	if _, err := os.Stat(filepath.Join(wd, "go.mod")); os.IsNotExist(err) {
		return nil, xerrors.Errorf("can only build Go modules (missing go.mod file)")
	}

	var (
		commands      = make(map[PackageBuildPhase][][]string)
		isGoWorkspace bool
		workFile      *modfile.WorkFile
	)
	if fc, err := os.ReadFile(filepath.Join(p.C.W.Origin, "go.work")); err == nil {
		isGoWorkspace = true

		workFile, err = modfile.ParseWork("go.work", fc, nil)
		if err != nil {
			return nil, xerrors.Errorf("cannot read go.work file: %w", err)
		}
		// we drop all use statements and later add the correct ones back in, starting with the src itself
		for _, use := range workFile.Use {
			err = workFile.DropUse(use.Path)
			if err != nil {
				return nil, err
			}
		}
		workFile.AddNewUse("./", "")
		workFile.SortBlocks()
		workFile.Cleanup()
		fc = modfile.Format(workFile.Syntax)
		err = os.WriteFile(filepath.Join(wd, "go.work"), fc, 0644)
		if err != nil {
			return nil, err
		}

	} else if !os.IsNotExist(err) {
		return nil, xerrors.Errorf("cannot read go.work file: %w", err)
	}

	var goCommand = "go"
	if cfg.GoVersion != "" {
		goCommand = cfg.GoVersion
		commands[PackageBuildPhasePrep] = append(commands[PackageBuildPhasePrep], [][]string{
			{"sh", "-c", "GO111MODULE=off go get golang.org/dl/" + cfg.GoVersion},
			{goCommand, "download"},
		}...)
	}

	// We don't check if ephemeral packages in the transitive dependency tree have been built,
	// as they may be too far down the tree to trigger a build (e.g. their parent may be built already).
	// Hence, we need to ensure all direct dependencies on ephemeral packages have been built.
	for _, deppkg := range p.GetDependencies() {
		_, ok := buildctx.LocalCache.Location(deppkg)
		if deppkg.Ephemeral && !ok {
			return nil, PkgNotBuiltErr{deppkg}
		}
	}

	transdep := p.GetTransitiveDependencies()
	if len(transdep) > 0 {
		commands[PackageBuildPhasePrep] = append(commands[PackageBuildPhasePrep], []string{"mkdir", "_deps"})

		for _, dep := range transdep {
			if dep.Ephemeral {
				continue
			}

			builtpkg, ok := buildctx.LocalCache.Location(dep)
			if !ok {
				return nil, PkgNotBuiltErr{dep}
			}

			tgt := filepath.Join("_deps", p.BuildLayoutLocation(dep))
			untarCmd, err := BuildUnTarCommand(
				WithInputFile(builtpkg),
				WithTargetDir(tgt),
				WithAutoDetectCompression(true),
			)
			if err != nil {
				return nil, err
			}

			commands[PackageBuildPhasePrep] = append(commands[PackageBuildPhasePrep], [][]string{
				{"mkdir", tgt},
				untarCmd,
			}...)

			if dep.Type != GoPackage {
				continue
			}

			if isGoWorkspace {
				commands[PackageBuildPhasePrep] = append(commands[PackageBuildPhasePrep], []string{"go", "work", "use", tgt})
			} else {
				commands[PackageBuildPhasePrep] = append(commands[PackageBuildPhasePrep], []string{"sh", "-c", fmt.Sprintf("%s mod edit -replace $(cd %s; grep module go.mod | cut -d ' ' -f 2 | head -n1)=./%s", goCommand, tgt, tgt)})
			}
		}
	}

	commands[PackageBuildPhasePrep] = append(commands[PackageBuildPhasePrep], p.PreparationCommands...)
	if cfg.Generate {
		commands[PackageBuildPhasePrep] = append(commands[PackageBuildPhasePrep], []string{goCommand, "generate", "-v", "./..."})
	}

	dlcmd := []string{goCommand, "mod", "download"}
	if log.IsLevelEnabled(log.DebugLevel) {
		dlcmd = append(dlcmd, "-x")
	}
	commands[PackageBuildPhasePull] = append(commands[PackageBuildPhasePull], dlcmd)

	if !cfg.DontCheckGoFmt {
		commands[PackageBuildPhaseLint] = append(commands[PackageBuildPhaseLint], []string{"sh", "-c", `if [ ! $(go fmt ./... | wc -l) -eq 0 ]; then echo; echo; echo please gofmt your code; echo; echo; exit 1; fi`})
	}
	if !cfg.DontLint {
		if len(cfg.LintCommand) == 0 {
			commands[PackageBuildPhaseLint] = append(commands[PackageBuildPhaseLint], []string{"golangci-lint", "run"})
		} else {
			commands[PackageBuildPhaseLint] = append(commands[PackageBuildPhaseLint], cfg.LintCommand)
		}
	}
	var reportCoverage testCoverageFunc
	if !cfg.DontTest && !buildctx.DontTest {
		testCommand := []string{goCommand, "test"}
		if log.IsLevelEnabled(log.DebugLevel) {
			testCommand = append(testCommand, "-v")
		}

		if buildctx.buildOptions.CoverageOutputPath != "" {
			testCommand = append(testCommand, fmt.Sprintf("-coverprofile=%v", codecovComponentName(p.FullName())))
		} else {
			testCommand = append(testCommand, "-coverprofile=testcoverage.out")
			reportCoverage = collectGoTestCoverage(filepath.Join(wd, "testcoverage.out"))
		}
		testCommand = append(testCommand, "./...")

		commands[PackageBuildPhaseTest] = append(commands[PackageBuildPhaseTest], testCommand)
	}

	var buildCmd []string
	if len(cfg.BuildCommand) > 0 {
		buildCmd = cfg.BuildCommand
	} else if cfg.Packaging == GoApp {
		buildCmd = []string{goCommand, "build"}
		buildCmd = append(buildCmd, cfg.BuildFlags...)
		buildCmd = append(buildCmd, ".")
	}
	if len(buildCmd) > 0 && cfg.Packaging != GoLibrary {
		commands[PackageBuildPhaseBuild] = append(commands[PackageBuildPhaseBuild], buildCmd)
	}

	commands[PackageBuildPhasePackage] = append(commands[PackageBuildPhasePackage], []string{"rm", "-rf", "_deps"})
	commands[PackageBuildPhasePackage] = append(commands[PackageBuildPhasePackage],
		BuildTarCommand(
			WithOutputFile(result),
			WithCompression(!buildctx.DontCompress),
		),
	)
	if !cfg.DontTest && !buildctx.DontTest {
		commands[PackageBuildPhasePackage] = append(commands[PackageBuildPhasePackage], [][]string{
			{"sh", "-c", fmt.Sprintf(`if [ -f "%v" ]; then cp -f %v %v; fi`, codecovComponentName(p.FullName()), codecovComponentName(p.FullName()), buildctx.buildOptions.CoverageOutputPath)},
		}...)
	}

	return &packageBuild{
		Commands:     commands,
		TestCoverage: reportCoverage,
	}, nil
}

func collectGoTestCoverage(covfile string) testCoverageFunc {
	return func() (coverage, funcsWithoutTest, funcsWithTest int, err error) {
		// We need to collect the coverage for all packages in the module.
		// To that end we load the coverage file.
		// The coverage file contains the coverage for all packages in the module.

		cmd := exec.Command("go", "tool", "cover", "-func", covfile)
		log.WithField("pwd", filepath.Dir(covfile)).WithField("covfile", covfile).Debug("collecting test coverage")
		cmd.Dir = filepath.Dir(covfile)
		out, err := cmd.CombinedOutput()
		if err != nil {
			err = xerrors.Errorf("cannot collect test coverage: %w: %s", err, string(out))
			return
		}

		coverage, funcsWithoutTest, funcsWithTest, err = parseGoCoverOutput(string(out))
		return
	}
}

func parseGoCoverOutput(input string) (coverage, funcsWithoutTest, funcsWithTest int, err error) {
	// The output of the coverage tool looks like this:
	// github.com/gitpod-io/gitpod/content_ws/pkg/contentws/contentws.go:33:	New		100.0%
	lines := strings.Split(input, "\n")

	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		perc := strings.Trim(strings.TrimSpace(fields[2]), "%")
		percF, err := strconv.ParseFloat(perc, 32)
		if err != nil {
			log.Warnf("cannot parse coverage percentage for line %s: %v", line, err)
			continue
		}
		intCov := int(percF)
		coverage += intCov
		if intCov == 0 {
			funcsWithoutTest++
		} else {
			funcsWithTest++
		}
	}

	total := (funcsWithoutTest + funcsWithTest)
	if total != 0 {
		coverage = coverage / total
	}
	return
}

// buildDocker implements the build process for Docker packages.
// If you change anything in this process that's not backwards compatible, make sure you increment buildProcessVersions accordingly.
func (p *Package) buildDocker(buildctx *buildContext, wd, result string) (res *packageBuild, err error) {
	cfg, ok := p.Config.(DockerPkgConfig)
	if !ok {
		return nil, xerrors.Errorf("package should have Docker config")
	}

	if cfg.Dockerfile == "" {
		return nil, xerrors.Errorf("dockerfile is required")
	}

	dockerfile := filepath.Join(p.C.Origin, cfg.Dockerfile)
	if _, err := os.Stat(dockerfile); os.IsNotExist(err) {
		return nil, err
	}

	var (
		commands          = make(map[PackageBuildPhase][][]string)
		imageDependencies = make(map[string]string)
	)
	commands[PackageBuildPhasePrep] = append(commands[PackageBuildPhasePrep], []string{"cp", dockerfile, "Dockerfile"})
	for _, dep := range p.GetDependencies() {
		fn, exists := buildctx.LocalCache.Location(dep)
		if !exists {
			return nil, PkgNotBuiltErr{dep}
		}

		tgt := p.BuildLayoutLocation(dep)
		untarCmd, err := BuildUnTarCommand(
			WithInputFile(fn),
			WithTargetDir(tgt),
			WithAutoDetectCompression(true),
		)
		if err != nil {
			return nil, err
		}
		commands[PackageBuildPhasePrep] = append(commands[PackageBuildPhasePrep], [][]string{
			{"mkdir", tgt},
			untarCmd,
		}...)

		if dep.Type != DockerPackage {
			continue
		}
		depimg, err := extractImageNameFromCache(dep.Name, fn)
		if err != nil {
			return nil, err
		}
		imageDependencies[strings.ToUpper(strings.ReplaceAll(dep.FilesystemSafeName(), "-", "_"))] = depimg
	}

	commands[PackageBuildPhasePrep] = append(commands[PackageBuildPhasePrep], p.PreparationCommands...)

	version, err := p.Version()
	if err != nil {
		return nil, err
	}

	buildcmd := []string{"docker", "build", "--pull", "-t", version}
	for arg, val := range cfg.BuildArgs {
		buildcmd = append(buildcmd, "--build-arg", fmt.Sprintf("%s=%s", arg, val))
	}
	for arg, val := range imageDependencies {
		buildcmd = append(buildcmd, "--build-arg", fmt.Sprintf("DEP_%s=%s", arg, val))
	}
	buildcmd = append(buildcmd, "--build-arg", fmt.Sprintf("__GIT_COMMIT=%s", p.C.Git().Commit))
	if cfg.Squash {
		buildcmd = append(buildcmd, "--squash")
	}
	if buildctx.DockerBuildOptions != nil {
		for opt, v := range *buildctx.DockerBuildOptions {
			buildcmd = append(buildcmd, fmt.Sprintf("--%s=%s", opt, v))
		}
	}
	buildcmd = append(buildcmd, ".")
	commands[PackageBuildPhaseBuild] = append(commands[PackageBuildPhaseBuild], buildcmd)

	if len(cfg.Image) == 0 {
		// we don't push the image, let's export it
		ef := strings.TrimSuffix(result, ".gz")
		commands[PackageBuildPhaseBuild] = append(commands[PackageBuildPhaseBuild], [][]string{
			{"docker", "save", "-o", ef, version},
		}...)
	}

	res = &packageBuild{
		Commands: commands,
	}

	var pkgCommands [][]string
	if len(cfg.Image) == 0 {
		// We've already built the build artifact by exporting the archive using "docker save"
		// At the very least we need to add the provenance bundle to that archive.
		ef := strings.TrimSuffix(result, ".gz")
		res.PostBuild = dockerExportPostBuild(wd, ef)

		var pkgcmds [][]string
		if p.C.W.Provenance.Enabled {
			pkgcmds = append(pkgcmds, []string{"tar", "fr", ef, "./" + provenanceBundleFilename})
		}

		pkgcmds = append(pkgcmds, []string{compressor, ef})
		commands[PackageBuildPhasePackage] = pkgcmds
	} else if len(cfg.Image) > 0 {
		for _, img := range cfg.Image {
			pkgCommands = append(pkgCommands, [][]string{
				{"docker", "tag", version, img},
				{"docker", "push", img},
			}...)
		}

		// We pushed the image which means we won't export it. We still need to place a marker the build cache.
		// The proper thing would be to export the image, but that's rather expensive. We'll place a tar file which
		// contains the names of the image we just pushed instead.
		for _, img := range cfg.Image {
			pkgCommands = append(pkgCommands,
				[]string{"sh", "-c", fmt.Sprintf("echo %s >> %s", img, dockerImageNamesFiles)},
				[]string{"sh", "-c", fmt.Sprintf("echo built image: %s", img)},
			)
		}
		// In addition to the imgnames.txt we also produce a file that contains the configured metadata,
		// which provides a sensible way to add metadata to the image names.
		consts, err := yaml.Marshal(cfg.Metadata)
		if err != nil {
			return nil, err
		}
		pkgCommands = append(pkgCommands, []string{"sh", "-c", fmt.Sprintf("echo %s | base64 -d > %s", base64.StdEncoding.EncodeToString(consts), dockerMetadataFile)})

		sourcePaths := []string{fmt.Sprintf("./%s", dockerImageNamesFiles), fmt.Sprintf("./%s", dockerMetadataFile)}
		if p.C.W.Provenance.Enabled {
			sourcePaths = append(sourcePaths, fmt.Sprintf("./%s", provenanceBundleFilename))
		}
		archiveCmd := BuildTarCommand(
			WithOutputFile(result),
			WithSourcePaths(sourcePaths...),
			WithCompression(!buildctx.DontCompress),
		)
		pkgCommands = append(pkgCommands, archiveCmd)

		commands[PackageBuildPhasePackage] = pkgCommands
		res.Subjects = func() (res []in_toto.Subject, err error) {
			defer func() {
				if err != nil {
					err = xerrors.Errorf("provenance get subjects: %w", err)
				}
			}()
			out, err := exec.Command("docker", "inspect", version).CombinedOutput()
			if err != nil {
				return nil, xerrors.Errorf("cannot determine ID of the image we just built")
			}
			var inspectRes []struct {
				ID string `json:"Id"`
			}
			err = json.Unmarshal(out, &inspectRes)
			if err != nil {
				return nil, xerrors.Errorf("cannot unmarshal Docker inspect response \"%s\": %w", string(out), err)
			}
			if len(inspectRes) == 0 {
				return nil, xerrors.Errorf("did not receive a proper Docker inspect response")
			}
			segs := strings.Split(inspectRes[0].ID, ":")
			if len(segs) != 2 {
				return nil, xerrors.Errorf("docker inspect returned invalid digest: %s", inspectRes[0].ID)
			}
			digest := common.DigestSet{
				segs[0]: segs[1],
			}

			res = make([]in_toto.Subject, 0, len(cfg.Image))
			for _, tag := range cfg.Image {
				res = append(res, in_toto.Subject{
					Name:   tag,
					Digest: digest,
				})
			}

			return res, nil
		}
	}

	return res, nil
}

func dockerExportPostBuild(builddir, result string) func(sources fileset) (subj []in_toto.Subject, absResultDir string, err error) {
	return func(sources fileset) (subj []in_toto.Subject, absResultDir string, err error) {
		f, err := os.Open(result)
		if err != nil {
			return
		}
		defer f.Close()

		archive := tar.NewReader(f)
		for {
			var hdr *tar.Header
			hdr, err = archive.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				return
			}
			if hdr.Typeflag != tar.TypeReg {
				continue
			}

			hash := sha256.New()
			_, err = io.Copy(hash, io.LimitReader(archive, hdr.Size))
			if err != nil {
				return nil, builddir, err
			}

			subj = append(subj, in_toto.Subject{
				Name:   hdr.Name,
				Digest: common.DigestSet{"sha256": hex.EncodeToString(hash.Sum(nil))},
			})
		}

		return subj, builddir, nil
	}
}

// extractImageNameFromCache extracts the Docker image name of a previously built package
// from the cache tar.gz file of that package.
func extractImageNameFromCache(pkgName, cacheBundleFN string) (imgname string, err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("cannot extract image ref from cache for %s: %w", pkgName, err)
		}
	}()

	f, err := os.Open(cacheBundleFN)
	if err != nil {
		return "", err
	}
	defer f.Close()

	gzin, err := gzip.NewReader(f)
	if err != nil {
		return "", err
	}
	defer gzin.Close()

	tarin := tar.NewReader(gzin)
	for {
		hdr, err := tarin.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", err
		}

		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		if filepath.Base(hdr.Name) != dockerImageNamesFiles {
			continue
		}

		imgnames := make([]byte, hdr.Size)
		n, err := io.ReadFull(tarin, imgnames)
		if err != nil {
			return "", err
		}
		if int64(n) != hdr.Size {
			return "", fmt.Errorf("cannot read %s from cache: %w", dockerImageNamesFiles, io.ErrShortBuffer)
		}

		lines := strings.Split(string(imgnames), "\n")
		return lines[0], nil
	}

	return "", nil
}

// Update buildGeneric to use compression arg helper
func (p *Package) buildGeneric(buildctx *buildContext, wd, result string) (res *packageBuild, err error) {
	cfg, ok := p.Config.(GenericPkgConfig)
	if !ok {
		return nil, xerrors.Errorf("package should have generic config")
	}

	// shortcut: no command == empty package
	if len(cfg.Commands) == 0 && len(cfg.Test) == 0 {
		log.WithField("package", p.FullName()).Debug("package has no commands nor test - creating empty tar")

		// Even for empty packages, we need to handle dependencies
		var commands [][]string
		for _, dep := range p.GetDependencies() {
			fn, exists := buildctx.LocalCache.Location(dep)
			if !exists {
				return nil, PkgNotBuiltErr{dep}
			}

			tgt := p.BuildLayoutLocation(dep)

			untarCmd, err := BuildUnTarCommand(
				WithInputFile(fn),
				WithTargetDir(tgt),
				WithAutoDetectCompression(true),
			)
			if err != nil {
				return nil, err
			}
			commands = append(commands, [][]string{
				{"mkdir", tgt},
				untarCmd,
			}...)
		}

		// Use buildTarCommand directly which will handle compression internally
		var tarCmd []string
		if p.C.W.Provenance.Enabled {
			tarCmd = BuildTarCommand(
				WithOutputFile(result),
				WithSourcePaths(fmt.Sprintf("./%s", provenanceBundleFilename)),
				WithCompression(!buildctx.DontCompress),
			)
			return &packageBuild{
				Commands: map[PackageBuildPhase][][]string{
					PackageBuildPhaseBuild:   commands,
					PackageBuildPhasePackage: {tarCmd},
				},
			}, nil
		}

		if len(commands) > 0 {
			return &packageBuild{
				Commands: map[PackageBuildPhase][][]string{
					PackageBuildPhaseBuild:   commands,
					PackageBuildPhasePackage: {tarCmd},
				},
			}, nil
		}

		// Truly empty package with no dependencies
		tarCmd = BuildTarCommand(
			WithFilesFrom("/dev/null"),
			WithCompression(!buildctx.DontCompress),
		)

		return &packageBuild{
			Commands: map[PackageBuildPhase][][]string{
				PackageBuildPhasePackage: {tarCmd},
			},
		}, nil
	}

	var commands [][]string
	for _, dep := range p.GetDependencies() {
		fn, exists := buildctx.LocalCache.Location(dep)
		if !exists {
			return nil, PkgNotBuiltErr{dep}
		}

		tgt := p.BuildLayoutLocation(dep)

		untarCmd, err := BuildUnTarCommand(
			WithInputFile(fn),
			WithTargetDir(tgt),
			WithAutoDetectCompression(true),
		)
		if err != nil {
			return nil, err
		}

		commands = append(commands, [][]string{
			{"mkdir", tgt},
			untarCmd,
		}...)
	}

	commands = append(commands, p.PreparationCommands...)
	commands = append(commands, cfg.Commands...)
	if !cfg.DontTest && !buildctx.DontTest {
		commands = append(commands, cfg.Test...)
	}

	return &packageBuild{
		Commands: map[PackageBuildPhase][][]string{
			PackageBuildPhaseBuild: commands,
			PackageBuildPhasePackage: {
				BuildTarCommand(
					WithOutputFile(result),
					WithCompression(!buildctx.DontCompress),
				),
			},
		},
	}, nil
}

func executeCommandsForPackage(buildctx *buildContext, p *Package, wd string, commands [][]string) error {
	if len(commands) == 0 {
		return nil
	}
	if buildctx.JailedExecution {
		return executeCommandsForPackageSafe(buildctx, p, wd, commands)
	}

	env := append(os.Environ(), p.Environment...)
	env = append(env, fmt.Sprintf("LEEWAY_WORKSPACE_ROOT=%s", p.C.W.Origin))
	for _, cmd := range commands {
		if len(cmd) == 0 {
			continue // Skip empty commands
		}
		err := run(buildctx.Reporter, p, env, wd, cmd[0], cmd[1:]...)
		if err != nil {
			return err
		}
	}
	return nil
}

func run(rep Reporter, p *Package, env []string, cwd, name string, args ...string) error {
	log.WithField("package", p.FullName()).WithField("command", strings.Join(append([]string{name}, args...), " ")).Debug("running")

	cmd := exec.Command(name, args...)
	cmd.Stdout = &reporterStream{R: rep, P: p, IsErr: false}
	cmd.Stderr = &reporterStream{R: rep, P: p, IsErr: true}
	cmd.Dir = cwd
	cmd.Env = env
	err := cmd.Run()

	if err != nil {
		return err
	}

	return nil
}

type reporterStream struct {
	R     Reporter
	P     *Package
	IsErr bool
}

func (s *reporterStream) Write(buf []byte) (n int, err error) {
	if s.R != nil {
		s.R.PackageBuildLog(s.P, s.IsErr, buf)
	}
	return len(buf), nil
}

func codecovComponentName(name string) string {
	reg, _ := regexp.Compile("[^a-zA-Z0-9]+")
	component := reg.ReplaceAllString(name, "-")
	return strings.ToLower(component + "-coverage.out")
}

// Convert *Package slice to cache.Package slice with improved logging
func toPackageInterface(pkgs []*Package) []cache.Package {
	result := make([]cache.Package, len(pkgs))
	for i, p := range pkgs {
		if p == nil {
			log.WithField("index", i).Warn("Nil package encountered in conversion")
			continue
		}
		result[i] = p
		log.WithFields(log.Fields{
			"package": p.FullName(),
			"type":    fmt.Sprintf("%T", p),
		}).Debug("Converting package to interface")
	}
	return result
}

// Convert map[cache.Package]struct{} to map[*Package]struct{} with improved logging and error handling
func toPackageMap(in map[cache.Package]struct{}) map[*Package]struct{} {
	result := make(map[*Package]struct{})
	for p := range in {
		if p == nil {
			log.Warn("Nil package encountered in map conversion")
			continue
		}

		pkg, ok := p.(*Package)
		if !ok {
			log.WithFields(log.Fields{
				"package": p.FullName(),
				"type":    fmt.Sprintf("%T", p),
			}).Warn("Failed to convert cache.Package to *Package")
			continue
		}

		result[pkg] = struct{}{}
		log.WithField("package", pkg.FullName()).Debug("Successfully converted package in map")
	}
	return result
}

// TarOptions represents configuration options for creating tar archives
type TarOptions struct {
	// OutputFile is the path to the output .tar or .tar.gz file
	OutputFile string

	// SourcePaths are the files/directories to include in the archive
	SourcePaths []string

	// WorkingDir changes to this directory before archiving (-C flag)
	WorkingDir string

	// UseCompression determines whether to apply compression
	UseCompression bool

	// FilesFrom specifies a file containing a list of files to include
	FilesFrom string
}

// WithOutputFile sets the output file path for the tar archive
func WithOutputFile(path string) func(*TarOptions) {
	return func(opts *TarOptions) {
		opts.OutputFile = path
	}
}

// WithSourcePaths adds files or directories to include in the archive
func WithSourcePaths(paths ...string) func(*TarOptions) {
	return func(opts *TarOptions) {
		opts.SourcePaths = append(opts.SourcePaths, paths...)
	}
}

// WithWorkingDir sets the working directory for the tar command
func WithWorkingDir(dir string) func(*TarOptions) {
	return func(opts *TarOptions) {
		opts.WorkingDir = dir
	}
}

// WithCompression enables compression for the tar archive
func WithCompression(enabled bool) func(*TarOptions) {
	return func(opts *TarOptions) {
		opts.UseCompression = enabled
	}
}

// WithFilesFrom specifies a file containing the list of files to archive
func WithFilesFrom(filePath string) func(*TarOptions) {
	return func(opts *TarOptions) {
		opts.FilesFrom = filePath
	}
}

// BuildTarCommand creates a platform-optimized tar command with the given options
func BuildTarCommand(options ...func(*TarOptions)) []string {
	// Initialize default options
	opts := &TarOptions{
		UseCompression: true, // Default to using compression
	}

	// Apply all option functions
	for _, option := range options {
		option(opts)
	}

	// Start building the command
	cmd := []string{"tar"}

	// Add Linux-specific optimizations
	if runtime.GOOS == "linux" {
		cmd = append(cmd, "--sparse")
	}

	// Handle files-from case specially
	if opts.FilesFrom != "" {
		return append(cmd, "--files-from", opts.FilesFrom)
	}

	// Basic create command
	if opts.UseCompression {
		if !strings.HasSuffix(opts.OutputFile, ".gz") {
			opts.OutputFile = opts.OutputFile + ".gz"
		}
	}

	cmd = append(cmd, "-cf", opts.OutputFile)

	// Add working directory if specified
	if opts.WorkingDir != "" {
		cmd = append(cmd, "-C", opts.WorkingDir)
	}

	// Add compression if needed
	if opts.UseCompression {
		cmd = append(cmd, fmt.Sprintf("--use-compress-program=%v", compressor))
	}

	// Add source paths (or "." if none specified)
	if len(opts.SourcePaths) > 0 {
		cmd = append(cmd, opts.SourcePaths...)
	} else {
		cmd = append(cmd, ".")
	}

	return cmd
}

// UnTarOptions represents configuration options for extracting tar archives
type UnTarOptions struct {
	// InputFile is the path to the .tar or .tar.gz file to extract
	InputFile string

	// TargetDir is the directory where files should be extracted
	TargetDir string

	// PreserveSameOwner determines whether to preserve file ownership
	PreserveSameOwner bool

	// AutoDetectCompression will check if the file is compressed
	AutoDetectCompression bool
}

// WithInputFile sets the input archive file path
func WithInputFile(path string) func(*UnTarOptions) {
	return func(opts *UnTarOptions) {
		opts.InputFile = path
	}
}

// WithTargetDir sets the directory where files will be extracted
func WithTargetDir(dir string) func(*UnTarOptions) {
	return func(opts *UnTarOptions) {
		opts.TargetDir = dir
	}
}

// WithPreserveSameOwner enables preserving file ownership
func WithPreserveSameOwner(preserve bool) func(*UnTarOptions) {
	return func(opts *UnTarOptions) {
		opts.PreserveSameOwner = preserve
	}
}

// WithAutoDetectCompression enables automatic detection of file compression
func WithAutoDetectCompression(detect bool) func(*UnTarOptions) {
	return func(opts *UnTarOptions) {
		opts.AutoDetectCompression = detect
	}
}

// isCompressedFile checks if a file is compressed by examining its header
func isCompressedFile(filepath string) (bool, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return false, fmt.Errorf("failed to open file for compression detection: %w", err)
	}
	defer file.Close()

	// Read the first few bytes to check for gzip magic number (1F 8B)
	header := make([]byte, 2)
	_, err = file.Read(header)
	if err != nil {
		return false, fmt.Errorf("failed to read file header: %w", err)
	}

	// Check for gzip magic number
	return header[0] == 0x1F && header[1] == 0x8B, nil
}

// BuildUnTarCommand creates a command to extract tar archives
func BuildUnTarCommand(options ...func(*UnTarOptions)) ([]string, error) {
	// Initialize default options
	opts := &UnTarOptions{
		PreserveSameOwner:     false, // Default to not preserving ownership
		AutoDetectCompression: true,  // Default to auto-detecting compression
	}

	// Apply all option functions
	for _, option := range options {
		option(opts)
	}

	// Start building the command
	cmd := []string{"tar"}

	// Add Linux-specific optimizations
	if runtime.GOOS == "linux" {
		cmd = append(cmd, "--sparse")
	}

	// Basic extraction command
	cmd = append(cmd, "-xf", opts.InputFile)

	// Add ownership flag if needed
	if !opts.PreserveSameOwner {
		cmd = append(cmd, "--no-same-owner")
	}

	// Add target directory if specified
	if opts.TargetDir != "" {
		cmd = append(cmd, "-C", opts.TargetDir)
	}

	// Handle compression if needed
	if opts.AutoDetectCompression {
		isCompressed, err := isCompressedFile(opts.InputFile)
		if err != nil {
			return nil, err
		}
		if isCompressed {
			// Use the same compressor as in BuildTarCommand but with decompression flag
			decompressFlag := fmt.Sprintf("--use-compress-program=%v -d", compressor)
			cmd = append(cmd, decompressFlag)
		}
	}

	return cmd, nil
}
