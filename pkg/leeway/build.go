package leeway

import (
	"archive/tar"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/gitpod-io/leeway/pkg/gokart"
	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/opencontainers/runc/libcontainer/specconv"
	"github.com/opencontainers/runtime-spec/specs-go"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/semaphore"
	"golang.org/x/xerrors"
	"gopkg.in/yaml.v3"
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
	// PackageBuilt means the package has been built already
	PackageBuilt PackageBuildStatus = "built"
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
		buildDir = filepath.Join(os.TempDir(), "build")
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
	LocalCache             Cache
	RemoteCache            RemoteCache
	AdditionalRemoteCaches []RemoteCache
	Reporter               Reporter
	DryRun                 bool
	BuildPlan              io.Writer
	DontTest               bool
	MaxConcurrentTasks     int64
	CoverageOutputPath     string
	DontRetag              bool
	DockerBuildOptions     *DockerBuildOptions
	JailedExecution        bool

	context *buildContext
}

// DockerBuildOptions are options passed to "docker build"
type DockerBuildOptions map[string]string

// BuildOption configures the build behaviour
type BuildOption func(*buildOptions) error

// WithLocalCache configures the local cache
func WithLocalCache(cache Cache) BuildOption {
	return func(opts *buildOptions) error {
		opts.LocalCache = cache
		return nil
	}
}

// WithRemoteCache configures the remote cache
func WithRemoteCache(cache RemoteCache) BuildOption {
	return func(opts *buildOptions) error {
		opts.RemoteCache = cache
		return nil
	}
}

// WithAdditionalRemoteCaches configures the remote cache
func WithAdditionalRemoteCaches(caches []RemoteCache) BuildOption {
	return func(opts *buildOptions) error {
		opts.AdditionalRemoteCaches = caches
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

// WithDontRetag disables the Docker image retagging
func WithDontRetag(dontRetag bool) BuildOption {
	return func(opts *buildOptions) error {
		opts.DontRetag = dontRetag
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
		RemoteCache: &NoRemoteCache{},
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

	requirements := pkg.GetTransitiveDependencies()
	allpkg := append(requirements, pkg)

	// respect per-package cache level when downloading from remote cache
	remotelyCachedReq := make([]*Package, 0, len(requirements))
	remotelyCachedReq = append(remotelyCachedReq, requirements...)

	err = options.RemoteCache.Download(ctx.LocalCache, remotelyCachedReq)
	if err != nil {
		return err
	}

	// Download only downloads packages that do not exist locally, yet
	for _, arc := range options.AdditionalRemoteCaches {
		err = arc.Download(ctx.LocalCache, remotelyCachedReq)
		if err != nil {
			return err
		}
	}

	pkgstatus := make(map[*Package]PackageBuildStatus)
	unresolvedArgs := make(map[string][]string)
	for _, dep := range allpkg {
		_, exists := ctx.LocalCache.Location(dep)
		if dep.Ephemeral {
			// ephemeral packages are never built at the begining of a build
			pkgstatus[dep] = PackageNotBuiltYet
		} else if exists {
			pkgstatus[dep] = PackageBuilt
		} else {
			pkgstatus[dep] = PackageNotBuiltYet
		}

		if exists {
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
	options.Reporter.BuildStarted(pkg, pkgstatus)
	defer func(err *error) {
		options.Reporter.BuildFinished(pkg, *err)
	}(&err)

	if len(unresolvedArgs) != 0 {
		var msg string
		for arg, pkgs := range unresolvedArgs {
			cleanArg := strings.TrimSuffix(strings.TrimPrefix(arg, "${"), "}")
			msg += fmt.Sprintf("cannot build with unresolved argument \"%s\": use -D%s=value to set the argument\n\t%s appears in %s\n\n", arg, cleanArg, arg, strings.Join(pkgs, ", "))
		}
		return xerrors.Errorf(msg)
	}

	if options.BuildPlan != nil {
		log.Debug("writing build plan")
		err = writeBuildPlan(options.BuildPlan, pkg, pkgstatus)
		if err != nil {
			return err
		}
	}

	if options.DryRun {
		// This is a dry-run. We've prepared everything for the build but do not execute the build itself.
		return nil
	}

	buildErr := pkg.build(ctx)
	cacheErr := options.RemoteCache.Upload(ctx.LocalCache, ctx.GetNewPackagesForCache())

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

func (p *Package) buildDependencies(buildctx *buildContext) (err error) {
	deps := p.GetDependencies()
	if deps == nil {
		return xerrors.Errorf("package \"%s\" is not linked", p.FullName())
	}

	failchan := make(chan error)
	donechan := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(len(p.GetDependencies()))
	for _, dep := range p.GetDependencies() {
		go func(dep *Package) {
			err := dep.build(buildctx)
			if err != nil {
				failchan <- err
			}
			wg.Done()
		}(dep)
	}
	go func() {
		wg.Wait()
		donechan <- struct{}{}
	}()

	select {
	case err := <-failchan:
		return err
	case <-donechan:
		return nil
	}
}

func (p *Package) build(buildctx *buildContext) (err error) {
	artifact, alreadyBuilt := buildctx.LocalCache.Location(p)
	if p.Ephemeral {
		// ephemeral packages always require a rebuild
	} else if alreadyBuilt {
		// some package types still need to do work even if we find their prior build artifact in the cache.
		if p.Type == DockerPackage && !buildctx.DontRetag {
			doBuild := buildctx.ObtainBuildLock(p)
			if !doBuild {
				return nil
			}
			defer buildctx.ReleaseBuildLock(p)

			err = p.retagDocker(buildctx, filepath.Dir(artifact), artifact)
			if err != nil {
				log.WithError(err).Warn("cannot re-use prior build artifact - building afresh.")
			} else {
				return
			}
		} else {
			log.WithField("package", p.FullName()).Debug("already built")
			return nil
		}
	}

	doBuild := buildctx.ObtainBuildLock(p)
	if !doBuild {
		return nil
	}
	defer buildctx.ReleaseBuildLock(p)

	version, err := p.Version()
	if err != nil {
		return err
	}

	err = p.buildDependencies(buildctx)
	if err != nil {
		return err
	}

	buildctx.Reporter.PackageBuildStarted(p)
	defer func(err *error) {
		buildctx.Reporter.PackageBuildFinished(p, *err)
	}(&err)

	pkgdir := p.FilesystemSafeName() + "." + version
	builddir := filepath.Join(buildctx.BuildDir(), pkgdir)
	if _, err := os.Stat(builddir); !os.IsNotExist(err) {
		err := os.RemoveAll(builddir)
		if err != nil {
			return err
		}
	}
	err = os.MkdirAll(builddir, 0755)
	if err != nil {
		return err
	}

	if len(p.Sources) > 0 {
		var (
			parentedFiles    []string
			notParentedFiles []string
		)
		for _, src := range p.Sources {
			prefix := p.C.Origin + "/"
			if strings.HasPrefix(src, prefix) {
				parentedFiles = append(parentedFiles, strings.TrimPrefix(src, prefix))
			} else {
				notParentedFiles = append(notParentedFiles, src)
			}
		}

		if len(parentedFiles) > 0 {
			parentedFiles = append([]string{"--parents"}, parentedFiles...)
			err = run(buildctx.Reporter, p, nil, p.C.Origin, "cp", append(parentedFiles, builddir)...)
			if err != nil {
				return err
			}
		}

		if len(notParentedFiles) > 0 {
			err = run(buildctx.Reporter, p, nil, p.C.Origin, "cp", append(notParentedFiles, builddir)...)
			if err != nil {
				return err
			}
		}
	}

	var (
		result, _ = buildctx.LocalCache.Location(p)
		bld       *packageBuild
		sources   fileset
	)

	buildctx.LimitConcurrentBuilds()
	defer buildctx.ReleaseConcurrentBuild()

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
		err = xerrors.Errorf("cannot build package type: %s", p.Type)
	}
	if err != nil {
		return err
	}

	now := time.Now()
	if p.C.W.Provenance.Enabled {
		sources, err = computeFileset(builddir)
		if err != nil {
			return err
		}
	}

	err = executeCommandsForPackage(buildctx, p, builddir, bld.BuildCommands)
	if err != nil {
		return err
	}

	if p.C.W.Provenance.Enabled {
		var (
			subjects  []in_toto.Subject
			resultDir = builddir
		)
		if bld.Subjects != nil {
			subjects, err = bld.Subjects()
			if err != nil {
				return err
			}
		} else if bld.PostBuild != nil {
			subjects, resultDir, err = bld.PostBuild(sources)
			if err != nil {
				return err
			}
		} else {
			postBuild, err := computeFileset(builddir)
			if err != nil {
				return err
			}
			subjects, err = postBuild.Sub(sources).Subjects(builddir)
			if err != nil {
				return err
			}
		}

		err = writeProvenance(p, buildctx, resultDir, subjects, now)
		if err != nil {
			return err
		}
	}

	err = executeCommandsForPackage(buildctx, p, builddir, bld.PackageCommands)
	if err != nil {
		return err
	}

	err = buildctx.RegisterNewlyBuilt(p)
	if err != nil {
		return err
	}

	return err
}

type packageBuild struct {
	BuildCommands   [][]string
	PackageCommands [][]string

	// If PostBuild is not nil but Subjects is, PostBuild is used
	// to compute the post build fileset for provenance subject computation.
	PostBuild func(sources fileset) (subj []in_toto.Subject, absResultDir string, err error)
	// If Subjects is not nil it's used to compute the provenance subjects of the
	// package build. This field takes precedence over PostBuild
	Subjects func() ([]in_toto.Subject, error)
}

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

// buildYarn implements the build process for Typescript packages.
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

	var commands [][]string
	if cfg.Packaging == YarnOfflineMirror {
		err := os.Mkdir(filepath.Join(wd, "_mirror"), 0755)
		if err != nil {
			return nil, err
		}

		commands = append(commands, [][]string{
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
			commands = append(commands, []string{"cp", builtpkg, filepath.Join("_mirror", fn)})
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
			commands = append(commands, []string{"sh", "-c", fmt.Sprintf("tar Ozfx %s package/%s | sed '/resolved /c\\  resolved \"file://%s\"' >> yarn.lock", builtpkg, pkgYarnLock, builtpkg)})
		} else {
			commands = append(commands, [][]string{
				{"mkdir", tgt},
				{"tar", "xfz", builtpkg, "--no-same-owner", "-C", tgt},
			}...)
		}
	}

	pkgJSONFilename := filepath.Join(wd, "package.json")
	var packageJSON map[string]interface{}
	fc, err := ioutil.ReadFile(pkgJSONFilename)
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
		err = ioutil.WriteFile(pkgJSONFilename, fc, 0644)
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
	commands = append(commands, p.PreparationCommands...)

	// The yarn cache cannot handly conccurency proplery and needs to be looked.
	// Make sure that all our yarn install calls lock the yarn cache.
	yarnMutex := os.Getenv(EnvvarYarnMutex)
	if yarnMutex == "" {
		log.Debugf("%s is not set, defaulting to \"network\"", EnvvarYarnMutex)
		yarnMutex = "network"
	}
	yarnCache := filepath.Join(buildctx.BuildDir(), fmt.Sprintf("yarn-cache-%s", buildctx.buildID))
	if len(cfg.Commands.Install) == 0 {
		commands = append(commands, []string{"yarn", "install", "--mutex", yarnMutex, "--cache-folder", yarnCache})
	} else {
		commands = append(commands, cfg.Commands.Install)
	}
	if len(cfg.Commands.Build) == 0 {
		commands = append(commands, []string{"yarn", "build"})
	} else {
		commands = append(commands, cfg.Commands.Build)
	}
	if !cfg.DontTest && !buildctx.DontTest {
		if len(cfg.Commands.Test) == 0 {
			commands = append(commands, []string{"yarn", "test"})
		} else {
			commands = append(commands, cfg.Commands.Test)
		}
	}

	res := &packageBuild{
		BuildCommands: commands,
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
			err = ioutil.WriteFile(filepath.Join(wd, "_mirror", fn), []byte(script), 0755)
			if err != nil {
				return nil, err
			}
		}

		dst := filepath.Join("_mirror", fmt.Sprintf("%s.tar.gz", p.FilesystemSafeName()))
		pkgCommands = append(pkgCommands, [][]string{
			{"sh", "-c", fmt.Sprintf("yarn generate-lock-entry --resolved file://./%s > _mirror/content_yarn.lock", dst)},
			{"sh", "-c", "cat yarn.lock >> _mirror/content_yarn.lock"},
			{"yarn", "pack", "--filename", dst},
			{"tar", "cfz", result, "-C", "_mirror", "."},
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
		err = ioutil.WriteFile(filepath.Join(wd, "_pkg", "package.json"), []byte(fmt.Sprintf(installerPackageJSONTemplate, version, pkgname, pkgversion)), 0755)
		if err != nil {
			return nil, err
		}

		pkg := filepath.Join(wd, "package.tar.tz")
		pkgCommands = append(pkgCommands, [][]string{
			{"sh", "-c", fmt.Sprintf("yarn generate-lock-entry --resolved file://%s > %s", pkg, pkgYarnLock)},
			{"yarn", "pack", "--filename", pkg},
			{"sh", "-c", fmt.Sprintf("cat yarn.lock %s > _pkg/yarn.lock", pkgYarnLock)},
			{"yarn", "--cwd", "_pkg", "install", "--prod", "--frozen-lockfile"},
			{"tar", "cfz", result, "-C", "_pkg", "."},
		}...)
		resultDir = "_pkg"
	} else if cfg.Packaging == YarnArchive {
		pkgCommands = append(pkgCommands, []string{"tar", "cfz", result, "."})
	} else {
		return nil, xerrors.Errorf("unknown Typescript packaging: %s", cfg.Packaging)
	}
	res.PackageCommands = pkgCommands
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

	if _, err := os.Stat(filepath.Join(p.C.Origin, "go.mod")); os.IsNotExist(err) {
		return nil, xerrors.Errorf("can only build Go modules (missing go.mod file)")
	}

	var (
		commands  [][]string
		goCommand = "go"
	)
	if cfg.GoVersion != "" {
		goCommand = cfg.GoVersion
		commands = append(commands, [][]string{
			{"sh", "-c", "GO111MODULE=off go get golang.org/dl/" + cfg.GoVersion},
			{goCommand, "download"},
		}...)
	}

	transdep := p.GetTransitiveDependencies()
	if len(transdep) > 0 {
		commands = append(commands, []string{"mkdir", "_deps"})

		for _, dep := range transdep {
			builtpkg, ok := buildctx.LocalCache.Location(dep)
			if !ok {
				return nil, PkgNotBuiltErr{dep}
			}

			tgt := filepath.Join("_deps", p.BuildLayoutLocation(dep))
			commands = append(commands, [][]string{
				{"mkdir", tgt},
				{"tar", "xfz", builtpkg, "--no-same-owner", "-C", tgt},
			}...)

			if dep.Type != GoPackage {
				continue
			}

			commands = append(commands, []string{"sh", "-c", fmt.Sprintf("%s mod edit -replace $(cd %s; grep module go.mod | cut -d ' ' -f 2 | head -n1)=./%s", goCommand, tgt, tgt)})
		}
	}
	commands = append(commands, p.PreparationCommands...)
	if cfg.Generate {
		commands = append(commands, []string{goCommand, "generate", "-v", "./..."})
	}
	commands = append(commands, []string{goCommand, "mod", "download", "-x"})

	if !cfg.DontCheckGoFmt {
		commands = append(commands, []string{"sh", "-c", `if [ ! $(go fmt ./... | wc -l) -eq 0 ]; then echo; echo; echo please gofmt your code; echo; echo; exit 1; fi`})
	}
	if !cfg.DontLint {
		if len(cfg.LintCommand) == 0 {
			commands = append(commands, []string{"golangci-lint", "run"})
		} else {
			commands = append(commands, cfg.LintCommand)
		}
	}
	if cfg.GoKart.Enabled {
		var apiDepPtn *regexp.Regexp
		if cfg.GoKart.APIDepsPattern == "" {
			apiDepPtn = regexp.MustCompile(`\/api`)
		} else {
			apiDepPtn, err = regexp.Compile(cfg.GoKart.APIDepsPattern)
			if err != nil {
				return nil, err
			}
			log.WithField("exp", apiDepPtn).Debug("using custom api dependency pattern for GoKart")
		}
		err = gokart.BuildAnalyzerConfig(wd, apiDepPtn)
		if err != nil {
			return nil, err
		}
		commands = append(commands, []string{"gokart", "scan", "-i", gokart.AnalyzerFilename, "-x"})
	}
	if !cfg.DontTest && !buildctx.DontTest {
		testArgs := []string{goCommand, "test", "-v"}
		if buildctx.buildOptions.CoverageOutputPath != "" {
			testArgs = append(testArgs, fmt.Sprintf("-coverprofile=%v", codecovComponentName(p.FullName())))
		}

		testArgs = append(testArgs, "./...")

		commands = append(commands, [][]string{
			// we build the test binaries in addition to running the tests regularly, so that downstream packages can run the tests in different environments
			{"sh", "-c", "mkdir _tests; for i in $(" + goCommand + " list ./...); do " + goCommand + " test -c $i; [ -e $(basename $i).test ] && mv $(basename $i).test _tests; true; done"},
			testArgs,
		}...)
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
		commands = append(commands, buildCmd)
	}
	commands = append(commands, []string{"rm", "-rf", "_deps"})

	pkgCommands := [][]string{
		{"tar", "cfz", result, "."},
	}
	if !cfg.DontTest && !buildctx.DontTest {
		pkgCommands = append(pkgCommands, [][]string{
			{"sh", "-c", fmt.Sprintf(`if [ -f "%v" ]; then cp -f %v %v; fi`, codecovComponentName(p.FullName()), codecovComponentName(p.FullName()), buildctx.buildOptions.CoverageOutputPath)},
		}...)
	}

	return &packageBuild{
		BuildCommands:   commands,
		PackageCommands: pkgCommands,
	}, nil
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

	var buildCommands [][]string
	buildCommands = append(buildCommands, []string{"cp", dockerfile, "Dockerfile"})
	for _, dep := range p.GetDependencies() {
		fn, exists := buildctx.LocalCache.Location(dep)
		if !exists {
			return nil, PkgNotBuiltErr{dep}
		}

		tgt := p.BuildLayoutLocation(dep)
		buildCommands = append(buildCommands, [][]string{
			{"mkdir", tgt},
			{"tar", "xfz", fn, "--no-same-owner", "-C", tgt},
		}...)
	}

	buildCommands = append(buildCommands, p.PreparationCommands...)

	version, err := p.Version()
	if err != nil {
		return nil, err
	}

	buildcmd := []string{"docker", "build", "--pull", "-t", version}
	for arg, val := range cfg.BuildArgs {
		buildcmd = append(buildcmd, "--build-arg", fmt.Sprintf("%s=%s", arg, val))
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
	buildCommands = append(buildCommands, buildcmd)

	if len(cfg.Image) == 0 {
		// we don't push the image, let's export it
		ef := strings.TrimSuffix(result, ".gz")
		buildCommands = append(buildCommands, [][]string{
			{"docker", "save", "-o", ef, version},
		}...)
	}

	res = &packageBuild{
		BuildCommands: buildCommands,
	}

	var pkgCommands [][]string
	if len(cfg.Image) == 0 {
		// We've already built the build artifact by exporting the archive using "docker save"
		// At the very least we need to add the provenance bundle to that archive.
		ef := strings.TrimSuffix(result, ".gz")
		res.PostBuild = dockerExportPostBuild(wd, ef)

		res.PackageCommands = [][]string{
			{"tar", "fr", ef, "./" + provenanceBundleFilename},
			{"gzip", ef},
		}
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

		archiveCmd := []string{"tar", "cfz", result, "./" + dockerImageNamesFiles, "./" + dockerMetadataFile}
		if p.C.W.Provenance.Enabled {
			archiveCmd = append(archiveCmd, "./"+provenanceBundleFilename)
		}
		pkgCommands = append(pkgCommands, archiveCmd)

		res.PackageCommands = pkgCommands
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
			digest := in_toto.DigestSet{
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
				Digest: in_toto.DigestSet{"sha256": hex.EncodeToString(hash.Sum(nil))},
			})
		}

		return subj, builddir, nil
	}
}

// buildGeneric implements the build process for generic packages.
// If you change anything in this process that's not backwards compatible, make sure you increment BuildGenericProccessVersion.
func (p *Package) buildGeneric(buildctx *buildContext, wd, result string) (res *packageBuild, err error) {
	cfg, ok := p.Config.(GenericPkgConfig)
	if !ok {
		return nil, xerrors.Errorf("package should have generic config")
	}

	// shortcut: no command == empty package
	if len(cfg.Commands) == 0 && len(cfg.Test) == 0 {
		log.WithField("package", p.FullName()).Debug("package has no commands nor test - creating empty tar")

		// if provenance is enabled, we have to make sure we capture the bundle
		if p.C.W.Provenance.Enabled {
			return &packageBuild{
				PackageCommands: [][]string{{"tar", "cfz", result, "./" + provenanceBundleFilename}},
			}, nil
		}

		return &packageBuild{
			PackageCommands: [][]string{{"tar", "cfz", result, "--files-from", "/dev/null"}},
		}, nil
	}

	var commands [][]string
	for _, dep := range p.GetDependencies() {
		fn, exists := buildctx.LocalCache.Location(dep)
		if !exists {
			return nil, PkgNotBuiltErr{dep}
		}

		tgt := p.BuildLayoutLocation(dep)
		commands = append(commands, [][]string{
			{"mkdir", tgt},
			{"tar", "xfz", fn, "--no-same-owner", "-C", tgt},
		}...)
	}

	commands = append(commands, p.PreparationCommands...)
	commands = append(commands, cfg.Commands...)
	if !cfg.DontTest && !buildctx.DontTest {
		commands = append(commands, cfg.Test...)
	}

	return &packageBuild{
		BuildCommands:   commands,
		PackageCommands: [][]string{{"tar", "cfz", result, "."}},
	}, nil
}

// retagDocker is called when we already have the build artifact for this package (and version)
// in the build cache. This function makes sure that if the build arguments changed the name of the
// Docker image this build time, we just re-tag the image.
func (p *Package) retagDocker(buildctx *buildContext, wd, prev string) (err error) {
	buildctx.LimitConcurrentBuilds()
	defer buildctx.ReleaseConcurrentBuild()

	cfg, ok := p.Config.(DockerPkgConfig)
	if !ok {
		return xerrors.Errorf("package should have Docker config")
	}
	if len(cfg.Image) == 0 {
		// this is not a pushed Docker image and as such needs no re-use
		log.WithField("package", p.FullName()).Debug("already built")
		return
	}

	// the previous build artifact should contain the name of the original image. Let's read that name/those names.
	if _, err := os.Stat(prev); os.IsNotExist(err) {
		return err
	}
	cmd := exec.Command("tar", "Ozfx", prev, "--no-same-owner", dockerImageNamesFiles)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return err
	}
	names := strings.Split(string(out), "\n")
	if len(names) == 0 {
		return xerrors.Errorf("build artifact is invalid")
	}

	commands := [][]string{
		{"docker", "pull", names[0]},
	}
	var needsRetagging bool
	for _, img := range cfg.Image {
		var found bool
		for _, nme := range names {
			if nme == img {
				found = true
				break
			}
		}
		if found {
			continue
		}

		needsRetagging = true
		commands = append(commands, [][]string{
			{"docker", "tag", names[0], img},
			{"docker", "push", img},
		}...)
	}
	if !needsRetagging {
		log.WithField("package", p.FullName()).Debug("already built")
		return
	}

	buildctx.Reporter.PackageBuildStarted(p)
	defer func(err *error) {
		buildctx.Reporter.PackageBuildFinished(p, *err)
	}(&err)

	err = executeCommandsForPackage(buildctx, p, wd, commands)
	if err != nil {
		return err
	}
	return nil
}

func executeCommandsForPackage(buildctx *buildContext, p *Package, wd string, commands [][]string) error {
	if buildctx.JailedExecution {
		return executeCommandsForPackageSafe(buildctx, p, wd, commands)
	}

	env := append(os.Environ(), p.Environment...)
	for _, cmd := range commands {
		err := run(buildctx.Reporter, p, env, wd, cmd[0], cmd[1:]...)
		if err != nil {
			return err
		}
	}
	return nil
}

func executeCommandsForPackageSafe(buildctx *buildContext, p *Package, wd string, commands [][]string) error {
	tmpdir, err := os.MkdirTemp("", "leeway-*")
	if err != nil {
		return err
	}

	jc, err := json.Marshal(commands)
	if err != nil {
		return err
	}
	commandsFN := filepath.Join(tmpdir, "commands")
	err = ioutil.WriteFile(commandsFN, []byte(base64.StdEncoding.EncodeToString(jc)), 0644)
	if err != nil {
		return err
	}

	if !log.IsLevelEnabled(log.DebugLevel) {
		defer os.RemoveAll(tmpdir)
	}

	log.WithField("tmpdir", tmpdir).WithField("package", p.FullName()).Debug("preparing build runc environment")
	err = os.MkdirAll(filepath.Join(tmpdir, "rootfs"), 0755)
	if err != nil {
		return err
	}

	version, err := p.Version()
	if err != nil {
		return err
	}
	name := fmt.Sprintf("b%s", version)

	spec := specconv.Example()
	specconv.ToRootless(spec)

	// we assemble the root filesystem from the outside world
	for _, d := range []string{"home", "bin", "dev", "etc", "lib", "lib64", "opt", "sbin", "sys", "usr", "var"} {
		spec.Mounts = append(spec.Mounts, specs.Mount{
			Destination: "/" + d,
			Source:      "/" + d,
			Type:        "bind",
			Options:     []string{"rbind", "rprivate"},
		})
	}

	spec.Mounts = append(spec.Mounts, specs.Mount{Destination: "/build", Source: wd, Type: "bind", Options: []string{"bind", "private"}})
	spec.Mounts = append(spec.Mounts, specs.Mount{Destination: "/commands", Source: commandsFN, Type: "bind", Options: []string{"bind", "private"}})

	for _, p := range []string{"tmp", "root"} {
		fn := filepath.Join(tmpdir, p)
		err = os.MkdirAll(fn, 0777)
		if err != nil {
			return err
		}
		spec.Mounts = append(spec.Mounts, specs.Mount{Destination: "/" + p, Source: fn, Type: "bind", Options: []string{"bind", "private"}})
	}

	buildCache, _ := buildctx.LocalCache.Location(p)
	buildCache = filepath.Dir(buildCache)
	spec.Mounts = append(spec.Mounts, specs.Mount{Destination: buildCache, Source: buildCache, Type: "bind", Options: []string{"bind", "private"}})

	self, err := os.Executable()
	if err != nil {
		return err
	}
	spec.Mounts = append(spec.Mounts, specs.Mount{Destination: "/leeway", Source: self, Type: "bind", Options: []string{"bind", "private"}})

	if p := os.Getenv("GOPATH"); p != "" {
		spec.Mounts = append(spec.Mounts, specs.Mount{Destination: p, Source: p, Type: "bind", Options: []string{"bind", "private"}})
	}
	if p := os.Getenv("GOROOT"); p != "" {
		spec.Mounts = append(spec.Mounts, specs.Mount{Destination: p, Source: p, Type: "bind", Options: []string{"bind", "private"}})
	}
	if p := os.Getenv("DOCKER_HOST"); strings.HasPrefix(p, "file://") {
		p = strings.TrimPrefix(p, "file://")
		spec.Mounts = append(spec.Mounts, specs.Mount{Destination: p, Source: p, Type: "bind", Options: []string{"bind", "private"}})
	} else if _, err := os.Stat("/var/run/docker.sock"); err == nil {
		p = "/var/run/docker.sock"
		spec.Mounts = append(spec.Mounts, specs.Mount{Destination: p, Source: p, Type: "bind", Options: []string{"bind", "private"}})
	}

	var env []string
	for _, e := range []string{"PATH", "TERM", "GOROOT", "GOPATH"} {
		val := os.Getenv(e)
		if val == "" {
			continue
		}
		env = append(env, fmt.Sprintf("%s=%s", e, val))
	}

	spec.Hostname = name
	spec.Process.Terminal = false
	spec.Process.NoNewPrivileges = true
	spec.Process.Args = []string{"/leeway", "plumbing", "exec", "/commands"}
	if log.IsLevelEnabled(log.DebugLevel) {
		spec.Process.Args = append(spec.Process.Args, "--verbose")

	}
	spec.Process.Cwd = "/build"
	spec.Process.Env = env

	fc, err := json.MarshalIndent(spec, "", "  ")
	if err != nil {
		return err
	}
	err = os.WriteFile(filepath.Join(tmpdir, "config.json"), fc, 0644)
	if err != nil {
		return err
	}

	args := []string{
		"--root", "state",
		"--log-format", "json",
	}
	if log.IsLevelEnabled(log.DebugLevel) {
		args = append(args, "--debug")
	}
	args = append(args,
		"run", name,
	)

	cmd := exec.Command("runc", args...)
	cmd.Dir = tmpdir
	cmd.Stdout = &reporterStream{R: buildctx.Reporter, P: p, IsErr: false}
	cmd.Stderr = &reporterStream{R: buildctx.Reporter, P: p, IsErr: true}
	return cmd.Run()
}

func run(rep Reporter, p *Package, env []string, cwd, name string, args ...string) error {
	log.WithField("command", strings.Join(append([]string{name}, args...), " ")).Debug("running")

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
	s.R.PackageBuildLog(s.P, s.IsErr, buf)
	return len(buf), nil
}

func codecovComponentName(name string) string {
	reg, _ := regexp.Compile("[^a-zA-Z0-9]+")
	component := reg.ReplaceAllString(name, "-")
	return strings.ToLower(component + "-coverage.out")
}
