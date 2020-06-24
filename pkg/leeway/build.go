package leeway

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"
	"golang.org/x/xerrors"
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

type packageDuringBuild struct {
	P         *Package
	Status    PackageBuildStatus
	Locked    bool
	FromCache bool
}

type buildContext struct {
	buildOptions
	buildDir string

	mu                 sync.Mutex
	newlyBuiltPackages map[string]*Package

	pkgLockCond *sync.Cond
	pkgLocks    map[string]struct{}
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
)

// buildProcessVersions contain the current version of the respective build processes.
// Increment this value if you change any of the build procedures.
var buildProcessVersions = map[PackageType]int{
	TypescriptPackage: 5,
	GoPackage:         1,
	DockerPackage:     1,
	GenericPackage:    1,
}

func newBuildContext(options buildOptions) (ctx *buildContext, err error) {
	if options.context != nil {
		return options.context, nil
	}

	buildDir := os.Getenv(EnvvarBuildDir)
	if buildDir == "" {
		buildDir = filepath.Join(os.TempDir(), "build")
	}

	ctx = &buildContext{
		buildOptions:       options,
		buildDir:           buildDir,
		newlyBuiltPackages: make(map[string]*Package),
		pkgLockCond:        sync.NewCond(&sync.Mutex{}),
		pkgLocks:           make(map[string]struct{}),
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
	LocalCache  Cache
	RemoteCache RemoteCache
	Reporter    Reporter
	DryRun      bool
	BuildPlan   io.Writer
	DontTest    bool

	context *buildContext
}

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

	requirements := pkg.GetTransitiveDependencies()
	allpkg := append(requirements, pkg)

	// respect per-package cache level when downloading from remote cache
	remotelyCachedReq := make([]*Package, 0, len(requirements))
	for _, req := range requirements {
		remotelyCachedReq = append(remotelyCachedReq, req)
	}

	err = options.RemoteCache.Download(ctx.LocalCache, remotelyCachedReq)
	if err != nil {
		return err
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
		if p.Type == DockerPackage {
			doBuild := buildctx.ObtainBuildLock(p)
			if !doBuild {
				return nil
			}
			defer buildctx.ReleaseBuildLock(p)

			err = p.rebuildDocker(buildctx, filepath.Dir(artifact), artifact)
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
		cpargs := []string{"--parents"}
		for _, src := range p.Sources {
			cpargs = append(cpargs, strings.TrimPrefix(src, p.C.Origin+"/"))
		}
		cpargs = append(cpargs, builddir)
		err = run(buildctx.Reporter, p, nil, p.C.Origin, "cp", cpargs...)
		if err != nil {
			return err
		}
	}

	if len(p.PreparationCommands) > 0 {
		err = executeCommandsForPackage(buildctx, p, builddir, p.PreparationCommands)
		if err != nil {
			return err
		}
	}

	result, _ := buildctx.LocalCache.Location(p)

	switch p.Type {
	case TypescriptPackage:
		err = p.buildTypescript(buildctx, builddir, result)
	case GoPackage:
		err = p.buildGo(buildctx, builddir, result)
	case DockerPackage:
		err = p.buildDocker(buildctx, builddir, result)
	case GenericPackage:
		err = p.buildGeneric(buildctx, builddir, result)
	default:
		err = xerrors.Errorf("cannot build package type: %s", p.Type)
	}
	if err != nil {
		return err
	}

	err = buildctx.RegisterNewlyBuilt(p)
	if err != nil {
		return err
	}

	return err
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

yarn install --frozenlockfile --prod
rm yarn.lock
`

	installerPackageJSONTemplate = `{"name":"local","version":"%s","license":"UNLICENSED","dependencies":{"%s":"%s"}}`
)

// buildTypescript implements the build process for Typescript packages.
// If you change anything in this process that's not backwards compatible, make sure you increment buildProcessVersions accordingly.
func (p *Package) buildTypescript(buildctx *buildContext, wd, result string) (err error) {
	cfg, ok := p.Config.(TypescriptPkgConfig)
	if !ok {
		return xerrors.Errorf("package should have typescript config")
	}

	ok = false
	for _, src := range p.Sources {
		fn := filepath.Base(src)
		if fn == "package.json" {
			ok = true
			break
		}
	}
	if !ok {
		return xerrors.Errorf("%s: typescript packages must have a package.json", p.FullName())
	}

	version, err := p.Version()
	if err != nil {
		return err
	}

	var commands [][]string
	if cfg.YarnLock != "" {
		commands = append(commands, []string{"cp", filepath.Join(p.C.Origin, cfg.YarnLock), "."})
	}
	if cfg.TSConfig != "" {
		commands = append(commands, []string{"cp", filepath.Join(p.C.Origin, cfg.TSConfig), "."})
	}

	if cfg.Packaging == TypescriptOfflineMirror {
		err := os.Mkdir(filepath.Join(wd, "_mirror"), 0755)
		if err != nil {
			return err
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
			return PkgNotBuiltErr{deppkg}
		}
	}

	pkgYarnLock := "pkg-yarn.lock"
	for _, deppkg := range p.GetTransitiveDependencies() {
		if deppkg.Ephemeral {
			continue
		}

		builtpkg, ok := buildctx.LocalCache.Location(deppkg)
		if !ok {
			return PkgNotBuiltErr{deppkg}
		}

		tgt := deppkg.FilesystemSafeName()
		if cfg.Packaging == TypescriptOfflineMirror {
			fn := fmt.Sprintf("%s.tar.gz", tgt)
			commands = append(commands, []string{"cp", builtpkg, filepath.Join("_mirror", fn)})
			builtpkg = filepath.Join(wd, "_mirror", fn)
		}

		var isTSLibrary bool
		if deppkg.Type == TypescriptPackage {
			cfg, ok := deppkg.Config.(TypescriptPkgConfig)
			if ok && cfg.Packaging == TypescriptLibrary {
				isTSLibrary = true
			}
		}
		if isTSLibrary {
			// make previously built package availabe through yarn lock
			commands = append(commands, []string{"sh", "-c", fmt.Sprintf("tar Ozfx %s package/%s | sed '/resolved /c\\  resolved \"file://%s\"' >> yarn.lock", builtpkg, pkgYarnLock, builtpkg)})
		} else {
			commands = append(commands, [][]string{
				{"mkdir", tgt},
				{"tar", "xfz", builtpkg, "-C", tgt},
			}...)
		}
	}

	pkgJSONFilename := filepath.Join(wd, "package.json")
	var packageJSON map[string]interface{}
	fc, err := ioutil.ReadFile(pkgJSONFilename)
	if err != nil {
		return xerrors.Errorf("cannot patch package.json of typescript package: %w", err)
	}
	err = json.Unmarshal(fc, &packageJSON)
	if err != nil {
		return xerrors.Errorf("cannot patch package.json of typescript package: %w", err)
	}
	var modifiedPackageJSON bool
	if cfg.Packaging == TypescriptLibrary {
		// We can't modify the `yarn pack` generated tar file without runnign the risk of yarn blocking when attempting to unpack it again. Thus, we must include the pkgYarnLock in the npm
		// package we're building. To this end, we modify the package.json of the source package.
		var packageJSONFiles []interface{}
		if rfs, ok := packageJSON["files"]; ok {
			fs, ok := rfs.([]interface{})
			if !ok {
				fmt.Println(rfs)
				return xerrors.Errorf("invalid package.json: files section is not a list of strings")
			}
			packageJSONFiles = fs
		}
		packageJSONFiles = append(packageJSONFiles, pkgYarnLock)
		packageJSON["files"] = packageJSONFiles

		modifiedPackageJSON = true
	}
	if cfg.Packaging == TypescriptApp {
		// We have to give this package a unique version to make sure we do not "poison" the yarn cache with this particular application version.
		// The yarn package name and leeway package name do not have to be the same which makes it possible to "reuse" the npm package name for
		// different things. This yarn cache can't handle that.
		packageJSON["version"] = fmt.Sprintf("0.0.0-%s", version)

		modifiedPackageJSON = true
	}
	if modifiedPackageJSON {
		fc, err = json.Marshal(packageJSON)
		if err != nil {
			return xerrors.Errorf("cannot patch package.json of typescript package: %w", err)
		}
		err = ioutil.WriteFile(pkgJSONFilename, fc, 0644)
		if err != nil {
			return xerrors.Errorf("cannot patch package.json of typescript package: %w", err)
		}
	}
	pkgname, ok := packageJSON["name"].(string)
	if !ok {
		return xerrors.Errorf("name is not a string, but :v", pkgname)
	}
	pkgversion := packageJSON["version"]
	if pkgname == "" || pkgversion == "" {
		return xerrors.Errorf("name or version in package.json must not be empty")
	}

	// The yarn cache cannot handly conccurency proplery and needs to be looked.
	// Make sure that all our yarn install calls lock the yarn cache.
	yarnMutex := os.Getenv(EnvvarYarnMutex)
	if yarnMutex == "" {
		log.Debugf("%s is not set, defaulting to \"network\"", EnvvarYarnMutex)
		yarnMutex = "network"
	}
	yarnCache := filepath.Join(buildctx.BuildDir(), "yarn-cache")
	if len(cfg.Commands.Install) == 0 {
		commands = append(commands, []string{"yarn", "install", "--mutex", yarnMutex, "--cache-folder", yarnCache})
	} else {
		commands = append(commands, cfg.Commands.Install)
	}
	if len(cfg.Commands.Build) == 0 {
		commands = append(commands, []string{"npx", "tsc"})
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

	if cfg.Packaging == TypescriptOfflineMirror {
		builtinScripts := map[string]string{
			"get_yarn_lock.sh":       getYarnLockScript,
			"install.sh":             installScript,
			"installer-package.json": fmt.Sprintf(installerPackageJSONTemplate, version, pkgname, pkgversion),
		}
		for fn, script := range builtinScripts {
			err = ioutil.WriteFile(filepath.Join(wd, "_mirror", fn), []byte(script), 0755)
			if err != nil {
				return err
			}
		}

		dst := filepath.Join("_mirror", fmt.Sprintf("%s.tar.gz", p.FilesystemSafeName()))
		commands = append(commands, [][]string{
			{"sh", "-c", fmt.Sprintf("yarn generate-lock-entry --resolved file://./%s > _mirror/content_yarn.lock", dst)},
			{"sh", "-c", "cat yarn.lock >> _mirror/content_yarn.lock"},
			{"yarn", "pack", "--filename", dst},
			{"tar", "cfz", result, "-C", "_mirror", "."},
		}...)
	} else if cfg.Packaging == TypescriptLibrary {
		commands = append(commands, [][]string{
			{"sh", "-c", fmt.Sprintf("yarn generate-lock-entry --resolved file://%s > %s", result, pkgYarnLock)},
			{"yarn", "pack", "--filename", result},
		}...)
	} else if cfg.Packaging == TypescriptApp {
		err := os.Mkdir(filepath.Join(wd, "_pkg"), 0755)
		if err != nil {
			return err
		}
		err = ioutil.WriteFile(filepath.Join(wd, "_pkg", "package.json"), []byte(fmt.Sprintf(installerPackageJSONTemplate, version, pkgname, pkgversion)), 0755)
		if err != nil {
			return err
		}

		pkg := filepath.Join(wd, "package.tar.tz")
		commands = append(commands, [][]string{
			{"sh", "-c", fmt.Sprintf("yarn generate-lock-entry --resolved file://%s > %s", pkg, pkgYarnLock)},
			{"yarn", "pack", "--filename", pkg},
			{"sh", "-c", fmt.Sprintf("cat yarn.lock %s > _pkg/yarn.lock", pkgYarnLock)},
			{"yarn", "--cwd", "_pkg", "install", "--prod", "--frozen-lockfile"},
			{"tar", "cfz", result, "-C", "_pkg", "."},
		}...)
	} else if cfg.Packaging == TypescriptArchive {
		commands = append(commands, []string{"tar", "cfz", result, "."})
	} else {
		return xerrors.Errorf("unknown Typescript packaging: %s", cfg.Packaging)
	}

	return executeCommandsForPackage(buildctx, p, wd, commands)
}

// buildGo implements the build process for Go packages.
// If you change anything in this process that's not backwards compatible, make sure you increment buildProcessVersions accordingly.
func (p *Package) buildGo(buildctx *buildContext, wd, result string) (err error) {
	cfg, ok := p.Config.(GoPkgConfig)
	if !ok {
		return xerrors.Errorf("package should have Go config")
	}

	if _, err := os.Stat(filepath.Join(p.C.Origin, "go.mod")); os.IsNotExist(err) {
		return xerrors.Errorf("can only build Go modules (missing go.mod file)")
	}

	var commands [][]string
	if len(p.GetDependencies()) > 0 {
		commands = append(commands, []string{"mkdir", "_deps"})

		for _, dep := range p.dependencies {
			builtpkg, ok := buildctx.LocalCache.Location(dep)
			if !ok {
				return PkgNotBuiltErr{dep}
			}

			tgt := filepath.Join("_deps", dep.FilesystemSafeName())
			commands = append(commands, [][]string{
				{"mkdir", tgt},
				{"tar", "xfz", builtpkg, "-C", tgt},
			}...)

			if dep.Type != GoPackage {
				continue
			}

			commands = append(commands, []string{"sh", "-c", fmt.Sprintf("go mod edit -replace $(cd %s; grep module go.mod | cut -d ' ' -f 2)=./%s", tgt, tgt)})
		}
	}
	commands = append(commands, []string{"go", "get", "-v", "./..."})
	if cfg.Generate {
		commands = append(commands, []string{"go", "generate", "-v", "./..."})
	}
	if !cfg.DontTest && !buildctx.DontTest {
		commands = append(commands, [][]string{
			// we build the test binaries in addition to running the tests regularly, so that downstream packages can run the tests in different environments
			{"sh", "-c", "mkdir _tests; for i in $(go list ./...); do go test -c $i; [ -e $(basename $i).test ] && mv $(basename $i).test _tests; true; done"},
			{"go", "test", "-v", "./..."},
		}...)
	}
	if !cfg.DontCheckGoFmt {
		commands = append(commands, []string{"sh", "-c", `if [ ! $(go fmt ./... | wc -l) -eq 0 ]; then echo; echo; echo please gofmt your code; echo; echo; exit 1; fi`})
	}
	if cfg.Packaging == GoApp {
		cmd := []string{"go", "build"}
		cmd = append(cmd, cfg.BuildFlags...)
		cmd = append(cmd, ".")
		commands = append(commands, cmd)
	}
	commands = append(commands, [][]string{
		{"rm", "-rf", "_deps"},
		{"tar", "cfz", result, "."},
	}...)

	return executeCommandsForPackage(buildctx, p, wd, commands)
}

// buildDocker implements the build process for Docker packages.
// If you change anything in this process that's not backwards compatible, make sure you increment buildProcessVersions accordingly.
func (p *Package) buildDocker(buildctx *buildContext, wd, result string) (err error) {
	cfg, ok := p.Config.(DockerPkgConfig)
	if !ok {
		return xerrors.Errorf("package should have Docker config")
	}

	if cfg.Dockerfile == "" {
		return xerrors.Errorf("dockerfile is required")
	}
	dockerfile := filepath.Join(p.C.Origin, cfg.Dockerfile)
	if _, err := os.Stat(dockerfile); os.IsNotExist(err) {
		return err
	}

	var commands [][]string
	commands = append(commands, []string{"cp", dockerfile, "Dockerfile"})
	for _, dep := range p.GetDependencies() {
		fn, exists := buildctx.LocalCache.Location(dep)
		if !exists {
			return PkgNotBuiltErr{dep}
		}

		tgt := dep.FilesystemSafeName()
		commands = append(commands, [][]string{
			{"mkdir", tgt},
			{"tar", "xfz", fn, "-C", tgt},
		}...)
	}

	version, err := p.Version()
	if err != nil {
		return err
	}

	buildcmd := []string{"docker", "build", "--pull", "-t", version}
	for arg, val := range cfg.BuildArgs {
		buildcmd = append(buildcmd, "--build-arg", fmt.Sprintf("%s=%s", arg, val))
	}
	if cfg.Squash {
		buildcmd = append(buildcmd, "--squash")
	}
	buildcmd = append(buildcmd, ".")
	commands = append(commands, buildcmd)

	if len(cfg.Image) == 0 {
		// we don't push the image, let's export it
		ef := strings.TrimSuffix(result, ".gz")
		commands = append(commands, [][]string{
			{"docker", "save", "-o", ef, version},
			{"gzip", ef},
		}...)
	} else {
		for _, img := range cfg.Image {
			commands = append(commands, [][]string{
				{"docker", "tag", version, img},
				{"docker", "push", img},
			}...)
		}

		// We pushed the image which means we won't export it. We still need to place a marker the build cache.
		// The proper thing would be to export the image, but that's rather expensive. We'll place a tar file which
		// contains the names of the image we just pushed instead.
		for _, img := range cfg.Image {
			commands = append(commands, []string{"sh", "-c", fmt.Sprintf("echo %s >> %s", img, dockerImageNamesFiles)})
		}
		commands = append(commands, []string{"tar", "cfz", result, dockerImageNamesFiles})
	}

	return executeCommandsForPackage(buildctx, p, wd, commands)
}

// buildGeneric implements the build process for generic packages.
// If you change anything in this process that's not backwards compatible, make sure you increment BuildGenericProccessVersion.
func (p *Package) buildGeneric(buildctx *buildContext, wd, result string) (err error) {
	cfg, ok := p.Config.(GenericPkgConfig)
	if !ok {
		return xerrors.Errorf("package should have generic config")
	}

	// shortcut: no command == empty package
	if len(cfg.Commands) == 0 {
		log.WithField("package", p.FullName()).Debug("package has no commands - creating empty tar")
		return run(buildctx.Reporter, p, nil, wd, "tar", "cfz", result, "--files-from", "/dev/null")
	}

	var commands [][]string
	for _, dep := range p.GetDependencies() {
		fn, exists := buildctx.LocalCache.Location(dep)
		if !exists {
			return PkgNotBuiltErr{dep}
		}

		tgt := dep.FilesystemSafeName()
		commands = append(commands, [][]string{
			{"mkdir", tgt},
			{"tar", "xfz", fn, "-C", tgt},
		}...)
	}

	commands = append(commands, cfg.Commands...)
	commands = append(commands, []string{"tar", "cfz", result, "."})

	return executeCommandsForPackage(buildctx, p, wd, commands)
}

// rebuildDocker is called when we already have the build artifact for this package (and version)
// in the build cache. This function makes sure that if the build arguments changed the name of the
// Docker image this build time, we just re-tag the image.
func (p *Package) rebuildDocker(buildctx *buildContext, wd, prev string) (err error) {
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
	cmd := exec.Command("tar", "Ozfx", prev, dockerImageNamesFiles)
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
	env := append(os.Environ(), p.Environment...)
	for _, cmd := range commands {
		err := run(buildctx.Reporter, p, env, wd, cmd[0], cmd[1:]...)
		if err != nil {
			return err
		}
	}
	return nil
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
