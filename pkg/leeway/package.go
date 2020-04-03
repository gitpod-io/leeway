package leeway

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/bmatcuk/doublestar"
	"github.com/minio/highwayhash"
	log "github.com/sirupsen/logrus"
	"golang.org/x/xerrors"
	"gopkg.in/yaml.v2"
)

// Arguments can be passed to components/packages introducing variation points
type Arguments map[string]string

// Workspace is the root container of all compoments. All components are named relative
// to the origin of this workspace.
type Workspace struct {
	DefaultTarget    string            `yaml:"defaultTarget,omitempty"`
	ArgumentDefaults map[string]string `yaml:"defaultArgs,omitempty"`

	Origin     string
	Components map[string]Component
	Packages   map[string]*Package

	ignores []string
}

// ShouldIngoreComponent returns true if a file should be ignored for a component listing
func (ws *Workspace) ShouldIngoreComponent(path string) bool {
	return ws.ShouldIngoreSource(path)
}

// ShouldIngoreSource returns true if a file should be ignored for a source listing
func (ws *Workspace) ShouldIngoreSource(path string) bool {
	for _, ptn := range ws.ignores {
		if strings.Contains(path, ptn) {
			return true
		}
	}
	return false
}

var (
	// buildArgRegexp is the regexp to find build arguments
	buildArgRegexp = regexp.MustCompile(`\$\{(\w+)\}`)
)

const (
	// BuiltinArgPackageVersion is a builtin argument/variable which contains the version of the package currently building
	BuiltinArgPackageVersion = "__pkg_version"

	// contentHashKey is the key we use to hash source files. Change this key and you'll break all past versions of all leeway builds ever.
	contentHashKey = "0340f3c8947cad7875140f4c4af7c62b43131dc2a8c7fc4628f0685e369a3b0b"
)

// FindUnresolvedArguments finds any still unresolved build arguments in a set of packages
func FindUnresolvedArguments(pkg *Package) ([]string, error) {
	meta, err := yaml.Marshal(pkg.packageInternal)
	if err != nil {
		return nil, err
	}
	cfg, err := yaml.Marshal(pkg.Config)
	if err != nil {
		return nil, err
	}
	fc := append(meta, cfg...)

	vars := make(map[string]struct{})

	args := buildArgRegexp.FindAll(fc, -1)
	for _, arg := range args {
		vars[string(arg)] = struct{}{}
	}

	for _, argdep := range pkg.ArgumentDependencies {
		if !strings.Contains(argdep, "<not-set>") {
			continue
		}

		segs := strings.Split(argdep, ":")
		vars[fmt.Sprintf("${%s}", segs[0])] = struct{}{}
	}

	var res []string
	for v := range vars {
		res = append(res, v)
	}
	return res, nil
}

// FindWorkspace looks for a WORKSPACE.yaml file within the path. If multiple such files are found,
// an error is returned.
func FindWorkspace(path string, args Arguments) (Workspace, error) {
	root := filepath.Join(path, "WORKSPACE.yaml")
	fc, err := ioutil.ReadFile(root)
	if err != nil {
		return Workspace{}, err
	}
	var workspace Workspace
	err = yaml.Unmarshal(fc, &workspace)
	if err != nil {
		return Workspace{}, err
	}
	workspace.Origin, err = filepath.Abs(filepath.Dir(root))
	if err != nil {
		return Workspace{}, err
	}

	var ignores []string
	ignoresFile := filepath.Join(workspace.Origin, ".leewayignore")
	if _, err := os.Stat(ignoresFile); !os.IsNotExist(err) {
		fc, err := ioutil.ReadFile(ignoresFile)
		if err != nil {
			return Workspace{}, err
		}
		ignores = strings.Split(string(fc), "\n")
	}
	workspace.ignores = ignores

	log.WithField("defaultArgs", workspace.ArgumentDefaults).Debug("applying workspace defaults")
	for key, val := range workspace.ArgumentDefaults {
		if args == nil {
			args = make(map[string]string)
		}

		_, alreadySet := args[key]
		if alreadySet {
			continue
		}

		args[key] = val
	}

	comps, err := discoverComponents(&workspace, args)
	if err != nil {
		return workspace, err
	}
	workspace.Components = make(map[string]Component)
	workspace.Packages = make(map[string]*Package)
	for _, comp := range comps {
		workspace.Components[comp.Name] = comp

		for _, pkg := range comp.Packages {
			workspace.Packages[pkg.FullName()] = pkg
		}
	}

	// now that we have all components/packages, we can link things
	for _, pkg := range workspace.Packages {
		err := pkg.link(workspace.Packages)
		if err != nil {
			return workspace, xerrors.Errorf("linking error in %s: %w", pkg.FullName(), err)
		}
	}

	// at this point all packages are fully loaded and we can compute the version, as well as resolve builtin variables
	for _, pkg := range workspace.Packages {
		err := pkg.resolveBuiltinVariables()
		if err != nil {
			return workspace, xerrors.Errorf("cannot resolve builtin variables %s: %w", pkg.FullName(), err)
		}
	}

	return workspace, nil
}

// discoverComponents discovers components in a workspace
func discoverComponents(workspace *Workspace, args Arguments) ([]Component, error) {
	path := workspace.Origin
	pths, err := doublestar.Glob(filepath.Join(path, "**/BUILD.yaml"))
	if err != nil {
		return nil, err
	}

	var comps []Component
	for _, pth := range pths {
		if workspace.ShouldIngoreComponent(pth) {
			continue
		}

		comp, err := loadComponent(workspace, pth, args)
		if err != nil {
			return nil, err
		}

		comps = append(comps, comp)
	}

	return comps, nil
}

// loadComponent loads a component from a BUILD.yaml file
func loadComponent(workspace *Workspace, path string, args Arguments) (Component, error) {
	fc, err := ioutil.ReadFile(path)
	if err != nil {
		return Component{}, err
	}

	// we attempt to load the constants of a component first so that we can add it to the args
	var compconst struct {
		Constants Arguments `yaml:"const"`
	}
	err = yaml.Unmarshal(fc, &compconst)
	if err != nil {
		return Component{}, err
	}
	compargs := make(Arguments)
	for k, v := range args {
		compargs[k] = v
	}
	for k, v := range compconst.Constants {
		// constants overwrite args
		compargs[k] = v
	}

	// replace build args
	if len(args) > 0 {
		fc = replaceBuildArguments(fc, compargs)
	}

	var comp Component
	err = yaml.Unmarshal(fc, &comp)
	if err != nil {
		return comp, err
	}

	name := strings.TrimPrefix(strings.TrimPrefix(filepath.Dir(path), workspace.Origin), "/")
	if name == "" {
		name = "//"
	}

	comp.W = workspace
	comp.Name = name
	comp.Origin = filepath.Dir(path)
	for _, pkg := range comp.Packages {
		pkg.C = &comp

		err := pkg.resolveSources()
		if err != nil {
			return comp, xerrors.Errorf("%s: %w", comp.Name, err)
		}

		// add component BUILD file and additional sources to package sources
		completeSources := make(map[string]struct{})
		completeSources[path] = struct{}{}
		for _, src := range pkg.Sources {
			completeSources[src] = struct{}{}
		}
		for _, src := range pkg.Config.AdditionalSources() {
			fn, err := filepath.Abs(filepath.Join(comp.Origin, src))
			if err != nil {
				return comp, xerrors.Errorf("%s: %w", comp.Name, err)
			}
			if _, err := os.Stat(fn); os.IsNotExist(err) {
				return comp, xerrors.Errorf("%s: %w", comp.Name, err)
			}
			if _, found := completeSources[fn]; found {
				continue
			}

			completeSources[fn] = struct{}{}
		}
		pkg.Sources = make([]string, len(completeSources))
		i := 0
		for src := range completeSources {
			pkg.Sources[i] = src
			i++
		}

		// re-set the version relevant arguments to <name>: <value>
		for i, argdep := range pkg.ArgumentDependencies {
			val, ok := args[argdep]
			if !ok {
				val = "<not-set>"
			}
			pkg.ArgumentDependencies[i] = fmt.Sprintf("%s: %s", argdep, val)
		}

		// make all dependencies fully qualified
		for idx, dep := range pkg.Dependencies {
			if !strings.HasPrefix(dep, ":") {
				continue
			}

			pkg.Dependencies[idx] = comp.Name + dep
		}
	}

	return comp, nil
}

// replaceBuildArguments replaces all build arguments in the byte stream (e.g. ${thisIsAnArg}) with its corresponding
// value from args. If args has no corresponding value, the argument is not changed.
func replaceBuildArguments(fc []byte, args Arguments) []byte {
	return buildArgRegexp.ReplaceAllFunc(fc, func(match []byte) []byte {
		arg := string(match)
		arg = strings.TrimPrefix(arg, "${")
		arg = strings.TrimSuffix(arg, "}")

		val, ok := args[arg]
		if !ok {
			return match
		}
		return []byte(val)
	})
}

// Component contains a single component that we wish to build
type Component struct {
	// W is the workspace this component belongs to
	W *Workspace
	// Origin is the absolute location of this Component in the filepath
	Origin string
	// Name is the name of the Component as computed from its location in the workspace
	Name string

	Constants Arguments  `yaml:"const"`
	Packages  []*Package `yaml:"packages"`
}

// PackageNotFoundErr is used when something references a package we don't know about
type PackageNotFoundErr struct {
	Package string
}

func (n PackageNotFoundErr) Error() string {
	return fmt.Sprintf("package \"%s\" is unkown", n.Package)
}

type packageInternal struct {
	Name                 string      `yaml:"name"`
	Type                 PackageType `yaml:"type"`
	Sources              []string    `yaml:"srcs"`
	Dependencies         []string    `yaml:"deps"`
	ArgumentDependencies []string    `yaml:"argdeps"`
	Environment          []string    `yaml:"env"`
	Ephemeral            bool        `yaml:"ephemeral"`
}

// Package is a single buildable artifact within a component
type Package struct {
	C *Component

	// computing the version is expensive - let's cache that
	versionCache string

	packageInternal
	Config PackageConfig `yaml:"config"`

	dependencies []*Package
}

// link connects resolves the references to the dependencies
func (p *Package) link(idx map[string]*Package) error {
	p.dependencies = make([]*Package, len(p.Dependencies))
	for i, dep := range p.Dependencies {
		var ok bool
		p.dependencies[i], ok = idx[dep]
		if !ok {
			return PackageNotFoundErr{dep}
		}
	}
	return nil
}

// GetDependencies returns the linked package dependencies or nil if not linked yet
func (p *Package) GetDependencies() []*Package {
	return p.dependencies
}

// GetTransitiveDependencies returns all transitive dependencies of a package.
func (p *Package) GetTransitiveDependencies() []*Package {
	idx := make(map[string]*Package)
	queue := []*Package{p}
	for len(queue) != 0 {
		dep := queue[0]
		queue = queue[1:]

		if _, ok := idx[dep.FullName()]; ok {
			continue
		}

		idx[dep.FullName()] = dep
		queue = append(queue, dep.dependencies...)
	}

	res := make([]*Package, len(idx)-1)
	i := 0
	for _, k := range idx {
		// don't include the package itself in the list of transitive dependencies
		if k == p {
			continue
		}
		res[i] = k
		i++
	}
	return res
}

// UnmarshalYAML unmarshals the package definition
func (p *Package) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var tpe packageInternal
	err := unmarshal(&tpe)
	if err != nil {
		return err
	}
	*p = Package{packageInternal: tpe}

	var buf yaml.MapSlice
	err = unmarshal(&buf)
	if err != nil {
		return err
	}

	cfg, err := unmarshalTypeDependentConfig(tpe.Type, unmarshal)
	if err != nil {
		return err
	}
	p.Config = cfg

	return nil
}

func unmarshalTypeDependentConfig(tpe PackageType, unmarshal func(interface{}) error) (PackageConfig, error) {
	switch tpe {
	case TypescriptPackage:
		var cfg struct {
			Config TypescriptPkgConfig `yaml:"config"`
		}
		if err := unmarshal(&cfg); err != nil {
			return nil, err
		}
		if cfg.Config.Packaging == "" {
			cfg.Config.Packaging = TypescriptApp
		}
		if err := cfg.Config.Validate(); err != nil {
			return nil, err
		}
		return cfg.Config, nil
	case GoPackage:
		var cfg struct {
			Config GoPkgConfig `yaml:"config"`
		}
		if err := unmarshal(&cfg); err != nil {
			return nil, err
		}
		if cfg.Config.Packaging == "" {
			cfg.Config.Packaging = GoApp
		}
		if err := cfg.Config.Validate(); err != nil {
			return nil, err
		}
		return cfg.Config, nil
	case DockerPackage:
		var cfg struct {
			Config DockerPkgConfig `yaml:"config"`
		}
		if err := unmarshal(&cfg); err != nil {
			return nil, err
		}
		if cfg.Config.Dockerfile == "" {
			cfg.Config.Dockerfile = "Dockerfile"
		}
		return cfg.Config, nil
	case GenericPackage:
		var cfg struct {
			Config GenericPkgConfig `yaml:"config"`
		}
		if err := unmarshal(&cfg); err != nil {
			return nil, err
		}
		return cfg.Config, nil
	default:
		return nil, xerrors.Errorf("unknown package type \"%s\"", tpe)
	}
}

// PackageConfig is the YAML unmarshalling config type of packages.
// This is one of TypescriptPkgConfig, GoPkgConfig, DockerPkgConfig or GenericPkgConfig.
type PackageConfig interface {
	AdditionalSources() []string
}

// TypescriptPkgConfig configures a typescript package
type TypescriptPkgConfig struct {
	YarnLock  string              `yaml:"yarnLock,omitempty"`
	TSConfig  string              `yaml:"tsconfig"`
	Packaging TypescriptPackaging `yaml:"packaging,omitempty"`
	DontTest  bool                `yaml:"dontTest,omitempty"`
	Commands  struct {
		Install []string `yaml:"install,omitempty"`
		Build   []string `yaml:"build,omitempty"`
		Test    []string `yaml:"test,omitempty"`
	} `yaml:"commands,omitempty"`
}

// Validate ensures this config can be acted upon/is valid
func (cfg TypescriptPkgConfig) Validate() error {
	switch cfg.Packaging {
	case TypescriptLibrary:
	case TypescriptOfflineMirror:
	case TypescriptApp:
	case TypescriptArchive:
	default:
		return xerrors.Errorf("unknown packaging: %s", cfg.Packaging)
	}

	return nil
}

// TypescriptPackaging configures the packaging method of a typescript package
type TypescriptPackaging string

const (
	// TypescriptLibrary means the package will be created using `yarn pack`
	TypescriptLibrary TypescriptPackaging = "library"
	// TypescriptOfflineMirror means that the package will become a yarn offline mirror
	TypescriptOfflineMirror TypescriptPackaging = "offline-mirror"
	// TypescriptApp installs the package using an empty package.json and tars the resulting node_modules/
	TypescriptApp TypescriptPackaging = "app"
	// TypescriptArchive simply tars the build directory
	TypescriptArchive TypescriptPackaging = "archive"
)

// AdditionalSources returns a list of unresolved sources coming in through this configuration
func (cfg TypescriptPkgConfig) AdditionalSources() []string {
	var res []string
	if cfg.YarnLock != "" {
		res = append(res, cfg.YarnLock)
	}
	if cfg.TSConfig != "" {
		res = append(res, cfg.TSConfig)
	}
	return res
}

// GoPkgConfig configures a Go package
type GoPkgConfig struct {
	Packaging      GoPackaging `yaml:"packaging,omitempty"`
	Generate       bool        `yaml:"generate,omitempty"`
	DontTest       bool        `yaml:"dontTest,omitempty"`
	DontCheckGoFmt bool        `yaml:"dontCheckGoFmt,omitempty"`
	BuildFlags     []string    `yaml:"buildFlags,omitempty"`
}

// Validate ensures this config can be acted upon/is valid
func (cfg GoPkgConfig) Validate() error {
	switch cfg.Packaging {
	case GoLibrary:
	case GoApp:
	default:
		return xerrors.Errorf("unknown packaging: %s", cfg.Packaging)
	}

	return nil
}

// GoPackaging configures the packaging method of a Go package
type GoPackaging string

const (
	// GoLibrary means the package can be imported in another package
	GoLibrary GoPackaging = "library"
	// GoApp runs go build and tars the build directory
	GoApp GoPackaging = "app"
)

// AdditionalSources returns a list of unresolved sources coming in through this configuration
func (cfg GoPkgConfig) AdditionalSources() []string {
	return []string{}
}

// DockerPkgConfig configures a Docker package
type DockerPkgConfig struct {
	Dockerfile string            `yaml:"dockerfile,omitempty"`
	Image      []string          `yaml:"image,omitempty"`
	BuildArgs  map[string]string `yaml:"buildArgs,omitempty"`
	Squash     bool              `yaml:"squash,omitempty"`
}

// AdditionalSources returns a list of unresolved sources coming in through this configuration
func (cfg DockerPkgConfig) AdditionalSources() []string {
	return []string{cfg.Dockerfile}
}

// GenericPkgConfig configures a generic package
type GenericPkgConfig struct {
	Commands [][]string `yaml:"commands"`
}

// AdditionalSources returns a list of unresolved sources coming in through this configuration
func (cfg GenericPkgConfig) AdditionalSources() []string {
	return []string{}
}

// PackageType describes the way a package is built and what it produces
type PackageType string

const (
	// TypescriptPackage runs tsc in a package and produces a yarn offline mirror
	TypescriptPackage PackageType = "typescript"

	// GoPackage runs go build and produces a binary file
	GoPackage PackageType = "go"

	// DockerPackage runs docker build
	DockerPackage PackageType = "docker"

	// GenericPackage runs an arbitary shell command
	GenericPackage PackageType = "generic"
)

// UnmarshalYAML unmarshals and validates a package type
func (p *PackageType) UnmarshalYAML(unmarshal func(interface{}) error) (err error) {
	var val string
	err = unmarshal(&val)
	if err != nil {
		return
	}

	*p = PackageType(val)
	switch *p {
	case TypescriptPackage, GoPackage, DockerPackage, GenericPackage:
	default:
		return fmt.Errorf("invalid package type: %s", err)
	}
	return
}

// CacheLevel describes a level of package cache
type CacheLevel string

const (
	// CacheUnspecified allows all downloads/uploads/caching operations
	CacheUnspecified CacheLevel = ""

	// CacheNone means no caching happens at all
	CacheNone CacheLevel = "none"

	// CacheLocal means a package is only cached locally
	CacheLocal CacheLevel = "local"

	// CacheRemote means a package is downloaded from and uploaded to a remote cache
	CacheRemote CacheLevel = "remote"

	// CacheRemotePush means a package is cached locally and possibly uploaded to a remote cache,
	// but it will never be downloaded from a remote cache.
	CacheRemotePush CacheLevel = "remote-push"

	// CacheRemotePull means a package is cached locally and possibly downloaded from a remote cache,
	// but it will never be uploaded to a remote cache.
	CacheRemotePull CacheLevel = "remote-pull"
)

// UnmarshalYAML unmarshals and validates a package type
func (c *CacheLevel) UnmarshalYAML(unmarshal func(interface{}) error) (err error) {
	var val string
	err = unmarshal(&val)
	if err != nil {
		return
	}

	*c = CacheLevel(val)
	switch *c {
	case CacheUnspecified, CacheNone, CacheLocal, CacheRemote, CacheRemotePush:
	default:
		return fmt.Errorf("invalid package type: %s", err)
	}
	return
}

// RemoteDownload returns true if this cache level permitts local download
func (c CacheLevel) RemoteDownload() bool {
	return c == CacheUnspecified || c == CacheRemote || c == CacheRemotePull
}

// RemoteUpload retruns true if the cache level permitts remote upload
func (c CacheLevel) RemoteUpload() bool {
	return c == CacheUnspecified || c == CacheRemote || c == CacheRemotePush
}

// FullName returns the packages fully qualified name (component:package)
func (p *Package) FullName() string {
	return fmt.Sprintf("%s:%s", p.C.Name, p.Name)
}

// FilesystemSafeName returns a string that is safe to use in a Unix filesystem as directory or filename
func (p *Package) FilesystemSafeName() string {
	pkgdir := p.FullName()
	pkgdir = strings.Replace(pkgdir, "/", "-", -1)
	pkgdir = strings.Replace(pkgdir, ":", "--", -1)
	// components in the workspace root would otherwise start with - which breaks a lot of shell commands
	pkgdir = strings.TrimLeft(pkgdir, "-")
	return pkgdir
}

// resolveSources resolves any glob expression in the source list
func (p *Package) resolveSources() error {
	var res []string
	for _, glb := range p.Sources {
		srcs, err := doublestar.Glob(filepath.Join(p.C.Origin, glb))
		if err != nil {
			return err
		}

		for _, src := range srcs {
			stat, err := os.Stat(src)
			if err != nil {
				return err
			}
			if stat.IsDir() {
				continue
			}
			if p.C.W.ShouldIngoreSource(src) {
				continue
			}
			res = append(res, src)
		}
	}
	p.Sources = res
	return nil
}

func (p *Package) resolveBuiltinVariables() error {
	ur, err := FindUnresolvedArguments(p)
	if err != nil {
		return err
	}
	var found bool
	for _, n := range ur {
		n = strings.TrimSuffix(strings.TrimPrefix(n, "${"), "}")
		if n == BuiltinArgPackageVersion {
			found = true
			break
		}
	}
	if !found {
		// no unresolved builtin args in there - nothing to do
		return nil
	}

	version, err := p.Version()
	if err != nil {
		return err
	}
	builtinArgs := map[string]string{
		BuiltinArgPackageVersion: version,
	}

	type configOnlyHelper struct {
		Config PackageConfig `yaml:"config"`
	}
	cfgonly := configOnlyHelper{Config: p.Config}
	fc, err := yaml.Marshal(cfgonly)
	if err != nil {
		return err
	}

	fc = replaceBuildArguments(fc, builtinArgs)

	cfg, err := unmarshalTypeDependentConfig(p.Type, func(out interface{}) error {
		return yaml.Unmarshal(fc, out)
	})
	if err != nil {
		return err
	}
	p.Config = cfg

	return nil
}

// ContentManifest produces an ordered list of content hashes (<filename>:<hash>) for each source file.
// Expects the sources to be resolved.
func (p *Package) ContentManifest() ([]string, error) {
	key, err := hex.DecodeString(contentHashKey)
	if err != nil {
		return nil, err
	}

	// TODO: parallelize
	res := make([]string, len(p.Sources))
	for i, src := range p.Sources {
		if stat, err := os.Stat(src); err != nil {
			return nil, err
		} else if stat.IsDir() {
			return nil, xerrors.Errorf("source list must not contain directories")
		}

		file, err := os.OpenFile(src, os.O_RDONLY, 0644)
		if err != nil {
			return nil, err
		}

		hash, err := highwayhash.New(key)
		if err != nil {
			file.Close()
			return nil, err
		}

		_, err = io.Copy(hash, file)
		if err != nil {
			file.Close()
			return nil, err
		}

		err = file.Close()
		if err != nil {
			return nil, err
		}

		name := strings.TrimPrefix(src, p.C.W.Origin+"/")
		res[i] = fmt.Sprintf("%s:%s", name, hex.EncodeToString(hash.Sum(nil)))
	}

	sort.Slice(res, func(i, j int) bool {
		return res[i] < res[j]
	})

	return res, nil
}

// WriteVersionManifest writes the manifest whoose hash is the version of this package (see Version())
func (p *Package) WriteVersionManifest(out io.Writer) error {
	if p.dependencies == nil {
		return xerrors.Errorf("package is not linked")
	}

	manifest, err := p.ContentManifest()
	if err != nil {
		return err
	}

	_, err = fmt.Fprintf(out, "buildProcessVersion: %d\n", buildProcessVersions[p.Type])
	if err != nil {
		return err
	}
	for _, argdep := range p.ArgumentDependencies {
		_, err = fmt.Fprintf(out, "arg %s\n", argdep)
		if err != nil {
			return err
		}
	}
	for _, dep := range p.dependencies {
		ver, err := dep.Version()
		if err != nil {
			return xerrors.Errorf("%s: %w", dep.FullName(), err)
		}
		_, err = fmt.Fprintf(out, "%s.%s\n", dep.FullName(), ver)
		if err != nil {
			return err
		}
	}

	_, err = io.WriteString(out, strings.Join(manifest, "\n"))
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(out)
	if err != nil {
		return err
	}

	return nil
}

// Version computes the Package version based on the content hash of the sources
func (p *Package) Version() (string, error) {
	if p.versionCache != "" {
		return p.versionCache, nil
	}

	h := sha1.New()
	err := p.WriteVersionManifest(h)
	if err != nil {
		return "", err
	}
	p.versionCache = hex.EncodeToString(h.Sum(nil))

	return p.versionCache, nil
}
