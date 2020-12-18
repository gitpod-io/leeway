package leeway

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/minio/highwayhash"
	"github.com/typefox/leeway/pkg/doublestar"
	"golang.org/x/xerrors"
	"gopkg.in/yaml.v3"
)

// Arguments can be passed to components/packages introducing variation points
type Arguments map[string]string

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
	// re-marshal packageInternal without the variants. Their unresolved arguments do not matter.
	// Only when a variant becomes selected do its argumnents play a role, at which point they'll
	// show up during the config/env re-marshalling.
	pi := pkg.packageInternal
	meta, err := yaml.Marshal(pi)
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
	Scripts   []*Script  `yaml:"scripts"`
}

// PackageNotFoundErr is used when something references a package we don't know about
type PackageNotFoundErr struct {
	Package string
}

func (n PackageNotFoundErr) Error() string {
	return fmt.Sprintf("package \"%s\" is unknown", n.Package)
}

type packageInternal struct {
	Name                 string            `yaml:"name"`
	Type                 PackageType       `yaml:"type"`
	Sources              []string          `yaml:"srcs"`
	Dependencies         []string          `yaml:"deps"`
	Layout               map[string]string `yaml:"layout"`
	ArgumentDependencies []string          `yaml:"argdeps"`
	Environment          []string          `yaml:"env"`
	Ephemeral            bool              `yaml:"ephemeral"`
	PreparationCommands  [][]string        `yaml:"prep"`
}

// Package is a single buildable artifact within a component
type Package struct {
	C *Component

	// computing the version is expensive - let's cache that
	versionCache string

	packageInternal
	Config PackageConfig `yaml:"config"`
	// Definition is the raw package definition YAML
	Definition []byte `yaml:"-"`

	dependencies     []*Package
	layout           map[*Package]string
	originalSources  []string
	fullNameOverride string
}

// link connects resolves the references to the dependencies
func (p *Package) link(idx map[string]*Package) error {
	if p.dependencies != nil {
		// we're already linked
		return nil
	}

	p.dependencies = make([]*Package, len(p.Dependencies))
	p.layout = make(map[*Package]string)
	for i, dep := range p.Dependencies {
		deppkg, ok := idx[dep]
		if !ok {
			return PackageNotFoundErr{dep}
		}
		p.dependencies[i] = deppkg

		// if the user hasn't specified a layout, tie it down at this point
		p.layout[deppkg], ok = p.Layout[dep]
		if !ok {
			p.layout[deppkg] = deppkg.FilesystemSafeName()
		}
	}
	return nil
}

func (p *Package) findCycle() ([]string, error) {
	var (
		walk  func(pkg *Package) ([]string, error)
		path  = make([]string, len(p.C.W.Packages))
		depth int
	)
	walk = func(pkg *Package) ([]string, error) {
		var (
			seen bool
			pkgn = pkg.FullName()
		)
		for _, p := range path[:depth] {
			if p == pkgn {
				seen = true
				break
			}
		}

		if len(path) <= depth {
			return nil, xerrors.Errorf("[internal error] depth exceeds max path length: looks like the workspace package index isn't build properly")
		}

		path[depth] = pkg.FullName()
		depth++
		defer func() {
			depth--
		}()

		if seen {
			return path[:depth], nil
		}

		path = append(path, pkgn)
		for _, dep := range pkg.GetDependencies() {
			r, err := walk(dep)
			if err != nil {
				return nil, err
			}
			if r != nil {
				return r, nil
			}
		}

		return nil, nil
	}

	return walk(p)
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

// BuildLayoutLocation returns the filesystem path a dependency is expected at during the build.
// This path will always be relative. If the provided package is not a depedency of this package,
// we'll still return a valid path.
func (p *Package) BuildLayoutLocation(dependency *Package) (loc string) {
	var ok bool
	loc, ok = p.layout[dependency]
	if ok {
		return loc
	}

	return dependency.FilesystemSafeName()
}

// UnmarshalYAML unmarshals the package definition
func (p *Package) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var tpe packageInternal
	err := unmarshal(&tpe)
	if err != nil {
		return err
	}
	*p = Package{packageInternal: tpe}

	var buf yaml.Node
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
	case DeprecatedTypescriptPackage:
		fallthrough
	case YarnPackage:
		var cfg struct {
			Config YarnPkgConfig `yaml:"config"`
		}
		if err := unmarshal(&cfg); err != nil {
			return nil, err
		}
		if cfg.Config.Packaging == "" {
			cfg.Config.Packaging = YarnApp
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
// This is one of YarnPkgConfig, GoPkgConfig, DockerPkgConfig or GenericPkgConfig.
type PackageConfig interface {
	AdditionalSources() []string
}

// YarnPkgConfig configures a yarn package
type YarnPkgConfig struct {
	YarnLock  string        `yaml:"yarnLock,omitempty"`
	TSConfig  string        `yaml:"tsconfig"`
	Packaging YarnPackaging `yaml:"packaging,omitempty"`
	DontTest  bool          `yaml:"dontTest,omitempty"`
	Commands  struct {
		Install []string `yaml:"install,omitempty"`
		Build   []string `yaml:"build,omitempty"`
		Test    []string `yaml:"test,omitempty"`
	} `yaml:"commands,omitempty"`
}

// Validate ensures this config can be acted upon/is valid
func (cfg YarnPkgConfig) Validate() error {
	switch cfg.Packaging {
	case YarnLibrary:
	case YarnOfflineMirror:
	case YarnApp:
	case YarnArchive:
	default:
		return xerrors.Errorf("unknown packaging: %s", cfg.Packaging)
	}

	return nil
}

// YarnPackaging configures the packaging method of a yarn package
type YarnPackaging string

const (
	// YarnLibrary means the package will be created using `yarn pack`
	YarnLibrary YarnPackaging = "library"
	// YarnOfflineMirror means that the package will become a yarn offline mirror
	YarnOfflineMirror YarnPackaging = "offline-mirror"
	// YarnApp installs the package using an empty package.json and tars the resulting node_modules/
	YarnApp YarnPackaging = "app"
	// YarnArchive simply tars the build directory
	YarnArchive YarnPackaging = "archive"
)

// AdditionalSources returns a list of unresolved sources coming in through this configuration
func (cfg YarnPkgConfig) AdditionalSources() []string {
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
	DontLint       bool        `yaml:"dontLint,omitempty"`
	BuildFlags     []string    `yaml:"buildFlags,omitempty"`
	LintCommand    []string    `yaml:"lintCommand,omitempty"`
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
	// DeprecatedTypescriptPackage runs tsc in a package and produces a yarn offline mirror
	DeprecatedTypescriptPackage PackageType = "typescript"

	// YarnPackage uses the yarn package manager to download dependencies and build the package
	YarnPackage PackageType = "yarn"

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
	case DeprecatedTypescriptPackage, YarnPackage, GoPackage, DockerPackage, GenericPackage:
	default:
		return fmt.Errorf("invalid package type: %s", err)
	}
	return
}

type packageVariantInternal struct {
	Name    string `yaml:"name"`
	Sources struct {
		Include []string `yaml:"include"`
		Exclude []string `yaml:"exclude"`
	} `yaml:"srcs"`
	Components struct {
		Exclude []string `yaml:"exclude"`
	} `yaml:"components"`
	Environment []string                  `yaml:"env"`
	RawConfig   map[PackageType]yaml.Node `yaml:"config"`
}

// PackageVariant provides a variation point for a package's sources,
// environment variables and config.
type PackageVariant struct {
	packageVariantInternal

	config map[PackageType]PackageConfig
}

// UnmarshalYAML unmarshals a package variant
func (v *PackageVariant) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var vi packageVariantInternal
	err := unmarshal(&vi)
	if err != nil {
		return err
	}

	config := make(map[PackageType]PackageConfig)
	for k, rc := range vi.RawConfig {
		b, err := yaml.Marshal(&rc)
		if err != nil {
			return err
		}
		cfg, err := unmarshalTypeDependentConfig(k, func(dst interface{}) error {
			lines := strings.Split(string(b), "\n")
			for i, l := range lines {
				lines[i] = "    " + l
			}
			b := []byte("config:\n" + strings.Join(lines, "\n"))
			return yaml.Unmarshal(b, dst)
		})
		if err != nil {
			return err
		}
		config[k] = cfg
	}

	*v = PackageVariant{
		packageVariantInternal: vi,
		config:                 config,
	}

	return nil
}

// Config returns this package variants configuration
func (v *PackageVariant) Config(t PackageType) (cfg PackageConfig, ok bool) {
	cfg, ok = v.config[t]
	return
}

// ExcludeComponent returns true if this variants excludes the component
func (v *PackageVariant) ExcludeComponent(name string) bool {
	for _, c := range v.Components.Exclude {
		if c == name {
			return true
		}
	}
	return false
}

// ResolveSources lists all files which are explicitely included or excluded by this variant.
// Inclusion takes precedence over exclusion.
func (v *PackageVariant) ResolveSources(workspace *Workspace, loc string) (incl []string, excl []string, err error) {
	incl, err = resolveSources(workspace, loc, v.Sources.Include, true)
	if err != nil {
		return
	}

	excl, err = resolveSources(workspace, loc, v.Sources.Exclude, true)
	if err != nil {
		return
	}

	return
}

func resolveSources(workspace *Workspace, loc string, globs []string, includeDirs bool) (res []string, err error) {
	for _, glb := range globs {
		srcs, err := doublestar.Glob(loc, glb, workspace.ShouldIgnoreSource)
		if err != nil {
			return nil, err
		}

		for _, src := range srcs {
			stat, err := os.Stat(src)
			if err != nil {
				return nil, err
			}
			if !includeDirs && stat.IsDir() {
				continue
			}
			if workspace.ShouldIgnoreSource(src) {
				continue
			}
			res = append(res, src)
		}
	}
	return res, nil
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
	if p.fullNameOverride != "" {
		return p.fullNameOverride
	}
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

// DefinitionHash hashes the package definition
func (p *Package) DefinitionHash() (string, error) {
	key, err := hex.DecodeString(contentHashKey)
	if err != nil {
		return "", err
	}

	hash, err := highwayhash.New(key)
	if err != nil {
		return "", err
	}

	_, err = hash.Write(p.Definition)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
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

	envhash, err := p.C.W.EnvironmentManifest.Hash()
	if err != nil {
		return err
	}
	defhash, err := p.DefinitionHash()
	if err != nil {
		return err
	}
	manifest, err := p.ContentManifest()
	if err != nil {
		return err
	}

	_, err = fmt.Fprintf(out, "buildProcessVersion: %d\n", buildProcessVersions[p.Type])
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(out, "environment: %s\n", envhash)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(out, "definition: %s\n", defhash)
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

// TopologicalSort sorts the list of packages by its build order according to the dependency tree
func TopologicalSort(pkgs []*Package) {
	var (
		idx  = make(map[string]int)
		walk func(p *Package, depth int)
	)
	walk = func(p *Package, depth int) {
		pn := p.FullName()
		deps := p.GetDependencies()

		d := idx[pn]
		if d < depth {
			d = depth
		}
		idx[pn] = d

		for _, d := range deps {
			walk(d, depth+1)
		}
	}
	for _, p := range pkgs {
		walk(p, 0)
	}

	sort.Slice(pkgs, func(i, j int) bool {
		di := idx[pkgs[i].FullName()]
		dj := idx[pkgs[j].FullName()]
		return di > dj
	})
}
