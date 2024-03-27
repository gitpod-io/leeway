package leeway

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"runtime/trace"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/dop251/goja"
	"github.com/imdario/mergo"
	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/minio/highwayhash"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
	"golang.org/x/xerrors"
	"gopkg.in/yaml.v3"

	"github.com/gitpod-io/leeway/pkg/doublestar"
)

// Workspace is the root container of all compoments. All components are named relative
// to the origin of this workspace.
type Workspace struct {
	DefaultTarget       string              `yaml:"defaultTarget,omitempty"`
	ArgumentDefaults    map[string]string   `yaml:"defaultArgs,omitempty"`
	DefaultVariant      *PackageVariant     `yaml:"defaultVariant,omitempty"`
	Variants            []*PackageVariant   `yaml:"variants,omitempty"`
	EnvironmentManifest EnvironmentManifest `yaml:"environmentManifest,omitempty"`
	Provenance          WorkspaceProvenance `yaml:"provenance,omitempty"`

	Origin          string                `yaml:"-"`
	Components      map[string]*Component `yaml:"-"`
	Packages        map[string]*Package   `yaml:"-"`
	Scripts         map[string]*Script    `yaml:"-"`
	SelectedVariant *PackageVariant       `yaml:"-"`
	Git             GitInfo               `yaml:"-"`

	ignores []string
}

type WorkspaceProvenance struct {
	Enabled bool `yaml:"enabled"`
	SLSA    bool `yaml:"slsa"`

	KeyPath string       `yaml:"key"`
	key     *in_toto.Key `yaml:"-"`
}

func DiscoverWorkspaceRoot() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}

	for i := 0; i < 100; i++ {
		if _, err := os.Stat(filepath.Join(wd, "WORKSPACE.yaml")); err == nil {
			return wd, nil
		}

		wd = filepath.Dir(wd)
		if wd == "/" || wd == "" {
			break
		}
	}

	return "", xerrors.Errorf("cannot find workspace root")
}

// EnvironmentManifest is a collection of environment manifest entries
type EnvironmentManifest []EnvironmentManifestEntry

// Write writes the manifest to the writer
func (mf EnvironmentManifest) Write(out io.Writer) error {
	for _, e := range mf {
		_, err := fmt.Fprintf(out, "%s: %s\n", e.Name, e.Value)
		if err != nil {
			return err
		}
	}
	return nil
}

// Hash produces the hash of this manifest
func (mf EnvironmentManifest) Hash() (string, error) {
	key, err := hex.DecodeString(contentHashKey)
	if err != nil {
		return "", err
	}

	hash, err := highwayhash.New(key)
	if err != nil {
		return "", err
	}

	err = mf.Write(hash)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

// MarshalJSON marshals a built-up environment manifest into JSON
func (mf EnvironmentManifest) MarshalJSON() ([]byte, error) {
	res := make(map[string]string, len(mf))
	for _, e := range mf {
		res[e.Name] = e.Value
	}
	return json.Marshal(res)
}

// EnvironmentManifestEntry represents an entry in the environment manifest
type EnvironmentManifestEntry struct {
	Name    string   `yaml:"name"`
	Command []string `yaml:"command"`

	Value   string `yaml:"-"`
	Builtin bool   `yaml:"-"`
}

const (
	builtinEnvManifestGOOS   = "goos"
	builtinEnvManifestGOARCH = "goarch"
)

var defaultEnvManifestEntries = map[PackageType]EnvironmentManifest{
	"": []EnvironmentManifestEntry{
		{Name: "os", Command: []string{builtinEnvManifestGOOS}, Builtin: true},
		{Name: "arch", Command: []string{builtinEnvManifestGOARCH}, Builtin: true},
	},
	GenericPackage: []EnvironmentManifestEntry{},
	DockerPackage:  []EnvironmentManifestEntry{
		// We do not pull the docker version here as that would make package versions dependent on a connection
		// to a Docker daemon. As the environment manifest is resolved on workspace load one would always need
		// a connection to a Docker daemon just to run e.g. leeway collect.
		//
		// If you want the behaviour described above, add the following to your WORKSPACE.yaml:
		//   environmentManifest:
		//     - name: docker
		//       command: ["docker", "version", "--format", "{{.Client.Version}} {{.Server.Version}}"]
		//
	},
	GoPackage: []EnvironmentManifestEntry{
		{Name: "go", Command: []string{"go", "version"}},
	},
	YarnPackage: []EnvironmentManifestEntry{
		{Name: "yarn", Command: []string{"yarn", "-v"}},
		{Name: "node", Command: []string{"node", "--version"}},
	},
}

// ShouldIgnoreComponent returns true if a file should be ignored for a component listing
func (ws *Workspace) ShouldIgnoreComponent(path string) bool {
	return ws.ShouldIgnoreSource(path)
}

// ShouldIgnoreSource returns true if a file should be ignored for a source listing
func (ws *Workspace) ShouldIgnoreSource(path string) bool {
	for _, ptn := range ws.ignores {
		if strings.Contains(path, ptn) {
			return true
		}
	}
	return false
}

// loadWorkspaceYAML loads a workspace's YAML file only - does not linking or processing of any kind.
// Probably you want to use loadWorkspace instead.
func loadWorkspaceYAML(path string) (Workspace, error) {
	root := filepath.Join(path, "WORKSPACE.yaml")
	fc, err := os.ReadFile(root)
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
	return workspace, nil
}

type loadWorkspaceOpts struct {
	PrelinkModifier   func(map[string]*Package)
	ArgumentDefaults  map[string]string
	ProvenanceKeyPath string
}

func loadWorkspace(ctx context.Context, path string, args Arguments, variant string, opts *loadWorkspaceOpts) (Workspace, error) {
	ctx, task := trace.NewTask(ctx, "loadWorkspace")
	defer task.End()

	workspace, err := loadWorkspaceYAML(path)
	if err != nil {
		return Workspace{}, err
	}

	if variant != "" {
		for _, vnt := range workspace.Variants {
			if vnt.Name == variant {
				workspace.SelectedVariant = vnt
				break
			}
		}
	} else if workspace.DefaultVariant != nil {
		workspace.SelectedVariant = workspace.DefaultVariant
		log.WithField("defaults", *workspace.SelectedVariant).Debug("applying default variant")
	}

	var ignores []string
	ignoresFile := filepath.Join(workspace.Origin, ".leewayignore")
	if _, err := os.Stat(ignoresFile); !os.IsNotExist(err) {
		fc, err := os.ReadFile(ignoresFile)
		if err != nil {
			return Workspace{}, err
		}
		ignores = strings.Split(string(fc), "\n")
	}
	otherWS, err := doublestar.Glob(workspace.Origin, "**/WORKSPACE.yaml", workspace.ShouldIgnoreSource)
	if err != nil {
		return Workspace{}, err
	}
	for _, ows := range otherWS {
		dir := filepath.Dir(ows)
		if dir == workspace.Origin {
			continue
		}

		ignores = append(ignores, dir)
	}
	workspace.ignores = ignores
	log.WithField("ignores", workspace.ignores).Debug("computed workspace ignores")

	if workspace.ArgumentDefaults == nil {
		workspace.ArgumentDefaults = make(map[string]string)
	}
	if len(opts.ArgumentDefaults) > 0 {
		for k, v := range opts.ArgumentDefaults {
			workspace.ArgumentDefaults[k] = v
		}
		log.WithField("rootDefaultArgs", opts.ArgumentDefaults).Debug("installed root workspace defaults")
	}

	defaultArgsFN := filepath.Join(path, "WORKSPACE.args.yaml")
	if fc, err := os.ReadFile(defaultArgsFN); err == nil {
		defargs := make(map[string]string)
		err = yaml.Unmarshal(fc, &defargs)
		if err != nil {
			return Workspace{}, xerrors.Errorf("cannot unmarshal %s: %w", defaultArgsFN, err)
		}
		for k, v := range defargs {
			workspace.ArgumentDefaults[k] = v
		}
		log.WithField("content", defargs).WithField("filename", defaultArgsFN).Debug("applied workspace default args file")
	} else if os.IsNotExist(err) {
		// ignore
	} else {
		return Workspace{}, xerrors.Errorf("cannot read %s: %w", defaultArgsFN, err)
	}

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

	comps, err := discoverComponents(ctx, &workspace, args, workspace.SelectedVariant, opts)
	if err != nil {
		return workspace, err
	}
	workspace.Components = make(map[string]*Component)
	workspace.Packages = make(map[string]*Package)
	workspace.Scripts = make(map[string]*Script)
	packageTypesUsed := make(map[PackageType]struct{})
	for _, comp := range comps {
		workspace.Components[comp.Name] = comp

		for _, pkg := range comp.Packages {
			workspace.Packages[pkg.FullName()] = pkg
			packageTypesUsed[pkg.Type] = struct{}{}
		}
		for _, script := range comp.Scripts {
			workspace.Scripts[script.FullName()] = script
		}
	}

	// with all packages loaded we can compute the env manifest, becuase now we know which package types are actually
	// used, hence know the default env manifest entries.
	workspace.EnvironmentManifest, err = buildEnvironmentManifest(workspace.EnvironmentManifest, packageTypesUsed)
	if err != nil {
		return Workspace{}, err
	}

	// if this workspace has a Git repo at its root, resolve its commit hash
	gitnfo, err := GetGitInfo(workspace.Origin)
	if err != nil {
		return workspace, xerrors.Errorf("cannot get Git info: %w", err)
	}
	if gitnfo != nil {
		// if there's no Git repo at the root of the workspace, gitnfo will be nil
		workspace.Git = *gitnfo
	}

	// now that we have all components/packages, we can link things
	if opts != nil && opts.PrelinkModifier != nil {
		opts.PrelinkModifier(workspace.Packages)
	}
	for _, pkg := range workspace.Packages {
		err := pkg.link(workspace.Packages)
		if err != nil {
			return workspace, xerrors.Errorf("linking error in package %s: %w", pkg.FullName(), err)
		}
	}
	for _, script := range workspace.Scripts {
		err := script.link(workspace.Packages)
		if err != nil {
			return workspace, xerrors.Errorf("linking error in script %s: %w", script.FullName(), err)
		}
	}

	// dependency cycles break the version computation and are not allowed
	for _, p := range workspace.Packages {
		c, err := p.findCycle()
		if err != nil {
			log.WithError(err).WithField("pkg", p.FullName()).Warn("internal error - skipping cycle detection")
			continue
		}
		if len(c) == 0 {
			continue
		}

		return workspace, xerrors.Errorf("dependency cycle found: %s", strings.Join(c, " -> "))
	}

	// at this point all packages are fully loaded and we can compute the version, as well as resolve builtin variables
	for _, pkg := range workspace.Packages {
		err = pkg.resolveBuiltinVariables()
		if err != nil {
			return workspace, xerrors.Errorf("cannot resolve builtin variables %s: %w", pkg.FullName(), err)
		}
	}

	// if the workspace has provenance enabled and a keypath specified (or the loadOpts specify one),
	// try and load the key
	if workspace.Provenance.Enabled {
		if opts.ProvenanceKeyPath != "" {
			workspace.Provenance.KeyPath = opts.ProvenanceKeyPath
		}
		fn := workspace.Provenance.KeyPath
		if fn != "" {
			var key in_toto.Key
			err = key.LoadKeyDefaults(fn)
			if err != nil {
				return workspace, xerrors.Errorf("cannot load workspace provenance signature key %s: %w", fn, err)
			}
			workspace.Provenance.key = &key
		}
	}

	return workspace, nil
}

// buildEnvironmentManifest executes the commands of an env manifest and updates the values
func buildEnvironmentManifest(entries EnvironmentManifest, pkgtpes map[PackageType]struct{}) (res EnvironmentManifest, err error) {
	t0 := time.Now()

	envmf := make(map[string]EnvironmentManifestEntry, len(entries))
	for _, e := range defaultEnvManifestEntries[""] {
		envmf[e.Name] = e
	}
	for tpe := range pkgtpes {
		for _, e := range defaultEnvManifestEntries[tpe] {
			envmf[e.Name] = e
		}
	}
	for _, e := range entries {
		e := e
		envmf[e.Name] = e
	}

	for k, e := range envmf {
		if e.Builtin {
			switch e.Command[0] {
			case builtinEnvManifestGOARCH:
				e.Value = runtime.GOARCH
			case builtinEnvManifestGOOS:
				e.Value = runtime.GOOS
			}
			res = append(res, e)
			continue
		}

		out := bytes.NewBuffer(nil)
		cmd := exec.Command(e.Command[0], e.Command[1:]...)
		cmd.Stdout = out
		err := cmd.Run()
		if err != nil {
			return nil, xerrors.Errorf("cannot resolve env manifest entry %v: %w", k, err)
		}
		e.Value = strings.TrimSpace(out.String())

		res = append(res, e)
	}

	sort.Slice(res, func(i, j int) bool { return res[i].Name < res[j].Name })

	log.WithField("time", time.Since(t0).String()).WithField("res", res).Debug("built environment manifest")

	return
}

// FindWorkspace looks for a WORKSPACE.yaml file within the path. If multiple such files are found,
// an error is returned.
func FindWorkspace(path string, args Arguments, variant, provenanceKey string) (Workspace, error) {
	return loadWorkspace(context.Background(), path, args, variant, &loadWorkspaceOpts{ProvenanceKeyPath: provenanceKey})
}

// discoverComponents discovers components in a workspace
func discoverComponents(ctx context.Context, workspace *Workspace, args Arguments, variant *PackageVariant, opts *loadWorkspaceOpts) ([]*Component, error) {
	defer trace.StartRegion(context.Background(), "discoverComponents").End()

	path := workspace.Origin
	pths, err := doublestar.Glob(path, "**/BUILD.yaml", workspace.ShouldIgnoreSource)
	if err != nil {
		return nil, err
	}

	eg, ctx := errgroup.WithContext(ctx)
	cchan := make(chan *Component, 20)

	for _, pth := range pths {
		if workspace.ShouldIgnoreComponent(pth) {
			continue
		}

		pth := pth
		eg.Go(func() error {
			comp, err := loadComponent(ctx, workspace, pth, args, variant)
			if err != nil {
				return err
			}
			cchan <- &comp
			return nil
		})
	}
	var (
		comps []*Component
		wg    sync.WaitGroup
	)
	wg.Add(1)
	go func() {
		defer wg.Done()

		for c := range cchan {
			// filter variant-excluded components and all their packages
			if filterExcludedComponents(variant, c) {
				continue
			}

			comps = append(comps, c)
		}
	}()
	err = eg.Wait()
	close(cchan)
	if err != nil {
		return nil, err
	}
	wg.Wait()

	return comps, nil
}

// filterExcludedComponents returns true if the component is excluded by the variant.
// This function also removes all dependencies to excluded components.
func filterExcludedComponents(variant *PackageVariant, c *Component) (ignoreComponent bool) {
	if variant == nil {
		return false
	}
	if variant.ExcludeComponent(c.Name) {
		log.WithField("component", c.Name).Debug("selected variant excludes this component")
		return true
	}

	for _, p := range c.Packages {
		for i, dep := range p.Dependencies {
			segs := strings.Split(dep, ":")
			if len(segs) != 2 {
				continue
			}

			if variant.ExcludeComponent(segs[0]) {
				p.Dependencies[i] = p.Dependencies[len(p.Dependencies)-1]
				p.Dependencies = p.Dependencies[:len(p.Dependencies)-1]
			}
		}
	}
	return false
}

// loadComponent loads a component from a BUILD.yaml file
func loadComponent(ctx context.Context, workspace *Workspace, path string, args Arguments, variant *PackageVariant) (c Component, err error) {
	defer trace.StartRegion(context.Background(), "loadComponent").End()
	trace.Log(ctx, "component", path)
	defer func() {
		if err != nil {
			err = xerrors.Errorf("%s: %w", path, err)
		}
	}()

	fc, err := os.ReadFile(path)
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
		log.WithField("comp", path).WithField("const", k).Debug("using const as arg")
	}

	// replace build args
	var rfc []byte = fc
	if len(args) > 0 {
		rfc = replaceBuildArguments(fc, compargs)
	}

	var (
		comp    Component
		rawcomp struct {
			Packages []yaml.Node
		}
	)
	err = yaml.Unmarshal(rfc, &comp)
	if err != nil {
		return comp, err
	}
	err = yaml.Unmarshal(fc, &rawcomp)
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

	// if this component has a Git repo at its root, resolve its commit hash
	comp.git, err = GetGitInfo(comp.Origin)
	if err != nil {
		log.WithField("comp", comp.Name).WithError(err).Warn("cannot get Git commit")
		err = nil
	}

	builderFN := strings.TrimSuffix(path, ".yaml") + ".js"
	if _, err := os.Stat(builderFN); err == nil {
		addFC, err := runPackageBuilder(builderFN, args)
		if err != nil {
			return Component{}, err
		}
		for _, p := range addFC {
			fc, err := yaml.Marshal(p)
			if err != nil {
				return Component{}, err
			}
			log.WithField("fc", string(fc)).WithField("component", comp.Name).Debug("adding dynamic package")

			var nd yaml.Node
			err = yaml.Unmarshal(fc, &nd)
			if err != nil {
				return Component{}, err
			}

			var pkg Package
			err = yaml.Unmarshal(fc, &pkg)
			if err != nil {
				return Component{}, err
			}

			comp.Packages = append(comp.Packages, &pkg)
			rawcomp.Packages = append(rawcomp.Packages, nd)
		}
	}

	for i, pkg := range comp.Packages {
		pkg.C = &comp

		pkg.Definition, err = yaml.Marshal(&rawcomp.Packages[i])
		if err != nil {
			return comp, xerrors.Errorf("%s: %w", comp.Name, err)
		}

		pkg.originalSources = pkg.Sources
		pkg.Sources, err = resolveSources(pkg.C.W, pkg.C.Origin, pkg.Sources, false)
		if err != nil {
			return comp, xerrors.Errorf("%s: %w", comp.Name, err)
		}

		// add additional sources to package sources
		completeSources := make(map[string]struct{})
		for _, src := range pkg.Sources {
			completeSources[src] = struct{}{}
		}
		for _, src := range pkg.Config.AdditionalSources(workspace.Origin) {
			fn := src
			if !filepath.IsAbs(fn) {
				var err error
				fn, err = filepath.Abs(filepath.Join(comp.Origin, src))
				if err != nil {
					return comp, xerrors.Errorf("%s: %w", comp.Name, err)
				}
			}

			if _, err := os.Stat(fn); os.IsNotExist(err) {
				return comp, xerrors.Errorf("cannot find additional source for %s: %w", comp.Name, err)
			}
			if _, found := completeSources[fn]; found {
				continue
			}

			completeSources[fn] = struct{}{}
		}
		if vnt := pkg.C.W.SelectedVariant; vnt != nil {
			incl, excl, err := vnt.ResolveSources(pkg.C.W, pkg.C.Origin)
			if err != nil {
				return comp, xerrors.Errorf("%s: %w", comp.Name, err)
			}
			for _, i := range incl {
				completeSources[i] = struct{}{}
			}
			for _, i := range excl {
				delete(completeSources, i)
			}
			log.WithField("pkg", pkg.Name).WithField("variant", variant).WithField("excl", excl).WithField("incl", incl).WithField("package", pkg.FullName()).Debug("applying variant")
		}
		pkg.Sources = make([]string, len(completeSources))
		i := 0
		for src := range completeSources {
			pkg.Sources[i] = src
			i++
		}

		// re-set the version relevant arguments to <name>: <value>
		for i, argdep := range pkg.ArgumentDependencies {
			val, ok := pkg.C.Constants[argdep]
			if !ok {
				val, ok = args[argdep]
			}
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
		// make all layout entries full qualified
		if pkg.Layout == nil {
			pkg.Layout = make(map[string]string)
		}
		for dep, loc := range pkg.Layout {
			if !strings.HasPrefix(dep, ":") {
				continue
			}

			delete(pkg.Layout, dep)
			pkg.Layout[comp.Name+dep] = loc
		}

		// apply variant config
		if vnt := pkg.C.W.SelectedVariant; vnt != nil {
			if vntcfg, ok := vnt.Config(pkg.Type); ok {
				err = mergeConfig(pkg, vntcfg)
				if err != nil {
					return comp, xerrors.Errorf("%s: %w", comp.Name, err)
				}
			}

			err = mergeEnv(pkg, vnt.Environment)
			if err != nil {
				return comp, xerrors.Errorf("%s: %w", comp.Name, err)
			}
		}
	}

	for _, scr := range comp.Scripts {
		scr.C = &comp

		// fill in defaults
		if scr.Type == "" {
			scr.Type = BashScript
		}
		if scr.WorkdirLayout == "" {
			scr.WorkdirLayout = WorkdirOrigin
		}

		// make all dependencies fully qualified
		for idx, dep := range scr.Dependencies {
			if !strings.HasPrefix(dep, ":") {
				continue
			}

			scr.Dependencies[idx] = comp.Name + dep
		}
	}

	return comp, nil
}

func mergeConfig(pkg *Package, src PackageConfig) error {
	if src == nil {
		return nil
	}

	switch pkg.Config.(type) {
	case YarnPkgConfig:
		dst := pkg.Config.(YarnPkgConfig)
		in, ok := src.(YarnPkgConfig)
		if !ok {
			return xerrors.Errorf("cannot merge %s onto %s", reflect.TypeOf(src).String(), reflect.TypeOf(dst).String())
		}
		err := mergo.Merge(&dst, in)
		if err != nil {
			return err
		}
		pkg.Config = dst
	case GoPkgConfig:
		dst := pkg.Config.(GoPkgConfig)
		in, ok := src.(GoPkgConfig)
		if !ok {
			return xerrors.Errorf("cannot merge %s onto %s", reflect.TypeOf(src).String(), reflect.TypeOf(dst).String())
		}
		err := mergo.Merge(&dst, in)
		if err != nil {
			return err
		}
		pkg.Config = dst
	case DockerPkgConfig:
		dst := pkg.Config.(DockerPkgConfig)
		in, ok := src.(DockerPkgConfig)
		if !ok {
			return xerrors.Errorf("cannot merge %s onto %s", reflect.TypeOf(src).String(), reflect.TypeOf(dst).String())
		}
		err := mergo.Merge(&dst, in)
		if err != nil {
			return err
		}
		pkg.Config = dst
	case GenericPkgConfig:
		dst := pkg.Config.(GenericPkgConfig)
		in, ok := src.(GenericPkgConfig)
		if !ok {
			return xerrors.Errorf("cannot merge %s onto %s", reflect.TypeOf(src).String(), reflect.TypeOf(dst).String())
		}
		err := mergo.Merge(&dst, in)
		if err != nil {
			return err
		}
		pkg.Config = dst
	default:
		return xerrors.Errorf("unknown config type %s", reflect.ValueOf(pkg.Config).Elem().Type().String())
	}
	return nil
}

func mergeEnv(pkg *Package, src []string) error {
	env := make(map[string]string, len(pkg.Environment))
	for _, set := range [][]string{pkg.Environment, src} {
		for _, kv := range set {
			segs := strings.Split(kv, "=")
			if len(segs) < 2 {
				return xerrors.Errorf("environment variable must have format ENV=VAR: %s", kv)
			}

			env[segs[0]] = strings.Join(segs[1:], "=")
		}

	}

	pkg.Environment = make([]string, 0, len(env))
	for k, v := range env {
		pkg.Environment = append(pkg.Environment, fmt.Sprintf("%s=%s", k, v))
	}
	return nil
}

func runPackageBuilder(fn string, args Arguments) (fc []map[string]interface{}, err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("failed to run package builder script at %s: %w", fn, err)
		}
	}()

	prog, err := os.ReadFile(fn)
	if err != nil {
		return nil, err
	}

	vm := goja.New()
	err = vm.Set("args", args)
	if err != nil {
		return nil, err
	}
	_, err = vm.RunString(string(prog))
	if err != nil {
		return nil, err
	}

	var res []map[string]interface{}
	err = vm.ExportTo(vm.Get("packages"), &res)
	if err != nil {
		return nil, err
	}

	log.WithField("res", res).WithField("fn", fn).Debug("ran package builder script")

	return res, nil
}
