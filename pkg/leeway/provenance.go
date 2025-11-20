package leeway

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/common"
	slsa "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v0.2"
	log "github.com/sirupsen/logrus"
	"golang.org/x/xerrors"
	"sigs.k8s.io/bom/pkg/provenance"
)

const (
	// ProvenanceBundleFilename is the filename suffix for provenance bundles stored alongside artifacts.
	// Provenance is stored as <artifact>.tar.gz + ProvenanceBundleFilename to keep it separate from the
	// deterministic artifact tar.gz.
	//
	// BEWARE: when you change this value this will break consumers. Existing
	//		   cached artefacts will not have the new filename which will break
	//         builds. If you change this value, make sure you introduce a cache-invalidating
	//         change, e.g. update the provenanceProcessVersion.
	ProvenanceBundleFilename = ".provenance.jsonl"

	// provenanceProcessVersion is the version of the provenance generating process.
	// If provenance is enabled in a workspace, this version becomes part of the manifest,
	// hence changing it will invalidate previously built packages.
	//
	// Version 4: Provenance stored exclusively outside tar.gz as <artifact>.provenance.jsonl
	//            Removed backward compatibility fallback to read from inside tar.gz.
	//            This ensures artifacts remain deterministic and cache invalidation works correctly.
	provenanceProcessVersion = 4

	// ProvenanceBuilderID is the prefix we use as Builder ID when issuing provenance
	ProvenanceBuilderID = "github.com/gitpod-io/leeway"
)

// writeProvenance produces a provenance bundle and writes it alongside the artifact in the cache.
// The provenance is written to <artifact>.provenance.jsonl (outside the tar.gz) to maintain artifact determinism.
// This function should be called AFTER the artifact tar.gz has been created.
func writeProvenance(p *Package, buildctx *buildContext, builddir string, subjects []in_toto.Subject, buildStarted time.Time) (err error) {
	if !p.C.W.Provenance.Enabled {
		return nil
	}

	// Get the artifact path in cache
	// Location() returns (path, exists) - during build it returns .tar path even if file doesn't exist yet
	artifactPath, exists := buildctx.LocalCache.Location(p)
	if artifactPath == "" {
		return fmt.Errorf("cannot determine cache location for %s", p.FullName())
	}

	// Determine the actual artifact path (.tar.gz)
	// Location() returns .tar.gz if it exists, otherwise .tar
	if !exists {
		// Artifact doesn't exist yet - this shouldn't happen as provenance should be written after packaging
		log.WithField("package", p.FullName()).WithField("path", artifactPath).Warn("Writing provenance before artifact exists")
	}

	// Ensure we use the .tar.gz extension
	if strings.HasSuffix(artifactPath, ".tar") && !strings.HasSuffix(artifactPath, ".tar.gz") {
		artifactPath = artifactPath + ".gz"
	} else if !strings.HasSuffix(artifactPath, ".tar.gz") && !strings.HasSuffix(artifactPath, ".tar") {
		artifactPath = artifactPath + ".tar.gz"
	}

	// Write provenance alongside artifact: <artifact>.provenance.jsonl
	// This keeps provenance metadata separate from the artifact for determinism
	provenancePath := artifactPath + ProvenanceBundleFilename

	// Ensure directory exists
	dir := filepath.Dir(provenancePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("cannot create provenance directory for %s: %w", p.FullName(), err)
	}

	f, err := os.OpenFile(provenancePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("cannot write provenance for %s: %w", p.FullName(), err)
	}
	defer f.Close()

	bundle := newAttestationBundle(f)
	err = p.getDependenciesProvenanceBundles(buildctx, bundle)
	if err != nil {
		return err
	}

	if p.C.W.Provenance.SLSA {
		env, err := p.produceSLSAEnvelope(buildctx, subjects, buildStarted)
		if err != nil {
			return err
		}

		err = bundle.Add(env)
		if err != nil {
			return err
		}
	}

	log.WithField("path", provenancePath).WithField("package", p.FullName()).Debug("wrote provenance bundle to cache (outside tar.gz)")

	return nil
}

func (p *Package) getDependenciesProvenanceBundles(buildctx *buildContext, dst *AttestationBundle) error {
	deps := p.GetDependencies()
	prevBundleSize := dst.Len()
	for _, dep := range deps {
		loc, exists := buildctx.LocalCache.Location(dep)
		if !exists {
			return PkgNotBuiltErr{dep}
		}

		err := AccessAttestationBundleInCachedArchive(loc, func(bundle io.Reader) error {
			return dst.AddFromBundle(bundle)
		})
		if err != nil {
			return err
		}
		log.WithField("prevBundleSize", prevBundleSize).WithField("newBundleSize", dst.Len()).WithField("loc", loc).Debug("extracted bundle from cached archive")
		prevBundleSize = dst.Len()
	}
	return nil
}

var ErrNoAttestationBundle error = fmt.Errorf("no attestation bundle found")

// fileExists checks if a file exists and is not a directory
func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if err != nil {
		return false
	}
	return !info.IsDir()
}

// AccessAttestationBundleInCachedArchive provides access to the attestation bundle for a cached build artifact.
// Reads from <artifact>.provenance.jsonl (outside tar.gz).
// If no bundle exists, ErrNoAttestationBundle is returned.
func AccessAttestationBundleInCachedArchive(fn string, handler func(bundle io.Reader) error) (err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("error accessing provenance bundle for %s: %w", fn, err)
		}
	}()

	provenancePath := fn + ProvenanceBundleFilename
	if !fileExists(provenancePath) {
		return ErrNoAttestationBundle
	}

	f, err := os.Open(provenancePath)
	if err != nil {
		return err
	}
	defer f.Close()

	return handler(f)
}

func (p *Package) produceSLSAEnvelope(buildctx *buildContext, subjects []in_toto.Subject, buildStarted time.Time) (res *provenance.Envelope, err error) {
	git := p.C.Git()
	if git.Commit == "" || git.Origin == "" {
		return nil, xerrors.Errorf("Git provenance is unclear - do not have any Git info")
	}

	var (
		now  = time.Now()
		pred = provenance.NewSLSAPredicate()
	)
	if p.C.Git().DirtyFiles(p.Sources) {
		files, err := p.inTotoMaterials()
		if err != nil {
			return nil, err
		}

		// It's unlikely that the BUILD.yaml is part of the material list - certainly the WORKSPACE.yaml
		// isn't. If so, we need to add them to the materials to provide full provenance for the recipe.
		var (
			buildYamlFN        = filepath.Join(p.C.Origin, "BUILD.yaml")
			buildYAML          = materialFileURI(buildYamlFN, p.C.W.Origin)
			workspaceYamlFN    = filepath.Join(p.C.W.Origin, "WORKSPACE.yaml")
			workspaceYAML      = materialFileURI(workspaceYamlFN, p.C.W.Origin)
			foundBuildYAML     bool
			foundWorkspaceYAML bool
		)
		for _, m := range files {
			if m.URI == buildYAML {
				foundBuildYAML = true
			}
			if m.URI == workspaceYAML {
				foundBuildYAML = true
			}
		}
		if !foundBuildYAML {
			hash, err := sha256Hash(buildYamlFN)
			if err != nil {
				return nil, err
			}
			files = append(files, common.ProvenanceMaterial{
				URI:    buildYAML,
				Digest: common.DigestSet{"sha256": hash},
			})
		}
		if !foundWorkspaceYAML {
			hash, err := sha256Hash(workspaceYamlFN)
			if err != nil {
				return nil, err
			}
			files = append(files, common.ProvenanceMaterial{
				URI:    workspaceYAML,
				Digest: common.DigestSet{"sha256": hash},
			})
		}

		pred.Materials = files
	} else {
		pred.Materials = []common.ProvenanceMaterial{
			{URI: "git+" + git.Origin, Digest: common.DigestSet{"sha256": git.Commit}},
		}
	}

	pred.Builder = common.ProvenanceBuilder{
		ID: fmt.Sprintf("%s:%s@sha256:%s", ProvenanceBuilderID, Version, buildctx.leewayHash),
	}
	pred.Metadata = &slsa.ProvenanceMetadata{
		Completeness: slsa.ProvenanceComplete{
			Parameters:  true,
			Environment: false,
			Materials:   true,
		},
		Reproducible:    false,
		BuildStartedOn:  &buildStarted,
		BuildFinishedOn: &now,
	}
	pred.Invocation = slsa.ProvenanceInvocation{
		ConfigSource: slsa.ConfigSource{
			URI:        fmt.Sprintf("https://github.com/gitpod-io/leeway/build@%s:%d", p.Type, buildProcessVersions[p.Type]),
			Digest:     map[string]string{},
			EntryPoint: p.FullName(),
		},
		Parameters: map[string]interface{}{
			"args": os.Args,
		},
		Environment: map[string]interface{}{
			"manifest": p.C.W.EnvironmentManifest,
		},
	}

	stmt := provenance.NewSLSAStatement()
	stmt.Subject = subjects
	stmt.PredicateType = slsa.PredicateSLSAProvenance
	stmt.Predicate = pred

	payload, err := json.MarshalIndent(stmt, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("cannot marshal provenance for %s: %w", p.FullName(), err)
	}

	var sigs []interface{}
	if p.C.W.Provenance.key != nil {
		sig, err := in_toto.GenerateSignature(payload, *p.C.W.Provenance.key)
		if err != nil {
			return nil, fmt.Errorf("cannot sign provenance for %s: %w", p.FullName(), err)
		}
		sigs = append(sigs, sig)
	}

	return &provenance.Envelope{
		PayloadType: in_toto.PayloadType,
		Payload:     base64.StdEncoding.EncodeToString(payload),
		Signatures:  sigs,
	}, nil
}

func (p *Package) inTotoMaterials() ([]common.ProvenanceMaterial, error) {
	res := make([]common.ProvenanceMaterial, 0, len(p.Sources))
	for _, src := range p.Sources {
		skip, err := shouldSkipSource(src)
		if err != nil {
			return nil, err
		}

		if skip {
			continue
		}

		hash, err := sha256Hash(src)
		if err != nil {
			return nil, err
		}

		res = append(res, common.ProvenanceMaterial{
			URI: materialFileURI(src, p.C.W.Origin),
			Digest: map[string]string{
				"sha256": hash,
			},
		})
	}
	return res, nil
}

func materialFileURI(fn, workspaceOrigin string) string {
	return "file://" + strings.TrimPrefix(strings.TrimPrefix(fn, workspaceOrigin), "/")
}

func sha256Hash(fn string) (res string, err error) {
	f, err := os.Open(fn)
	if err != nil {
		return "", xerrors.Errorf("cannot compute hash of %s: %w", fn, err)
	}

	defer f.Close()

	hash := sha256.New()
	_, err = io.Copy(hash, f)
	if err != nil {
		return "", xerrors.Errorf("cannot compute hash of %s: %w", fn, err)
	}

	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}

type fileset map[string]struct{}

func computeFileset(dir string, ignoreFN ...func(fn string) bool) (fileset, error) {
	res := make(fileset)
	err := filepath.WalkDir(dir, func(path string, info fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		for _, ignore := range ignoreFN {
			if ignore(path) {
				return nil
			}
		}

		fn := strings.TrimPrefix(path, dir)
		res[fn] = struct{}{}
		return nil
	})
	log.WithField("prefix", dir).WithField("res", res).Debug("computing fileset")
	return res, err
}

// Sub produces a new fileset with all entries from the other fileset
func (fset fileset) Sub(other fileset) fileset {
	res := make(fileset, len(fset))
	for fn := range fset {
		if _, ok := other[fn]; ok {
			continue
		}
		res[fn] = struct{}{}
	}
	return res
}

func (fset fileset) Subjects(base string) ([]in_toto.Subject, error) {
	res := make([]in_toto.Subject, 0, len(fset))
	for src := range fset {
		f, err := os.Open(filepath.Join(base, src))
		if err != nil {
			return nil, xerrors.Errorf("cannot compute hash of %s: %w", src, err)
		}

		skip, err := shouldSkipSource(f.Name())
		if err != nil {
			return nil, xerrors.Errorf("cannot compute hash of %s: %w", src, err)
		}

		if skip {
			continue
		}

		hash := sha256.New()
		_, err = io.Copy(hash, f)
		if err != nil {
			return nil, xerrors.Errorf("cannot compute hash of %s: %w", src, err)
		}
		f.Close()

		res = append(res, in_toto.Subject{
			Name: src,
			Digest: common.DigestSet{
				"sha256": fmt.Sprintf("%x", hash.Sum(nil)),
			},
		})
	}
	return res, nil
}

// AttestationBundle represents an in-toto attestation bundle. See https://github.com/in-toto/attestation/blob/main/spec/bundle.md
// for more details.
type AttestationBundle struct {
	out  io.Writer
	keys map[string]struct{}
}

func newAttestationBundle(out io.Writer) *AttestationBundle {
	return &AttestationBundle{
		out:  out,
		keys: make(map[string]struct{}),
	}
}

// Add adds an entry to the bundle and writes it directly to the out writer.
// This function ensures an envelope is added only once.
// This function is not synchronised.
func (a *AttestationBundle) Add(env *provenance.Envelope) error {
	hash := sha256.New()
	err := json.NewEncoder(hash).Encode(env)
	if err != nil {
		return err
	}
	key := hex.EncodeToString(hash.Sum(nil))
	if _, exists := a.keys[key]; exists {
		return nil
	}

	err = json.NewEncoder(a.out).Encode(env)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(a.out)
	if err != nil {
		return err
	}
	a.keys[key] = struct{}{}

	return nil
}

// Adds the entries from another bundle to this one, writing them directly to the out writer.
// This function ensures entries are unique.
// This function is not synchronised.
func (a *AttestationBundle) AddFromBundle(other io.Reader) error {
	reader := bufio.NewReader(other)
	for {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}

		hash := sha256.New()
		_, err = hash.Write(line)
		if err != nil {
			return err
		}
		key := hex.EncodeToString(hash.Sum(nil))

		if _, exists := a.keys[key]; exists {
			continue
		}

		_, err = a.out.Write(line)
		if err != nil {
			return err
		}
		a.keys[key] = struct{}{}
	}
	return nil
}

func (a *AttestationBundle) Len() int { return len(a.keys) }

func shouldSkipSource(src string) (bool, error) {
	stat, err := os.Lstat(src)
	if err != nil {
		return false, err
	}

	if stat.Mode().IsDir() || !stat.Mode().IsRegular() {
		return true, nil
	}

	// in case of symlinks, we need to resolve the link and check the target
	if stat.Mode()&os.ModeSymlink == os.ModeSymlink {
		targetSrc, _ := os.Readlink(src)
		stat, err := os.Lstat(targetSrc)
		if err != nil {
			return false, err
		}

		if stat.Mode().IsDir() || !stat.Mode().IsRegular() {
			return true, nil
		}
	}

	return false, nil

}
