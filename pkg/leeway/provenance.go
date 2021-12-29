package leeway

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/in-toto/in-toto-golang/in_toto"
	log "github.com/sirupsen/logrus"
	"golang.org/x/xerrors"
	"sigs.k8s.io/bom/pkg/provenance"
)

const (
	// provenanceBundleFilename is the name of the attestation bundle file
	// we store in the archived build artefacts.
	//
	// BEWARE: when you change this value this will break consumers. Existing
	//		   cached artefacts will not have the new filename which will break
	//         builds. If you change this value, make sure you introduce a cache-invalidating
	//         change, e.g. a manifest change.
	provenanceBundleFilename = "provenance-bundle.jsonl"
)

var (
	// maxBundleEntrySize is the maximum size in bytes an attestation bundle entry may have.
	// If we encounter a bundle entry lager than this size, the build will fail.
	// Note: we'll allocate multiple buffers if this size, i.e. this size directly impacts
	//       the amount of memory required during a build (parralellBuildCount * maxBundleEntrySize).
	maxBundleEntrySize = func() int {
		env := os.Getenv("LEEWAY_MAX_PROVENANCE_BUNDLE_SIZE")
		res, err := strconv.ParseInt(env, 10, 64)
		if err != nil {
			return 2 * 1024 * 1024
		}

		return int(res)
	}()
)

// writeProvenance produces a provenanceWriter which ought to be used during package builds
func writeProvenance(p *Package, buildctx *buildContext, builddir string, subjects []in_toto.Subject) (err error) {
	if !p.C.W.Provenance.Enabled {
		return nil
	}

	bundle := make(map[string]struct{})
	err = p.getDependenciesProvenanceBundles(buildctx, bundle)
	if err != nil {
		return err
	}

	if p.C.W.Provenance.SLSA {
		env, err := p.produceSLSAEnvelope(subjects)
		if err != nil {
			return err
		}

		entry, err := json.Marshal(env)
		if err != nil {
			return err
		}

		bundle[string(entry)] = struct{}{}
	}

	f, err := os.OpenFile(filepath.Join(builddir, provenanceBundleFilename), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("cannot write provenance for %s: %w", p.FullName(), err)
	}
	defer f.Close()

	for entry := range bundle {
		_, err = f.WriteString(entry + "\n")
		if err != nil {
			return fmt.Errorf("cannot write provenance for %s: %w", p.FullName(), err)
		}
	}
	return nil
}

func (p *Package) getDependenciesProvenanceBundles(buildctx *buildContext, out map[string]struct{}) error {
	deps := p.GetTransitiveDependencies()
	for _, dep := range deps {
		loc, exists := buildctx.LocalCache.Location(dep)
		if !exists {
			return PkgNotBuiltErr{dep}
		}

		err := extractBundleFromCachedArchive(dep, loc, out)
		if err != nil {
			return err
		}
	}
	return nil
}

func extractBundleFromCachedArchive(dep *Package, loc string, out map[string]struct{}) (err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("error extracting provenance bundle from %s: %w", loc, err)
		}
	}()

	f, err := os.Open(loc)
	if err != nil {
		return err
	}
	defer f.Close()

	g, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer g.Close()

	var (
		prevBundleSize = len(out)
		bundleFound    bool
	)

	a := tar.NewReader(g)
	var hdr *tar.Header
	for {
		hdr, err = a.Next()
		if err == io.EOF {
			err = nil
			break
		}
		if err != nil {
			break
		}

		if hdr.Name != "./"+provenanceBundleFilename && hdr.Name != "package/"+provenanceBundleFilename {
			continue
		}

		// TOOD(cw): use something other than a scanner. We've seen "Token Too Long" in first trials already.
		scan := bufio.NewScanner(io.LimitReader(a, hdr.Size))
		scan.Buffer(make([]byte, maxBundleEntrySize), maxBundleEntrySize)
		for scan.Scan() {
			out[scan.Text()] = struct{}{}
		}
		if scan.Err() != nil {
			return scan.Err()
		}
		bundleFound = true
		break
	}
	if err != nil {
		return
	}

	if !bundleFound {
		return fmt.Errorf("dependency %s has no provenance bundle", dep.FullName())
	}

	log.WithField("prevBundleSize", prevBundleSize).WithField("newBundleSize", len(out)).WithField("loc", loc).Debug("extracted bundle from cached archive")

	return nil
}

func (p *Package) produceSLSAEnvelope(subjects []in_toto.Subject) (res *provenance.Envelope, err error) {
	git := p.C.Git()
	if git.Commit == "" || git.Origin == "" {
		return nil, xerrors.Errorf("Git provenance is unclear - do not have any Git info")
	}

	var (
		recipeMaterial *int
		now            = time.Now()
		pred           = provenance.NewSLSAPredicate()
	)
	if p.C.Git().Dirty {
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
			pos := len(files)
			recipeMaterial = &pos
			files = append(files, in_toto.ProvenanceMaterial{
				URI:    buildYAML,
				Digest: in_toto.DigestSet{"sha256": hash},
			})
		}
		if !foundWorkspaceYAML {
			hash, err := sha256Hash(workspaceYamlFN)
			if err != nil {
				return nil, err
			}
			files = append(files, in_toto.ProvenanceMaterial{
				URI:    workspaceYAML,
				Digest: in_toto.DigestSet{"sha256": hash},
			})
		}

		pred.Materials = files
	} else {
		pred.Materials = []in_toto.ProvenanceMaterial{
			{URI: "git+" + git.Origin, Digest: in_toto.DigestSet{"sha256": git.Commit}},
		}
		zero := 0
		recipeMaterial = &zero
	}

	pred.Builder = in_toto.ProvenanceBuilder{
		ID: "github.com/gitpod-io/leeway:" + Version,
	}
	pred.Metadata = &in_toto.ProvenanceMetadata{
		Completeness: in_toto.ProvenanceComplete{
			Arguments:   true,
			Environment: false,
			Materials:   true,
		},
		Reproducible:   false,
		BuildStartedOn: &now,
	}
	pred.Recipe = in_toto.ProvenanceRecipe{
		Type:              fmt.Sprintf("https://github.com/gitpod-io/leeway/build@%s:%d", p.Type, buildProcessVersions[p.Type]),
		Arguments:         os.Args,
		EntryPoint:        p.FullName(),
		DefinedInMaterial: recipeMaterial,
	}

	stmt := provenance.NewSLSAStatement()
	stmt.Subject = subjects
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

func (p *Package) inTotoMaterials() ([]in_toto.ProvenanceMaterial, error) {
	res := make([]in_toto.ProvenanceMaterial, 0, len(p.Sources))
	for _, src := range p.Sources {
		hash, err := sha256Hash(src)
		if err != nil {
			return nil, err
		}

		res = append(res, in_toto.ProvenanceMaterial{
			URI: materialFileURI(src, p.C.W.Origin),
			Digest: in_toto.DigestSet{
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

	hash := sha256.New()
	_, err = io.Copy(hash, f)
	if err != nil {
		return "", xerrors.Errorf("cannot compute hash of %s: %w", fn, err)
	}
	f.Close()

	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}

type fileset map[string]struct{}

func computeFileset(dir string) (fileset, error) {
	res := make(fileset)
	err := filepath.WalkDir(dir, func(path string, info fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}

		fn := strings.TrimPrefix(path, dir)
		res[fn] = struct{}{}
		return nil
	})
	log.WithField("prefix", dir).WithField("res", res).Debug("computing fileset")
	return res, err
}

// Sub produces a new fileset with all entries from the other fileset subjectraced
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

		hash := sha256.New()
		_, err = io.Copy(hash, f)
		if err != nil {
			return nil, xerrors.Errorf("cannot compute hash of %s: %w", src, err)
		}
		f.Close()

		res = append(res, in_toto.Subject{
			Name: src,
			Digest: in_toto.DigestSet{
				"sha256": fmt.Sprintf("%x", hash.Sum(nil)),
			},
		})
	}
	return res, nil
}
