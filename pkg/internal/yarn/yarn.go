package yarn

import (
	"encoding/json"
	"io/ioutil"
	"path/filepath"

	"github.com/typefox/leeway/pkg/leeway"
	"golang.org/x/xerrors"
)

// PackageJSON represents Yarn package's package.json file
type PackageJSON struct {
	// Origin is the location in the filesystem
	Origin string `json:"-"`

	Name         PackageName                 `json:"name"`
	Version      string                      `json:"version"`
	Dependencies map[PackageName]interface{} `json:"dependencies"`
}

// GetPackageJSON loads the package JSON of a Yarn package.
// Returns nil if the package is not a Yarn package.
func GetPackageJSON(pkg *leeway.Package) (*PackageJSON, error) {
	if pkg.Type != leeway.YarnPackage {
		return nil, nil
	}

	var (
		found bool
		pkgFN = filepath.Join(pkg.C.Origin, "package.json")
	)
	for _, src := range pkg.Sources {
		if src == pkgFN {
			found = true
			break
		}
	}
	if !found {
		return nil, xerrors.Errorf("package %s has no package.json", pkg.FullName())
	}

	fc, err := ioutil.ReadFile(pkgFN)
	if err != nil {
		return nil, err
	}
	var res PackageJSON
	err = json.Unmarshal(fc, &res)
	if err != nil {
		return nil, err
	}

	if res.Name == "" {
		return nil, xerrors.Errorf("package %s has no Yarn package name", pkg.FullName())
	}

	res.Origin = pkgFN

	return &res, nil
}

// PackageName is the value of the name field in a package.json file
type PackageName string

// MapYarnToLeeway maps the yarn package namespace of a worksapce to leeway packages.
// Note that this is not an injective (one-to-one) mapping, as multiple leeway packages can be based on the same yarn package.
func MapYarnToLeeway(ws *leeway.Workspace) (leewayIdx map[PackageName][]*leeway.Package, yarnIdx map[PackageName]PackageJSON, err error) {
	leewayIdx = make(map[PackageName][]*leeway.Package)
	yarnIdx = make(map[PackageName]PackageJSON)

	for _, pkg := range ws.Packages {
		if pkg.Type != leeway.YarnPackage {
			continue
		}

		pkgjson, err := GetPackageJSON(pkg)
		if err != nil {
			return nil, nil, err
		}

		leewayIdx[pkgjson.Name] = append(leewayIdx[pkgjson.Name], pkg)
		yarnIdx[pkgjson.Name] = *pkgjson
	}

	return
}
