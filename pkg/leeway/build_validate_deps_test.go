package leeway

import (
	"testing"

	"github.com/gitpod-io/leeway/pkg/leeway/cache"
	"github.com/stretchr/testify/require"
)

// mockLocalCache implements cache.LocalCache for testing
type mockLocalCache struct {
	packages map[string]string // fullName -> path
}

func newMockLocalCache() *mockLocalCache {
	return &mockLocalCache{
		packages: make(map[string]string),
	}
}

func (m *mockLocalCache) Location(pkg cache.Package) (string, bool) {
	path, exists := m.packages[pkg.FullName()]
	return path, exists
}

func (m *mockLocalCache) addPackage(fullName, path string) {
	m.packages[fullName] = path
}

// newTestPackage creates a test package with the given name and type
func newTestPackage(name string, pkgType PackageType) *Package {
	pkg := &Package{
		fullNameOverride: name,
		dependencies:     []*Package{},
	}
	pkg.PackageInternal.Type = pkgType
	return pkg
}

func TestValidateDependenciesAvailable(t *testing.T) {
	tests := []struct {
		name           string
		setupPackages  func() (*Package, map[*Package]PackageBuildStatus, *mockLocalCache)
		expectedResult bool
	}{
		{
			name: "package with no dependencies",
			setupPackages: func() (*Package, map[*Package]PackageBuildStatus, *mockLocalCache) {
				pkg := newTestPackage("test:pkg", GenericPackage)
				pkgstatus := map[*Package]PackageBuildStatus{
					pkg: PackageDownloaded,
				}
				cache := newMockLocalCache()
				cache.addPackage("test:pkg", "/cache/test-pkg.tar.gz")
				return pkg, pkgstatus, cache
			},
			expectedResult: true,
		},
		{
			name: "package with all dependencies in cache",
			setupPackages: func() (*Package, map[*Package]PackageBuildStatus, *mockLocalCache) {
				depA := newTestPackage("test:dep-a", GenericPackage)
				pkg := newTestPackage("test:pkg", GenericPackage)
				pkg.dependencies = []*Package{depA}

				pkgstatus := map[*Package]PackageBuildStatus{
					pkg:  PackageDownloaded,
					depA: PackageBuilt,
				}
				cache := newMockLocalCache()
				cache.addPackage("test:pkg", "/cache/test-pkg.tar.gz")
				cache.addPackage("test:dep-a", "/cache/test-dep-a.tar.gz")
				return pkg, pkgstatus, cache
			},
			expectedResult: true,
		},
		{
			name: "package with dependency marked for build",
			setupPackages: func() (*Package, map[*Package]PackageBuildStatus, *mockLocalCache) {
				depA := newTestPackage("test:dep-a", GenericPackage)
				pkg := newTestPackage("test:pkg", GenericPackage)
				pkg.dependencies = []*Package{depA}

				pkgstatus := map[*Package]PackageBuildStatus{
					pkg:  PackageDownloaded,
					depA: PackageNotBuiltYet, // Will be built
				}
				cache := newMockLocalCache()
				cache.addPackage("test:pkg", "/cache/test-pkg.tar.gz")
				// depA is NOT in cache but will be built
				return pkg, pkgstatus, cache
			},
			expectedResult: true,
		},
		{
			name: "package with dependency in remote cache",
			setupPackages: func() (*Package, map[*Package]PackageBuildStatus, *mockLocalCache) {
				depA := newTestPackage("test:dep-a", GenericPackage)
				pkg := newTestPackage("test:pkg", GenericPackage)
				pkg.dependencies = []*Package{depA}

				pkgstatus := map[*Package]PackageBuildStatus{
					pkg:  PackageDownloaded,
					depA: PackageInRemoteCache, // Will be downloaded
				}
				cache := newMockLocalCache()
				cache.addPackage("test:pkg", "/cache/test-pkg.tar.gz")
				return pkg, pkgstatus, cache
			},
			expectedResult: true,
		},
		{
			name: "package with missing dependency - not in cache, unknown status",
			setupPackages: func() (*Package, map[*Package]PackageBuildStatus, *mockLocalCache) {
				depA := newTestPackage("test:dep-a", GenericPackage)
				pkg := newTestPackage("test:pkg", GenericPackage)
				pkg.dependencies = []*Package{depA}

				pkgstatus := map[*Package]PackageBuildStatus{
					pkg: PackageDownloaded,
					// depA has no status entry
				}
				cache := newMockLocalCache()
				cache.addPackage("test:pkg", "/cache/test-pkg.tar.gz")
				// depA is NOT in cache
				return pkg, pkgstatus, cache
			},
			expectedResult: false,
		},
		{
			name: "package with ephemeral dependency - should be skipped",
			setupPackages: func() (*Package, map[*Package]PackageBuildStatus, *mockLocalCache) {
				depA := newTestPackage("test:dep-a", GenericPackage)
				depA.Ephemeral = true // Ephemeral packages are always rebuilt

				pkg := newTestPackage("test:pkg", GenericPackage)
				pkg.dependencies = []*Package{depA}

				pkgstatus := map[*Package]PackageBuildStatus{
					pkg: PackageDownloaded,
					// depA has no status - but it's ephemeral so should be skipped
				}
				cache := newMockLocalCache()
				cache.addPackage("test:pkg", "/cache/test-pkg.tar.gz")
				return pkg, pkgstatus, cache
			},
			expectedResult: true,
		},
		{
			name: "Go package with transitive dependency missing",
			setupPackages: func() (*Package, map[*Package]PackageBuildStatus, *mockLocalCache) {
				depB := newTestPackage("test:dep-b", GenericPackage)
				depA := newTestPackage("test:dep-a", GenericPackage)
				depA.dependencies = []*Package{depB}

				pkg := newTestPackage("test:pkg", GoPackage) // Go packages need transitive deps
				pkg.dependencies = []*Package{depA}

				pkgstatus := map[*Package]PackageBuildStatus{
					pkg:  PackageDownloaded,
					depA: PackageBuilt,
					// depB has no status - missing transitive dependency
				}
				cache := newMockLocalCache()
				cache.addPackage("test:pkg", "/cache/test-pkg.tar.gz")
				cache.addPackage("test:dep-a", "/cache/test-dep-a.tar.gz")
				// depB is NOT in cache
				return pkg, pkgstatus, cache
			},
			expectedResult: false,
		},
		{
			name: "Go package with all transitive dependencies available",
			setupPackages: func() (*Package, map[*Package]PackageBuildStatus, *mockLocalCache) {
				depB := newTestPackage("test:dep-b", GenericPackage)
				depA := newTestPackage("test:dep-a", GenericPackage)
				depA.dependencies = []*Package{depB}

				pkg := newTestPackage("test:pkg", GoPackage)
				pkg.dependencies = []*Package{depA}

				pkgstatus := map[*Package]PackageBuildStatus{
					pkg:  PackageDownloaded,
					depA: PackageBuilt,
					depB: PackageBuilt,
				}
				cache := newMockLocalCache()
				cache.addPackage("test:pkg", "/cache/test-pkg.tar.gz")
				cache.addPackage("test:dep-a", "/cache/test-dep-a.tar.gz")
				cache.addPackage("test:dep-b", "/cache/test-dep-b.tar.gz")
				return pkg, pkgstatus, cache
			},
			expectedResult: true,
		},
		{
			name: "Docker package only checks direct dependencies",
			setupPackages: func() (*Package, map[*Package]PackageBuildStatus, *mockLocalCache) {
				depB := newTestPackage("test:dep-b", GenericPackage)
				depA := newTestPackage("test:dep-a", GenericPackage)
				depA.dependencies = []*Package{depB}

				pkg := newTestPackage("test:pkg", DockerPackage) // Docker only needs direct deps
				pkg.dependencies = []*Package{depA}

				pkgstatus := map[*Package]PackageBuildStatus{
					pkg:  PackageDownloaded,
					depA: PackageBuilt,
					// depB has no status - but Docker doesn't need it
				}
				cache := newMockLocalCache()
				cache.addPackage("test:pkg", "/cache/test-pkg.tar.gz")
				cache.addPackage("test:dep-a", "/cache/test-dep-a.tar.gz")
				// depB is NOT in cache - but Docker doesn't check transitive deps
				return pkg, pkgstatus, cache
			},
			expectedResult: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkg, pkgstatus, cache := tt.setupPackages()
			result := validateDependenciesAvailable(pkg, cache, pkgstatus)
			require.Equal(t, tt.expectedResult, result)
		})
	}
}

func TestValidateDependenciesAvailable_YarnPackage(t *testing.T) {
	// Yarn packages should check transitive dependencies like Go packages
	depB := newTestPackage("test:dep-b", GenericPackage)
	depA := newTestPackage("test:dep-a", GenericPackage)
	depA.dependencies = []*Package{depB}

	pkg := newTestPackage("test:pkg", YarnPackage)
	pkg.dependencies = []*Package{depA}

	pkgstatus := map[*Package]PackageBuildStatus{
		pkg:  PackageDownloaded,
		depA: PackageBuilt,
		// depB missing
	}

	cache := newMockLocalCache()
	cache.addPackage("test:pkg", "/cache/test-pkg.tar.gz")
	cache.addPackage("test:dep-a", "/cache/test-dep-a.tar.gz")

	// Should fail because Yarn needs transitive deps
	result := validateDependenciesAvailable(pkg, cache, pkgstatus)
	require.False(t, result, "Yarn package should fail validation when transitive dependency is missing")
}
