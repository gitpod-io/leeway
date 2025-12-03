package leeway

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestSortPackagesByDependencyDepth tests the dependency-aware sorting
func TestSortPackagesByDependencyDepth(t *testing.T) {
	tests := []struct {
		name     string
		packages []*Package
		validate func(t *testing.T, sorted []*Package)
	}{
		{
			name:     "empty list",
			packages: []*Package{},
			validate: func(t *testing.T, sorted []*Package) {
				require.Equal(t, 0, len(sorted))
			},
		},
		{
			name: "single package",
			packages: []*Package{
				{fullNameOverride: "pkg1"},
			},
			validate: func(t *testing.T, sorted []*Package) {
				require.Equal(t, 1, len(sorted))
				require.Equal(t, "pkg1", sorted[0].FullName())
			},
		},
		{
			name: "linear dependency chain",
			packages: []*Package{
				{fullNameOverride: "leaf", dependencies: []*Package{}},
				{
					fullNameOverride: "middle",
					dependencies: []*Package{
						{fullNameOverride: "leaf", dependencies: []*Package{}},
					},
				},
				{
					fullNameOverride: "root",
					dependencies: []*Package{
						{
							fullNameOverride: "middle",
							dependencies: []*Package{
								{fullNameOverride: "leaf", dependencies: []*Package{}},
							},
						},
					},
				},
			},
			validate: func(t *testing.T, sorted []*Package) {
				require.Equal(t, 3, len(sorted))
				// Root should be first (deepest), leaf should be last (shallowest)
				require.Equal(t, "root", sorted[0].FullName())
				require.Equal(t, "middle", sorted[1].FullName())
				require.Equal(t, "leaf", sorted[2].FullName())
			},
		},
		{
			name: "diamond dependency",
			packages: []*Package{
				{fullNameOverride: "base", dependencies: []*Package{}},
				{
					fullNameOverride: "left",
					dependencies: []*Package{
						{fullNameOverride: "base", dependencies: []*Package{}},
					},
				},
				{
					fullNameOverride: "right",
					dependencies: []*Package{
						{fullNameOverride: "base", dependencies: []*Package{}},
					},
				},
				{
					fullNameOverride: "top",
					dependencies: []*Package{
						{
							fullNameOverride: "left",
							dependencies: []*Package{
								{fullNameOverride: "base", dependencies: []*Package{}},
							},
						},
						{
							fullNameOverride: "right",
							dependencies: []*Package{
								{fullNameOverride: "base", dependencies: []*Package{}},
							},
						},
					},
				},
			},
			validate: func(t *testing.T, sorted []*Package) {
				require.Equal(t, 4, len(sorted))
				// Top should be first (depth 2), base should be last (depth 0)
				require.Equal(t, "top", sorted[0].FullName())
				require.Equal(t, "base", sorted[3].FullName())
				// Left and right have equal depth (1), so either order is fine
				middleNames := []string{sorted[1].FullName(), sorted[2].FullName()}
				require.Contains(t, middleNames, "left")
				require.Contains(t, middleNames, "right")
			},
		},
		{
			name: "multiple independent trees",
			packages: []*Package{
				{fullNameOverride: "tree1-leaf", dependencies: []*Package{}},
				{
					fullNameOverride: "tree1-root",
					dependencies: []*Package{
						{fullNameOverride: "tree1-leaf", dependencies: []*Package{}},
					},
				},
				{fullNameOverride: "tree2-leaf", dependencies: []*Package{}},
				{
					fullNameOverride: "tree2-root",
					dependencies: []*Package{
						{fullNameOverride: "tree2-leaf", dependencies: []*Package{}},
					},
				},
			},
			validate: func(t *testing.T, sorted []*Package) {
				require.Equal(t, 4, len(sorted))
				// Roots should be first (depth 1), leaves should be last (depth 0)
				rootNames := []string{sorted[0].FullName(), sorted[1].FullName()}
				require.Contains(t, rootNames, "tree1-root")
				require.Contains(t, rootNames, "tree2-root")

				leafNames := []string{sorted[2].FullName(), sorted[3].FullName()}
				require.Contains(t, leafNames, "tree1-leaf")
				require.Contains(t, leafNames, "tree2-leaf")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sorted := sortPackagesByDependencyDepth(tt.packages)
			tt.validate(t, sorted)
		})
	}
}

// TestCalculateDependencyDepth tests the depth calculation
func TestCalculateDependencyDepth(t *testing.T) {
	tests := []struct {
		name          string
		pkg           *Package
		expectedDepth int
	}{
		{
			name:          "leaf node",
			pkg:           &Package{fullNameOverride: "leaf", dependencies: []*Package{}},
			expectedDepth: 0,
		},
		{
			name: "one level deep",
			pkg: &Package{
				fullNameOverride: "parent",
				dependencies: []*Package{
					{fullNameOverride: "child", dependencies: []*Package{}},
				},
			},
			expectedDepth: 1,
		},
		{
			name: "two levels deep",
			pkg: &Package{
				fullNameOverride: "grandparent",
				dependencies: []*Package{
					{
						fullNameOverride: "parent",
						dependencies: []*Package{
							{fullNameOverride: "child", dependencies: []*Package{}},
						},
					},
				},
			},
			expectedDepth: 2,
		},
		{
			name: "multiple dependencies - max depth",
			pkg: &Package{
				fullNameOverride: "root",
				dependencies: []*Package{
					{fullNameOverride: "shallow", dependencies: []*Package{}},
					{
						fullNameOverride: "deep",
						dependencies: []*Package{
							{
								fullNameOverride: "deeper",
								dependencies: []*Package{
									{fullNameOverride: "deepest", dependencies: []*Package{}},
								},
							},
						},
					},
				},
			},
			expectedDepth: 3, // Max depth through deep->deeper->deepest
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache := make(map[string]int)
			depth := calculateDependencyDepth(tt.pkg, cache)
			require.Equal(t, tt.expectedDepth, depth)
		})
	}
}

// TestSortPackagesByDependencyDepth_Stability tests that sorting is stable
func TestSortPackagesByDependencyDepth_Stability(t *testing.T) {
	// Create packages with same depth - order should be preserved
	packages := []*Package{
		{fullNameOverride: "pkg1", dependencies: []*Package{}},
		{fullNameOverride: "pkg2", dependencies: []*Package{}},
		{fullNameOverride: "pkg3", dependencies: []*Package{}},
	}

	sorted := sortPackagesByDependencyDepth(packages)

	// All have depth 0, so order should be preserved
	require.Equal(t, "pkg1", sorted[0].FullName())
	require.Equal(t, "pkg2", sorted[1].FullName())
	require.Equal(t, "pkg3", sorted[2].FullName())
}

// TestSortPackagesByDependencyDepth_Performance tests with larger graphs
func TestSortPackagesByDependencyDepth_Performance(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping performance test in short mode")
	}

	// Create a chain of 100 packages
	packages := make([]*Package, 100)
	for i := 0; i < 100; i++ {
		pkg := &Package{
			fullNameOverride: "pkg" + string(rune(i)),
			dependencies:     []*Package{},
		}
		if i > 0 {
			pkg.dependencies = []*Package{packages[i-1]}
		}
		packages[i] = pkg
	}

	// Should complete quickly even with 100 packages
	sorted := sortPackagesByDependencyDepth(packages)
	require.Equal(t, 100, len(sorted))

	// Deepest package (pkg99) should be first
	require.Equal(t, "pkg"+string(rune(99)), sorted[0].FullName())
	// Shallowest (leaf, pkg0) should be last
	require.Equal(t, "pkg"+string(rune(0)), sorted[99].FullName())
}

// BenchmarkSortPackagesByDependencyDepth benchmarks the sorting algorithm
func BenchmarkSortPackagesByDependencyDepth(b *testing.B) {
	sizes := []int{10, 50, 100, 200}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("%d-packages", size), func(b *testing.B) {
			// Create a chain of packages (worst case for depth calculation)
			packages := make([]*Package, size)
			for i := 0; i < size; i++ {
				pkg := &Package{
					fullNameOverride: fmt.Sprintf("pkg%d", i),
					dependencies:     []*Package{},
				}
				if i > 0 {
					pkg.dependencies = []*Package{packages[i-1]}
				}
				packages[i] = pkg
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = sortPackagesByDependencyDepth(packages)
			}
		})
	}
}

// BenchmarkCalculateDependencyDepth benchmarks depth calculation
func BenchmarkCalculateDependencyDepth(b *testing.B) {
	depths := []int{5, 10, 20, 50}

	for _, depth := range depths {
		b.Run(fmt.Sprintf("depth-%d", depth), func(b *testing.B) {
			// Create a linear chain of given depth
			var pkg *Package
			for i := 0; i < depth; i++ {
				newPkg := &Package{
					fullNameOverride: fmt.Sprintf("pkg%d", i),
					dependencies:     []*Package{},
				}
				if pkg != nil {
					newPkg.dependencies = []*Package{pkg}
				}
				pkg = newPkg
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				cache := make(map[string]int)
				_ = calculateDependencyDepth(pkg, cache)
			}
		})
	}
}
