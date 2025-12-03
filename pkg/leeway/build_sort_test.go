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
// A stable sort preserves the relative order of elements with equal keys
func TestSortPackagesByDependencyDepth_Stability(t *testing.T) {
	// Create a shared leaf dependency
	leaf := &Package{fullNameOverride: "leaf", dependencies: []*Package{}}

	// Create multiple packages at depth 1 (all depend on leaf)
	depth1Packages := []*Package{
		{fullNameOverride: "d1-alpha", dependencies: []*Package{leaf}},
		{fullNameOverride: "d1-beta", dependencies: []*Package{leaf}},
		{fullNameOverride: "d1-gamma", dependencies: []*Package{leaf}},
		{fullNameOverride: "d1-delta", dependencies: []*Package{leaf}},
	}

	// Create multiple packages at depth 0 (no dependencies)
	depth0Packages := []*Package{
		{fullNameOverride: "d0-alpha", dependencies: []*Package{}},
		{fullNameOverride: "d0-beta", dependencies: []*Package{}},
		{fullNameOverride: "d0-gamma", dependencies: []*Package{}},
	}

	// Test with different input orderings to verify stability
	// The key insight: within each depth group, relative order must be preserved
	testCases := []struct {
		name  string
		input []*Package
	}{
		{
			name: "depth1 first, then depth0",
			input: []*Package{
				depth1Packages[0], depth1Packages[1], depth1Packages[2], depth1Packages[3],
				depth0Packages[0], depth0Packages[1], depth0Packages[2],
			},
		},
		{
			name: "depth0 first, then depth1",
			input: []*Package{
				depth0Packages[0], depth0Packages[1], depth0Packages[2],
				depth1Packages[0], depth1Packages[1], depth1Packages[2], depth1Packages[3],
			},
		},
		{
			name: "interleaved",
			input: []*Package{
				depth1Packages[0], depth0Packages[0], depth1Packages[1], depth0Packages[1],
				depth1Packages[2], depth0Packages[2], depth1Packages[3],
			},
		},
		{
			name: "reverse interleaved",
			input: []*Package{
				depth0Packages[2], depth1Packages[3], depth0Packages[1], depth1Packages[2],
				depth0Packages[0], depth1Packages[1], depth1Packages[0],
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Record the input order of packages at each depth
			inputOrderDepth0 := []string{}
			inputOrderDepth1 := []string{}
			for _, pkg := range tc.input {
				if len(pkg.dependencies) == 0 {
					inputOrderDepth0 = append(inputOrderDepth0, pkg.FullName())
				} else {
					inputOrderDepth1 = append(inputOrderDepth1, pkg.FullName())
				}
			}

			sorted := sortPackagesByDependencyDepth(tc.input)

			// Extract the output order at each depth
			outputOrderDepth0 := []string{}
			outputOrderDepth1 := []string{}
			for _, pkg := range sorted {
				if len(pkg.dependencies) == 0 {
					outputOrderDepth0 = append(outputOrderDepth0, pkg.FullName())
				} else {
					outputOrderDepth1 = append(outputOrderDepth1, pkg.FullName())
				}
			}

			// Depth 1 packages should come before depth 0 packages
			require.Equal(t, 7, len(sorted), "should have all 7 packages")

			// First 4 should be depth 1, last 3 should be depth 0
			for i := 0; i < 4; i++ {
				require.Equal(t, 1, len(sorted[i].dependencies), "first 4 should be depth 1")
			}
			for i := 4; i < 7; i++ {
				require.Equal(t, 0, len(sorted[i].dependencies), "last 3 should be depth 0")
			}

			// Stability check: relative order within each depth group must match input order
			require.Equal(t, inputOrderDepth1, outputOrderDepth1,
				"depth 1 packages should maintain relative input order (stability)")
			require.Equal(t, inputOrderDepth0, outputOrderDepth0,
				"depth 0 packages should maintain relative input order (stability)")
		})
	}
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
