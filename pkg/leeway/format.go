package leeway

import (
	"io"
	"sort"

	"gopkg.in/yaml.v3"
)

// FormatBUILDyaml formats a component's build.yaml file
func FormatBUILDyaml(out io.Writer, in io.Reader, fixIssues bool) error {
	var n yaml.Node
	err := yaml.NewDecoder(in).Decode(&n)
	if err != nil {
		return err
	}

	sortPackageDeps(&n)
	// if fixIssues {
	// 		right now we have no automatic issue fixes - if this changes, add them here
	// }

	enc := yaml.NewEncoder(out)
	enc.SetIndent(2)
	return enc.Encode(&n)
}

func sortPackageDeps(n *yaml.Node) {
	if n == nil || len(n.Content) < 1 {
		return
	}

	// Get the root mapping node
	root := n.Content[0]
	if root.Kind != yaml.MappingNode {
		return
	}

	// Find the packages section
	for i := 0; i < len(root.Content); i += 2 {
		if root.Content[i].Value != "packages" {
			continue
		}

		// Get the packages mapping
		packagesNode := root.Content[i+1]
		if packagesNode.Kind != yaml.MappingNode {
			return
		}

		// Iterate through each package
		for j := 0; j < len(packagesNode.Content); j += 2 {
			pkg := packagesNode.Content[j+1]
			if pkg.Kind != yaml.MappingNode {
				continue
			}

			// Find deps in the package
			for k := 0; k < len(pkg.Content); k += 2 {
				if pkg.Content[k].Value != "deps" {
					continue
				}

				// Get the deps sequence
				depsNode := pkg.Content[k+1]
				if depsNode.Kind != yaml.SequenceNode {
					continue
				}

				// Sort the dependencies
				sort.Slice(depsNode.Content, func(i, j int) bool {
					return depsNode.Content[i].Value < depsNode.Content[j].Value
				})
			}
		}
		break
	}
}
