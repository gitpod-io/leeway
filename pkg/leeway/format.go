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
	if len(n.Content) < 1 {
		return
	}

	nde := n.Content[0]
	for rootIdx, rootNde := range nde.Content {
		if rootNde.Value != "packages" || rootIdx == len(nde.Content)-1 {
			continue
		}

		nde := nde.Content[rootIdx+1]
		if len(nde.Content) < 1 {
			return
		}
		nde = nde.Content[0]

		for pkgIdx, pkgNde := range nde.Content {
			if pkgNde.Value != "deps" || pkgIdx == len(nde.Content)-1 {
				continue
			}

			nde := nde.Content[pkgIdx+1]
			sort.Slice(nde.Content, func(i, j int) bool { return nde.Content[i].Value < nde.Content[j].Value })
		}
	}
}
