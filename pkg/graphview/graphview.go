//go:generate bash -c "cd web && yarn install && yarn build"
//go:generate bash -c "go get github.com/GeertJohan/go.rice/rice && rice embed-go"

package graphview

import (
	"encoding/json"
	"net/http"

	rice "github.com/GeertJohan/go.rice"
	"github.com/typefox/leeway/pkg/leeway"
)

// Serve serves the dependency graph view for a package
func Serve(pkg *leeway.Package, addr string) error {
	http.HandleFunc("/graph.json", serveDepGraphJSON(pkg))
	http.Handle("/", http.FileServer(rice.MustFindBox("web/dist").HTTPBox()))
	return http.ListenAndServe(addr, nil)
}

type graph struct {
	Nodes []node `json:"nodes"`
	Links []link `json:"links"`
}

type node struct {
	Name      string `json:"name"`
	Component string `json:"comp"`
	Group     int    `json:"group"`
}

type link struct {
	Source int `json:"source"`
	Target int `json:"target"`
}

func serveDepGraphJSON(pkg *leeway.Package) http.HandlerFunc {
	var (
		tdeps   = append(pkg.GetTransitiveDependencies(), pkg)
		nodes   = make([]node, len(tdeps))
		nodeidx = make(map[string]int)
		compidx = make(map[string]int)
		links   []link
	)
	for i, p := range tdeps {
		group, ok := compidx[p.C.Name]
		if !ok {
			group = len(compidx)
			compidx[p.C.Name] = group
		}

		nodes[i] = node{Name: p.FullName(), Component: p.C.Name, Group: group}
		nodeidx[p.FullName()] = i
	}
	for src, p := range tdeps {
		for _, dep := range p.GetDependencies() {
			links = append(links, link{
				Source: src,
				Target: nodeidx[dep.FullName()],
			})
		}
	}
	js, _ := json.Marshal(graph{Nodes: nodes, Links: links})

	return func(w http.ResponseWriter, r *http.Request) {
		w.Write(js)
	}
}
