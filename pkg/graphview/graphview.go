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
	Source int   `json:"source"`
	Target int   `json:"target"`
	Path   []int `json:"path"`
}

func serveDepGraphJSON(pkg *leeway.Package) http.HandlerFunc {
	var (
		tdeps   = append(pkg.GetTransitiveDependencies(), pkg)
		nodes   = make([]node, len(tdeps))
		nodeidx = make(map[string]int)
		compidx = make(map[string]int)
		links   []link
		walk    func(pkg *leeway.Package, path []int)
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

	walk = func(p *leeway.Package, path []int) {
		src := nodeidx[p.FullName()]
		for _, dep := range p.GetDependencies() {
			links = append(links, link{
				Source: src,
				Target: nodeidx[dep.FullName()],
				Path:   append(path, src),
			})
			walk(dep, append(path, src))
		}
	}
	walk(pkg, nil)

	js, _ := json.Marshal(graph{Nodes: nodes, Links: links})

	return func(w http.ResponseWriter, r *http.Request) {
		w.Write(js)
	}
}
