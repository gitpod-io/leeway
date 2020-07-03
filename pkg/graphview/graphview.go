//go:generate bash -c "cd web && yarn install && yarn build"
//go:generate bash -c "go get github.com/GeertJohan/go.rice/rice && rice embed-go"

package graphview

import (
	"encoding/json"
	"net/http"
	"sort"

	rice "github.com/GeertJohan/go.rice"
	"github.com/typefox/leeway/pkg/leeway"
)

// Serve serves the dependency graph view for a package
func Serve(addr string, pkgs ...*leeway.Package) error {
	http.HandleFunc("/graph.json", serveDepGraphJSON(pkgs))
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

	Type   string `json:"type"`
	TypeID int    `json:"typeid"`
}

type link struct {
	Source int   `json:"source"`
	Target int   `json:"target"`
	Path   []int `json:"path"`
}

func serveDepGraphJSON(pkgs []*leeway.Package) http.HandlerFunc {
	var (
		nodes []node
		links []link
	)
	for _, p := range pkgs {
		n, l := computeDependencyGraph(p, len(nodes))
		nodes = append(nodes, n...)
		links = append(links, l...)
	}

	js, _ := json.Marshal(graph{Nodes: nodes, Links: links})
	return func(w http.ResponseWriter, r *http.Request) {
		w.Write(js)
	}
}

func computeDependencyGraph(pkg *leeway.Package, offset int) ([]node, []link) {
	var (
		tdeps   = append(pkg.GetTransitiveDependencies(), pkg)
		nodes   = make([]node, len(tdeps))
		nodeidx = make(map[string]int)
		typeidx = make(map[string]int)
		links   []link
		walk    func(pkg *leeway.Package, path []int)
	)

	for i, p := range tdeps {
		nodes[i] = node{Name: p.FullName(), Component: p.C.Name, Type: getPackageType(p)}
		nodeidx[nodes[i].Name] = offset + i
		typeidx[nodes[i].Type] = 0
	}
	types := make([]string, 0, len(typeidx))
	for k := range typeidx {
		types = append(types, k)
	}
	sort.Strings(types)
	for i, k := range types {
		typeidx[k] = i
	}
	for i, n := range nodes {
		n.TypeID = typeidx[n.Type]
		nodes[i] = n
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

	return nodes, links
}

func getPackageType(pkg *leeway.Package) (typen string) {
	switch c := pkg.Config.(type) {
	case leeway.DockerPkgConfig:
		typen = "docker"
	case leeway.GenericPkgConfig:
		typen = "generic"
	case leeway.GoPkgConfig:
		typen = "go-" + string(c.Packaging)
	case leeway.TypescriptPkgConfig:
		typen = "typescript-" + string(c.Packaging)
	}
	return typen
}
