package earthly

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/gitpod-io/leeway/pkg/leeway"
)

type Generator struct {
	DefaultImage string
}

func Write(dst string, files map[string]string) error {
	for fn, cntnt := range files {
		fn = filepath.Join(dst, fn)
		err := os.WriteFile(fn, []byte(cntnt), 0644)
		if err != nil {
			return fmt.Errorf("error writing %s: %w", fn, err)
		}
	}
	return nil
}

func (g *Generator) Workspace(ws *leeway.Workspace) (map[string]string, error) {
	res := make(map[string]string, len(ws.Components))

	for _, comp := range ws.Components {
		ce, err := g.Component(comp)
		if err != nil {
			return nil, err
		}

		res[filepath.Join(strings.TrimPrefix(comp.Origin, ws.Origin), "Earthfile")] = ce
	}

	return res, nil
}

func (g *Generator) Component(comp *leeway.Component) (string, error) {
	var res []string

	res = append(res, "VERSION 0.6")
	res = append(res, "FROM "+g.DefaultImage)
	res = append(res, "WORKDIR /work")

	for _, pkg := range comp.Packages {
		res = append(res, "\n"+pkg.Name+":")

		for _, dep := range pkg.GetDependencies() {
			depn, err := filepath.Rel(pkg.C.Name, dep.C.Name)
			if err != nil {
				return "", err
			}
			if strings.HasPrefix(depn, "/") {
				depn = "." + depn
			}
			depn += "+" + dep.Name

			res = append(res, "\tFROM "+depn)
		}
		if len(pkg.Sources) > 0 {
			srcs := make([]string, len(pkg.Sources))
			for i := range pkg.Sources {
				srcs[i] = strings.TrimPrefix(pkg.Sources[i], comp.Origin)
				srcs[i] = strings.TrimPrefix(srcs[i], "/")
			}

			res = append(res, "\tCOPY "+strings.Join(srcs, " ")+" .")
		}

		switch pkg.Type {
		case leeway.GoPackage:
			res = append(res, "\tRUN go mod download")
			res = append(res, "\tRUN go build")
		}
	}

	return strings.Join(res, "\n"), nil
}
