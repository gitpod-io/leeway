package vet

import (
	"bytes"
	"os"
	"path/filepath"

	"github.com/gitpod-io/leeway/pkg/leeway"
)

func init() {
	register(ComponentCheck("fmt", "ensures the BUILD.yaml of a component is leeway fmt'ed", checkComponentsFmt))
}

func checkComponentsFmt(comp *leeway.Component) ([]Finding, error) {
	fc, err := os.ReadFile(filepath.Join(comp.Origin, "BUILD.yaml"))
	if err != nil {
		return nil, err
	}
	if len(fc) == 0 {
		// empty BUILD.yaml files are ok
		return nil, nil
	}

	buf := bytes.NewBuffer(nil)
	err = leeway.FormatBUILDyaml(buf, bytes.NewReader(fc), false)
	if err != nil {
		return nil, err
	}

	if bytes.EqualFold(buf.Bytes(), fc) {
		return nil, nil
	}

	return []Finding{
		{
			Component:   comp,
			Description: "component's BUILD.yaml is not formated using `leeway fmt`",
			Error:       false,
		},
	}, nil
}
