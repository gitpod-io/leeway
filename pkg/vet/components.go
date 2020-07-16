package vet

import (
	"bytes"
	"io/ioutil"
	"path/filepath"

	"github.com/typefox/leeway/pkg/leeway"
)

func init() {
	register(Check{
		Name:        "components:fmt",
		Description: "ensures the BUILD.yaml of a component is leeway fmt'ed",
		RunCmp:      checkComponentsFmt,
	})
}

func checkComponentsFmt(comp *leeway.Component) ([]Finding, error) {
	fc, err := ioutil.ReadFile(filepath.Join(comp.Origin, "BUILD.yaml"))
	if err != nil {
		return nil, err
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
