package testutil

import (
	"io"
	"os"
	"path/filepath"

	"github.com/gitpod-io/leeway/pkg/leeway"
	"gopkg.in/yaml.v3"
)

type Setup struct {
	Workspace  leeway.Workspace `yaml:"workspace"`
	Components []Component      `yaml:"components"`
}

type Component struct {
	Location string            `yaml:"location"`
	Files    map[string]string `yaml:"files"`
	Comp     leeway.Component  `yaml:"comp"`
	Packages []leeway.Package  `yaml:"packages"`
	Scripts  []leeway.Script   `yaml:"scripts"`
}

// LoadFromYAML loads a workspace setup from a YAML file
func LoadFromYAML(in io.Reader) (*Setup, error) {
	fc, err := io.ReadAll(in)
	if err != nil {
		return nil, err
	}

	var res Setup
	err = yaml.Unmarshal(fc, &res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

// Materialize produces a leeway workspace according to the setup spec
func (s Setup) Materialize() (workspaceRoot string, err error) {
	workspaceRoot, err = os.MkdirTemp("", "leeway-test-*")
	if err != nil {
		return
	}

	fc, err := yaml.Marshal(s.Workspace)
	if err != nil {
		return
	}
	err = os.WriteFile(filepath.Join(workspaceRoot, "WORKSPACE.yaml"), fc, 0644)
	if err != nil {
		return
	}

	for _, comp := range s.Components {
		err = os.MkdirAll(filepath.Join(workspaceRoot, comp.Location), 0755)
		if err != nil {
			return
		}

		cmp := struct {
			Constants leeway.Arguments `yaml:"const,omitempty"`
			Packages  []leeway.Package `yaml:"packages,omitempty"`
			Scripts   []leeway.Script  `yaml:"scripts,omitempty"`
		}{
			Constants: comp.Comp.Constants,
			Packages:  comp.Packages,
			Scripts:   comp.Scripts,
		}

		fc, err = yaml.Marshal(cmp)
		if err != nil {
			return
		}

		err = os.WriteFile(filepath.Join(workspaceRoot, comp.Location, "BUILD.yaml"), fc, 0644)
		if err != nil {
			return
		}
	}

	return
}
