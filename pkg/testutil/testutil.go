package testutil

import (
	"bytes"
	"errors"
	"flag"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gitpod-io/leeway/cmd"
	"github.com/gitpod-io/leeway/pkg/leeway"
	"gopkg.in/yaml.v3"
)

type Setup struct {
	Workspace  leeway.Workspace  `yaml:"workspace"`
	Components []Component       `yaml:"components"`
	Files      map[string]string `yaml:"files"`
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
	for fn, content := range s.Files {
		fn = filepath.Join(workspaceRoot, fn)
		err = os.MkdirAll(filepath.Dir(fn), 0755)
		if errors.Is(err, os.ErrExist) {
			err = nil
		}
		if err != nil {
			return
		}
		err = os.WriteFile(fn, []byte(content), 0644)
		if err != nil {
			return
		}
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

		for fn, content := range comp.Files {
			err = os.MkdirAll(filepath.Join(workspaceRoot, comp.Location, filepath.Dir(fn)), 0755)
			if errors.Is(err, os.ErrExist) {
				err = nil
			}
			if err != nil {
				return
			}
			err = os.WriteFile(filepath.Join(workspaceRoot, comp.Location, fn), []byte(content), 0644)
			if err != nil {
				return
			}
		}
	}

	return
}

var Dut = flag.Bool("dut", false, "run command/device under test")

func RunDUT() {
	if *Dut {
		cmd.Execute()
		os.Exit(0)
	}
}

type CommandFixtureTest struct {
	Name              string
	T                 *testing.T
	Args              []string
	ExitCode          int
	NoNestedWorkspace bool
	StdoutSubs        []string
	NoStdoutSub       string
	StderrSub         string
	NoStderrSub       string
	Eval              func(t *testing.T, stdout, stderr string)
	Fixture           *Setup
	FixturePath       string
}

// Run executes the fixture test - do not forget to call this one
func (ft *CommandFixtureTest) Run() {
	if *Dut {
		cmd.Execute()
		return
	}

	ft.T.Run(ft.Name, func(t *testing.T) {
		loc := "../../"

		if ft.FixturePath != "" && ft.Fixture != nil {
			t.Fatalf("Only one of FixturePath and Fixture must be set. You have set both.")
		}

		if ft.FixturePath != "" {
			fp, err := os.Open(ft.FixturePath)
			if err != nil {
				t.Fatalf("cannot load fixture from %s: %v", ft.FixturePath, err)
			}
			ft.Fixture, err = LoadFromYAML(fp)
			fp.Close()
			if err != nil {
				t.Fatalf("cannot load fixture from %s: %v", ft.FixturePath, err)
			}
		}
		if ft.Fixture != nil {
			var err error
			loc, err = ft.Fixture.Materialize()
			if err != nil {
				t.Fatalf("cannot materialize fixture: %v", err)
			}
			t.Logf("materialized fixture workspace: %s", loc)
			t.Cleanup(func() { os.RemoveAll(loc) })
		}

		env := os.Environ()
		n := 0
		for _, x := range env {
			if strings.HasPrefix(x, "LEEWAY_") {
				continue
			}
			env[n] = x
			n++
		}
		env = env[:n]

		self, err := os.Executable()
		if err != nil {
			t.Fatalf("cannot identify test binary: %q", err)
		}
		cmd := exec.Command(self, append([]string{"--dut"}, ft.Args...)...)
		var (
			sout = bytes.NewBuffer(nil)
			serr = bytes.NewBuffer(nil)
		)
		cmd.Stdout = sout
		cmd.Stderr = serr
		cmd.Dir = loc
		cmd.Env = env
		err = cmd.Run()

		var exitCode int
		if xerr, ok := err.(*exec.ExitError); ok {
			exitCode = xerr.ExitCode()
			err = nil
		}
		if err != nil {
			t.Fatalf("cannot re-run test binary: %q", err)
		}
		if exitCode != ft.ExitCode {
			t.Errorf("unepxected exit code: expected %d, actual %d (stderr: %s, stdout: %s)", ft.ExitCode, exitCode, serr.String(), sout.String())
		}
		var (
			stdout = sout.String()
			stderr = serr.String()
		)
		for _, stdoutStub := range ft.StdoutSubs {
			if !strings.Contains(stdout, stdoutStub) {
				t.Errorf("stdout: expected to find \"%s\" in \"%s\"", stdoutStub, stdout)
			}
		}
		if ft.NoStdoutSub != "" && strings.Contains(stdout, ft.NoStdoutSub) {
			t.Errorf("stdout: expected not to find \"%s\" in \"%s\"", ft.NoStdoutSub, stdout)
		}
		if !strings.Contains(stderr, ft.StderrSub) {
			t.Errorf("stderr: expected to find \"%s\" in \"%s\"", ft.StderrSub, stderr)
		}
		if ft.NoStderrSub != "" && strings.Contains(stderr, ft.NoStderrSub) {
			t.Errorf("stderr: expected not to find \"%s\" in \"%s\"", ft.NoStderrSub, stderr)
		}
		if ft.Eval != nil {
			ft.Eval(t, stdout, stderr)
		}
	})
}
