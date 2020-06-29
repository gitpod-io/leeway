package leeway_test

import (
	// "path/filepath"
	"bytes"
	"flag"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/typefox/leeway/cmd"
)

var dut = flag.Bool("dut", false, "run command/device under test")

func TestScriptArgs(t *testing.T) {
	tests := []*CommandFixtureTest{
		{
			Name:     "unresolved arg",
			T:        t,
			Args:     []string{"run", "fixtures/scripts:echo"},
			ExitCode: 1,
		},
		{
			Name:     "resovled args",
			T:        t,
			Args:     []string{"run", "fixtures/scripts:echo", "-Dmsg=foobar"},
			ExitCode: 0,
		},
	}

	for _, test := range tests {
		test.Run()
	}
}

type CommandFixtureTest struct {
	Name      string
	T         *testing.T
	Args      []string
	ExitCode  int
	StdoutSub string
	StderrSub string
}

// Run executes the fixture test - do not forget to call this one
func (ft *CommandFixtureTest) Run() {
	if *dut {
		cmd.Execute()
		return
	}

	ft.T.Run(ft.Name, func(t *testing.T) {
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
		cmd.Dir = "../../"
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
		if stdout := sout.String(); !strings.Contains(stdout, ft.StdoutSub) {
			t.Errorf("stdout: expected to find \"%s\" in \"%s\"", ft.StdoutSub, stdout)
		}
		if stderr := sout.String(); !strings.Contains(stderr, ft.StderrSub) {
			t.Errorf("stderr: expected to find \"%s\" in \"%s\"", ft.StderrSub, stderr)
		}
	})
}
