package leeway_test

import (
	// "path/filepath"

	"fmt"
	"testing"

	"github.com/gitpod-io/leeway/pkg/leeway"
	"github.com/gitpod-io/leeway/pkg/testutil"
)

// Used in multiple tests to verify how we deal with scripts having dependencies
var genericPackage = leeway.Package{
	PackageInternal: leeway.PackageInternal{
		Name:    "something",
		Type:    "generic",
		Sources: []string{"*.txt"},
	},
	Config: leeway.GenericPkgConfig{
		Commands: [][]string{{"echo"}},
		Test:     [][]string{{"echo", "testing"}},
	},
}

func TestScriptArgs(t *testing.T) {
	testutil.RunDUT()

	setup := &testutil.Setup{
		Components: []testutil.Component{
			{
				Location: "scripts",
				Packages: []leeway.Package{},
				Scripts: []leeway.Script{
					{
						Name:        "echo",
						Description: "echos an argument",
						Script:      `echo ${msg}`,
					},
				},
			},
		},
	}

	tests := []*testutil.CommandFixtureTest{
		// If the argument isn't passed then Leeway should fail with an exit code of 1
		{
			Name:              "unresolved arg",
			T:                 t,
			Args:              []string{"run", "scripts:echo"},
			NoNestedWorkspace: true,
			ExitCode:          1,
			Fixture:           setup,
		},
		// The argument should be passed to the script correctly - verified by checking stdout
		{
			Name:              "resovled args",
			T:                 t,
			Args:              []string{"run", "scripts:echo", "-Dmsg=foobar"},
			NoNestedWorkspace: true,
			ExitCode:          0,
			StdoutSubs:        []string{"foobar"},
			Fixture:           setup,
		},
	}

	for _, test := range tests {
		test.Run()
	}
}

func TestWorkingDirLayout(t *testing.T) {
	testutil.RunDUT()

	setup := &testutil.Setup{
		Components: []testutil.Component{
			{
				Location: "scripts",
				Packages: []leeway.Package{genericPackage},
				Scripts: []leeway.Script{
					{
						Name:          "pwd-origin",
						WorkdirLayout: "origin",
						Dependencies:  []string{fmt.Sprintf(":%s", genericPackage.Name)},
						Script:        `pwd && find .`,
					},
					{
						Name:          "pwd-packages",
						WorkdirLayout: "packages",
						Dependencies:  []string{fmt.Sprintf(":%s", genericPackage.Name)},
						Script:        `pwd && find .`,
					},
				},
			},
		},
	}

	tests := []*testutil.CommandFixtureTest{
		// Shows that even though it depends on a package, it isn't copied into the working directory
		{
			Name:              "origin",
			T:                 t,
			Args:              []string{"run", "scripts:pwd-origin"},
			ExitCode:          0,
			NoNestedWorkspace: true,
			Fixture:           setup,
			StdoutSubs: []string{`.
./BUILD.yaml`},
		},
		// Shows that the dependency is copied into the working directly, and that nothing else is present
		{
			Name:              "packages",
			T:                 t,
			Args:              []string{"run", "scripts:pwd-packages"},
			ExitCode:          0,
			NoNestedWorkspace: true,
			Fixture:           setup,
			StdoutSubs: []string{`.
./scripts--something`},
		},
	}

	for _, test := range tests {
		test.Run()
	}
}

func TestPATHEnvironment(t *testing.T) {
	testutil.RunDUT()

	setup := &testutil.Setup{
		Components: []testutil.Component{
			{
				Location: "scripts",
				Packages: []leeway.Package{genericPackage},
				Scripts: []leeway.Script{
					{
						Name:         "path",
						Description:  "prints the $PATH of the script execution context",
						Dependencies: []string{fmt.Sprintf(":%s", genericPackage.Name)},
						Script:       `echo $PATH`,
					},
				},
			},
		},
	}

	tests := []*testutil.CommandFixtureTest{
		// The PATH should contain the package that the script depends on
		{
			Name:              "resovled args",
			T:                 t,
			Args:              []string{"run", "scripts:path"},
			NoNestedWorkspace: true,
			ExitCode:          0,
			StdoutSubs:        []string{"scripts--something"},
			Fixture:           setup,
		},
	}

	for _, test := range tests {
		test.Run()
	}
}

func TestScriptParallel(t *testing.T) {
	testutil.RunDUT()

	setup := &testutil.Setup{
		Components: []testutil.Component{
			{
				Location: "scripts",
				Packages: []leeway.Package{},
				Scripts: []leeway.Script{
					{
						Name:        "script-a",
						Description: "Script A",
						Script:      `echo "Starting script A"`,
					},
					{
						Name:        "script-b",
						Description: "Script B",
						Script:      `echo "Starting script B"`,
					},
					{
						Name:        "exit-42",
						Description: "Exists with exit code 42",
						Script:      `echo "Exiting" && exit 42`,
					},
				},
			},
		},
	}

	tests := []*testutil.CommandFixtureTest{
		// When two or more scripts are passed, it should execute both.
		{
			Name:              "two successful invocations",
			T:                 t,
			Args:              []string{"run", "scripts:script-a", "scripts:script-b"},
			NoNestedWorkspace: true,
			ExitCode:          0,
			Fixture:           setup,
			StdoutSubs:        []string{"Starting script A", "Starting script B"},
		},
		// When one of the scripts fail, Leeway should still run the other scripts to completions
		// and it should fail with an exit code of 1
		//
		{
			Name:              "two successful invocations",
			T:                 t,
			Args:              []string{"run", "scripts:exit-42", "scripts:script-a"},
			NoNestedWorkspace: true,
			ExitCode:          1,
			Fixture:           setup,
			StdoutSubs:        []string{"Starting script A", "Exiting"},
		},
	}

	for _, test := range tests {
		test.Run()
	}
}
