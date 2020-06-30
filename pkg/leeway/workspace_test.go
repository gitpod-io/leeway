package leeway_test

import "testing"

func TestFixLoadWorkspace(t *testing.T) {
	tests := []*CommandFixtureTest{
		{
			Name:              "single workspace packages",
			T:                 t,
			Args:              []string{"collect", "-w", "fixtures/nested-ws/wsa"},
			NoNestedWorkspace: true,
			ExitCode:          0,
			StdoutSub:         "pkg1:app",
		},
		{
			Name:              "single workspace components",
			T:                 t,
			Args:              []string{"collect", "-w", "fixtures/nested-ws/wsa", "components"},
			NoNestedWorkspace: true,
			ExitCode:          0,
			StdoutSub:         "pkg1\n//",
		},
		{
			Name:              "ignore nested workspaces",
			T:                 t,
			Args:              []string{"collect", "-w", "fixtures/nested-ws", "components"},
			NoNestedWorkspace: true,
			ExitCode:          1,
			StderrSub:         "pkg0:app: package \\\"wsa/pkg1:app\\\" is unkown",
		},
		{
			Name:      "nested workspace packages",
			T:         t,
			Args:      []string{"collect", "-w", "fixtures/nested-ws"},
			StdoutSub: "pkg0:app",
			ExitCode:  0,
		},
		{
			Name:      "nested workspace components",
			T:         t,
			Args:      []string{"collect", "components", "-w", "fixtures/nested-ws"},
			StdoutSub: "pkg0",
			ExitCode:  0,
		},
	}

	for _, test := range tests {
		test.Run()
	}
}
