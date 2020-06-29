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
