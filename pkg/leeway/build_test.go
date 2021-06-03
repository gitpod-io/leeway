package leeway

import (
	"testing"
)

func TestCodecovComponentName(t *testing.T) {
	tests := []struct {
		Test     string
		Package  string
		Expected string
	}{
		{"valid package format", "components/ee/ws-scheduler", "components-ee-ws-scheduler-coverage.out"},
		{"lower case", "COMPONENTS/gitpod-cli:app", "components-gitpod-cli-app-coverage.out"},
		{"special character", "components/~ü:app", "components-app-coverage.out"},
		{"with numbers", "components/1icens0r:app", "components-1icens0r-app-coverage.out"},
	}

	for _, test := range tests {
		name := codecovComponentName(test.Package)
		if name != test.Expected {
			t.Errorf("%s: expected: %v, actual: %v", test.Test, test.Expected, name)
		}
	}
}
