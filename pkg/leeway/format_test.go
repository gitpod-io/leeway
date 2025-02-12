package leeway

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestSortPackageDeps(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "empty yaml",
			input:    "",
			expected: "",
		},
		{
			name: "no packages",
			input: `
other:
  field: value`,
			expected: `
other:
  field: value`,
		},
		{
			name: "packages without deps",
			input: `
packages:
  some-package:
    name: test
    type: go`,
			expected: `
packages:
  some-package:
    name: test
    type: go`,
		},
		{
			name: "packages with unsorted deps",
			input: `
packages:
  some-package:
    name: test
    type: go
    deps:
      - :package-c
      - :package-a
      - :package-b`,
			expected: `
packages:
  some-package:
    name: test
    type: go
    deps:
      - :package-a
      - :package-b
      - :package-c`,
		},
		{
			name: "multiple packages with deps",
			input: `
packages:
  package1:
    deps:
      - :c
      - :a
      - :b
  package2:
    deps:
      - :z
      - :x
      - :y`,
			expected: `
packages:
  package1:
    deps:
      - :a
      - :b
      - :c
  package2:
    deps:
      - :x
      - :y
      - :z`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Parse input YAML
			var inputNode yaml.Node
			err := yaml.Unmarshal([]byte(tc.input), &inputNode)
			if tc.input != "" && err != nil {
				t.Fatalf("failed to unmarshal input YAML: %v", err)
			}

			// Sort dependencies
			sortPackageDeps(&inputNode)

			// Marshal back to string
			var output strings.Builder
			enc := yaml.NewEncoder(&output)
			enc.SetIndent(2)
			if tc.input != "" {
				if err := enc.Encode(&inputNode); err != nil {
					t.Fatalf("failed to marshal output YAML: %v", err)
				}
			}

			// Compare with expected
			expectedStr := strings.TrimSpace(tc.expected)
			actualStr := strings.TrimSpace(output.String())
			if expectedStr != actualStr {
				t.Errorf("\nexpected:\n%s\n\nactual:\n%s", expectedStr, actualStr)
			}
		})
	}
}
