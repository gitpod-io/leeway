package leeway

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestParseGoCoverOutput(t *testing.T) {
	type Expectation struct {
		Error            string
		Coverage         int
		FuncsWithoutTest int
		FuncsWithTest    int
	}
	tests := []struct {
		Name        string
		Input       string
		Expectation Expectation
	}{
		{
			Name: "empty",
		},
		{
			Name: "valid",
			Input: `github.com/gitpod-io/leeway/store.go:165:                    Get                             100.0%
			github.com/gitpod-io/leeway/store.go:173:                    Set                             100.0%
			github.com/gitpod-io/leeway/store.go:178:                    Delete                          100.0%
			github.com/gitpod-io/leeway/store.go:183:                    Scan                            80.0%
			github.com/gitpod-io/leeway/store.go:194:                    Close                           0.0%
			github.com/gitpod-io/leeway/store.go:206:                    Upsert                          0.0%`,
			Expectation: Expectation{
				Coverage:         63,
				FuncsWithoutTest: 2,
				FuncsWithTest:    4,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			var act Expectation

			var err error
			act.Coverage, act.FuncsWithoutTest, act.FuncsWithTest, err = parseGoCoverOutput(test.Input)
			if err != nil {
				act.Error = err.Error()
			}

			if diff := cmp.Diff(test.Expectation, act); diff != "" {
				t.Errorf("parseGoCoverOutput() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
