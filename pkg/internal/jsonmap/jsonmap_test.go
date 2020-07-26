package jsonmap_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/typefox/leeway/pkg/internal/jsonmap"
)

func TestRemarshalJSON(t *testing.T) {
	tests := []string{
		"{}\n",
		`{"hello":"world"}` + "\n",
		`{"hello":"foo","bar":"baz"}` + "\n",
		`{"hi":"a & b"}` + "\n",
		`{"hi":"a & b","abc":[1,2,3,4],"deps":{"a":1}}` + "\n",
		`{"hi":"a & b","abc":[1,2,3,4],"deps":{"a":1,"b":"c && d"}}` + "\n",
		`{"hi":"a & b","deps":{"a":1},"devdeps":{"a":1}}` + "\n",
	}

	for i, test := range tests {
		t.Run(fmt.Sprintf("%03d", i), func(t *testing.T) {
			var om jsonmap.OrderedMap
			err := json.Unmarshal([]byte(test), &om)
			if err != nil {
				t.Fatalf("unexpected error: %q", err)
			}

			res, err := jsonmap.MarshalJSON(&om, "", false)
			if err != nil {
				t.Fatalf("unexpected error: %q", err)
			}

			if !bytes.EqualFold([]byte(test), res) {
				t.Errorf("unexpected result: expected %q, got %q", test, string(res))
			}
		})
	}
}
