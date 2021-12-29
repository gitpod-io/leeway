package provutil

import (
	"encoding/json"
	"io"

	"sigs.k8s.io/bom/pkg/provenance"
)

// DecodeBundle returns a function which attempts to decode an attestation bundle from the reader
// and calls the handler for every envelope found in the bundle. If decoding fails, or the handler
// returns an error, decoding stops and the error is returned.
func DecodeBundle(bundle io.Reader, handler func(env *provenance.Envelope) error) error {
	var env provenance.Envelope
	dec := json.NewDecoder(bundle)
	for dec.More() {
		err := dec.Decode(&env)
		if err != nil {
			return err
		}

		err = handler(&env)
		if err != nil {
			return err
		}
	}
	return nil
}
