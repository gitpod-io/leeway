package provutil

import (
	"encoding/json"
	"io"

	"github.com/gitpod-io/leeway/pkg/leeway"
	"sigs.k8s.io/bom/pkg/provenance"
)

// AccessPkgAttestationBundle provides access to the attestation bundle entries from a cached build artifact.
// pkgFN is expected to point to a cached tar file.
func AccessPkgAttestationBundle(pkgFN string, handler func(env *provenance.Envelope) error) error {
	return leeway.AccessAttestationBundleInCachedArchive(pkgFN, func(bundle io.Reader) error {
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
	})
}
