package cmd

import (
	"encoding/base64"
	"encoding/json"
	"os"

	"github.com/gitpod-io/leeway/pkg/provutil"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"sigs.k8s.io/bom/pkg/provenance"
)

// provenanceExportCmd represents the provenance export command
var provenanceExportCmd = &cobra.Command{
	Use:   "export <package>",
	Short: "Exports the provenance bundle of a (previously built) package",
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		_, pkg, _, _ := getTarget(args, false)
		if pkg == nil {
			log.Fatal("provenance export requires a package")
		}

		_, cache := getBuildOpts(cmd)
		pkgFN, ok := cache.Location(pkg)
		if !ok {
			log.Fatalf("%s is not built", pkg.FullName())
		}

		decode, _ := cmd.Flags().GetBool("decode")
		out := json.NewEncoder(os.Stdout)
		err := provutil.AccessPkgAttestationBundle(pkgFN, func(env *provenance.Envelope) error {
			if !decode {
				return out.Encode(env)
			}

			dec, err := base64.StdEncoding.DecodeString(env.Payload)
			if err != nil {
				return err
			}

			// we make a Marshal(Unmarshal(...)) detour here to ensure we're still outputing
			// newline delimited JSON. We have no idea how the payload actually looks like, just
			// that it's valid JSON.
			var decc map[string]interface{}
			err = json.Unmarshal(dec, &decc)
			if err != nil {
				return err
			}
			err = out.Encode(decc)
			if err != nil {
				return err
			}

			return nil
		})
		if err != nil {
			log.WithError(err).Fatal("cannot extract attestation bundle")
		}
	},
}

func init() {
	provenanceExportCmd.Flags().Bool("decode", false, "decode the base64 payload of the envelopes")

	provenanceCmd.AddCommand(provenanceExportCmd)
	addBuildFlags(provenanceExportCmd)
}
