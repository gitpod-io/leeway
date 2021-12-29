package cmd

import (
	"encoding/base64"
	"encoding/json"

	"github.com/gitpod-io/leeway/pkg/provutil"
	"github.com/in-toto/in-toto-golang/in_toto"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"sigs.k8s.io/bom/pkg/provenance"
)

// provenanceExportCmd represents the provenance assert command
var provenanceAssertCmd = &cobra.Command{
	Use:   "assert <package>",
	Short: "Makes assertions about the provenance of a package",
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

		var assertions provutil.Assertions
		if signed, _ := cmd.Flags().GetBool("signed"); signed {
			var key in_toto.Key
			err := key.LoadKeyDefaults(pkg.C.W.Provenance.KeyPath)
			if err != nil {
				log.WithError(err).Fatal("cannot load key from " + pkg.C.W.Provenance.KeyPath)
			}
			assertions = append(assertions, provutil.AssertSignedWith(key))
		}
		if do, _ := cmd.Flags().GetBool("leeway-built"); do {
			assertions = append(assertions, provutil.AssertBuiltWithLeeway)
		}
		if ver, _ := cmd.Flags().GetString("leeway-version"); ver != "" {
			assertions = append(assertions, provutil.AssertBuiltWithLeewayVersion(ver))
		}
		if do, _ := cmd.Flags().GetBool("git-only"); do {
			assertions = append(assertions, provutil.AssertGitMaterialOnly)
		}

		var failures []provutil.Violation
		stmt := provenance.NewSLSAStatement()
		err := provutil.AccessPkgAttestationBundle(pkgFN, func(env *provenance.Envelope) error {
			if env.PayloadType != in_toto.PayloadType {
				log.Warnf("only supporting %s payloads, not %s - skipping", in_toto.PayloadType, env.PayloadType)
				return nil
			}

			failures = append(assertions.AssertEnvelope(env), failures...)

			raw, err := base64.StdEncoding.DecodeString(env.Payload)
			if err != nil {
				return err
			}
			err = json.Unmarshal(raw, &stmt)
			if err != nil {
				return err
			}

			failures = append(assertions.AssertStatement(stmt), failures...)

			return nil
		})
		if err != nil {
			log.WithError(err).Fatal("cannot assert attestation bundle")
		}

		if len(failures) != 0 {
			for _, f := range failures {
				log.Error(f.String())
			}
			log.Fatal("failed")
		}
	},
}

func init() {
	provenanceAssertCmd.Flags().Bool("signed", false, "ensure that all entries in the attestation bundle are signed and valid under the given key")
	provenanceAssertCmd.Flags().Bool("built-with-leeway", false, "ensure that all entries in the attestation bundle are built by leeway")
	provenanceAssertCmd.Flags().String("built-with-leeway-version", "", "ensure that all entries in the attestation bundle are built by a specific leeway version")
	provenanceAssertCmd.Flags().Bool("git-only", false, "ensure that all entries in the attestation bundle are built directly from Git (i.e. only have git material entries)")

	addBuildFlags(provenanceAssertCmd)
	provenanceCmd.AddCommand(provenanceAssertCmd)
}
