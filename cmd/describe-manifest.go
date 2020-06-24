package cmd

import (
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// describeManifestCmd represents the describeManifest command
var describeManifestCmd = &cobra.Command{
	Use:   "manifest",
	Short: "Prints the version manifest (input for the version hash) of a package",
	Run: func(cmd *cobra.Command, args []string) {
		_, pkg, _, _ := getTarget(args, false)
		if pkg == nil {
			log.Fatal("manifest needs a package")
		}

		err := pkg.WriteVersionManifest(os.Stdout)
		if err != nil {
			log.Fatal(err)
		}
	},
}

func init() {
	describeCmd.AddCommand(describeManifestCmd)
}
