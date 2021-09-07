package cmd

import (
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/gitpod-io/leeway/pkg/prettyprint"
)

// describeConstCmd represents the describeTree command
var describeConstCmd = &cobra.Command{
	Use:   "const",
	Short: "Prints the value of a component constant",
	Run: func(cmd *cobra.Command, args []string) {
		comp, pkg, _, exists := getTarget(args, false)
		if !exists {
			log.Fatal("const needs a component")
		}
		if comp == nil && pkg != nil {
			comp = pkg.C
		}

		type constDesc struct {
			Name  string `json:"name" yaml:"name"`
			Value string `json:"value" yaml:"value"`
		}

		w := getWriterFromFlags(cmd)
		if w.Format == prettyprint.TemplateFormat && w.FormatString == "" {
			w.FormatString = `{{ range . }}{{ .Name }}:{{"\t"}}{{ .Value }}{{"\n"}}{{ end }}`
		}

		desc := make([]constDesc, 0, len(comp.Constants))
		for k, v := range comp.Constants {
			desc = append(desc, constDesc{Name: k, Value: v})
		}
		//nolint:errcheck
		w.Write(desc)
	},
}

func init() {
	describeCmd.AddCommand(describeConstCmd)
	addFormatFlags(describeConstCmd)
}
