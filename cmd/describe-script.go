package cmd

import (
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/gitpod-io/leeway/pkg/prettyprint"
)

// describeScriptCmd represents the describeTree command
var describeScriptCmd = &cobra.Command{
	Use:   "script",
	Short: "Describes a script",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		_, _, script, exists := getTarget(args, true)
		if !exists || script == nil {
			log.Fatal("needs a script")
		}

		w := getWriterFromFlags(cmd)
		if w.Format == prettyprint.TemplateFormat && w.FormatString == "" {
			w.FormatString = `Name:{{"\t"}}{{ .FullName }}
{{ if .Description }}Description:{{"\t"}}{{ .Description }}{{ end }}
Type:{{"\t"}}{{ .Type }}
Workdir Layout:{{"\t"}}{{ .WorkdirLayout }}
{{ if .Dependencies -}}
Dependencies:
{{- range $k, $v := .Dependencies }}
{{"\t"}}{{ $v.FullName -}}{{"\t"}}{{ $v.Version -}}
{{ end -}}
{{ end }}
`
		}

		desc := newScriptDescription(script)
		err := w.Write(desc)
		if err != nil {
			log.Fatal(err)
		}
	},
}

func init() {
	describeCmd.AddCommand(describeScriptCmd)
	addFormatFlags(describeScriptCmd)
}
