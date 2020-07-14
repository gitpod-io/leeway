package cmd

import (
	"github.com/typefox/leeway/pkg/prettyprint"
	"github.com/typefox/leeway/pkg/vet"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// versionCmd represents the version command
var vetCmd = &cobra.Command{
	Use:   "vet [ls]",
	Short: "Validates the leeway workspace",
	RunE: func(cmd *cobra.Command, args []string) error {
		w := getWriterFromFlags(cmd)
		if len(args) > 0 && args[0] == "ls" {
			if w.FormatString == "" && w.Format == prettyprint.TemplateFormat {
				w.FormatString = `{{ range . }}
{{ .Name }}{{"\t"}}{{ .Description }}
{{ end }}`
			}
			w.Write(vet.Checks())
		}

		ws, err := getWorkspace()
		if err != nil {
			return err
		}

		var opts []vet.RunOpt
		if checks, _ := cmd.Flags().GetStringArray("checks"); len(checks) > 0 {
			opts = append(opts, vet.WithChecks(checks))
		}
		if pkgs, _ := cmd.Flags().GetStringArray("packages"); len(pkgs) > 0 {
			idx := make(vet.StringSet)
			for _, p := range pkgs {
				idx[p] = struct{}{}
			}
			opts = append(opts, vet.OnPackages(idx))
		}
		if comps, _ := cmd.Flags().GetStringArray("components"); len(comps) > 0 {
			idx := make(vet.StringSet)
			for _, p := range comps {
				idx[p] = struct{}{}
			}
			opts = append(opts, vet.OnComponents(idx))
		}

		findings, errs := vet.Run(ws)
		if len(errs) != 0 {
			log.Error(err.Error())
			return nil
		}

		if w.FormatString == "" && w.Format == prettyprint.TemplateFormat {
			w.FormatString = `{{ range . -}}
{{ if .Component -}}
on "{{ .Component.Name }}"
{{ end }}
{{ if .Package -}}
on "{{ .Package.FullName }}"
{{ end }}
	{{ .Description }}
{{ end }}`
		}
		return w.Write(findings)
	},
}

func init() {
	rootCmd.AddCommand(vetCmd)

	vetCmd.Flags().StringArray("checks", nil, "run these checks only")
	vetCmd.Flags().StringArray("packages", nil, "run checks on these packages only")
	vetCmd.Flags().StringArray("components", nil, "run checks on these components only")
	addFormatFlags(vetCmd)
}
