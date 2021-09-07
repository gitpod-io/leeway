package cmd

import (
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/gitpod-io/leeway/pkg/prettyprint"
	"github.com/gitpod-io/leeway/pkg/vet"
)

// versionCmd represents the version command
var vetCmd = &cobra.Command{
	Use:   "vet [ls]",
	Short: "Validates the leeway workspace",
	RunE: func(cmd *cobra.Command, args []string) error {
		w := getWriterFromFlags(cmd)
		if len(args) > 0 && args[0] == "ls" {
			if w.FormatString == "" && w.Format == prettyprint.TemplateFormat {
				w.FormatString = `{{ range . -}}
{{ .Name }}{{"\t"}}{{ .Description }}
{{ end }}`
			}
			err := w.Write(vet.Checks())
			if err != nil {
				return err
			}
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

		findings, errs := vet.Run(ws, opts...)
		if ignoreWarnings, _ := cmd.Flags().GetBool("ignore-warnings"); ignoreWarnings {
			n := 0
			for _, x := range findings {
				if x.Error {
					findings[n] = x
					n++
				}
			}
			findings = findings[:n]
		}

		if len(errs) != 0 {
			for _, err := range errs {
				log.Error(err.Error())
			}
			return nil
		}

		if w.FormatString == "" && w.Format == prettyprint.TemplateFormat {
			w.FormatString = `{{ range . }}
{{"\033"}}[90m{{ if .Package -}}📦{{"\t"}}{{ .Package.FullName }}{{ else if .Component }}🗃️{{"\t"}}{{ .Component.Name }}{{ end }}
✔️ {{ .Check }}{{"\033"}}[0m
{{ if .Error -}}❌{{ else }}⚠️{{ end -}}{{"\t"}}{{ .Description }}
{{ end }}`
		}
		err = w.Write(findings)
		if err != nil {
			return err
		}

		if len(findings) == 0 {
			os.Exit(0)
		} else {
			os.Exit(128)
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(vetCmd)

	vetCmd.Flags().StringArray("checks", nil, "run these checks only")
	vetCmd.Flags().StringArray("packages", nil, "run checks on these packages only")
	vetCmd.Flags().StringArray("components", nil, "run checks on these components only")
	vetCmd.Flags().Bool("ignore-warnings", false, "ignores all warnings")
	addFormatFlags(vetCmd)
}
