package cmd

import (
	"fmt"
	"os"
	"sort"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/typefox/leeway/pkg/leeway"
	"github.com/typefox/leeway/pkg/prettyprint"
	"gopkg.in/yaml.v2"
)

// describeCmd represents the describe command
var describeCmd = &cobra.Command{
	Use:   "describe <component|package>",
	Short: "Describes a single component or package",
	Args:  cobra.MaximumNArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 2 {
			cmdname := args[0]
			var subcmd *cobra.Command
			for _, c := range cmd.Commands() {
				if c.Name() == cmdname {
					cmd = c
					break
				}
			}

			if subcmd == nil {
				log.Fatalf("unknown command %s", cmdname)
			}

			subcmd.SetArgs(args[1:])
			err := subcmd.Execute()
			if err != nil {
				log.Fatal(err)
			}
			return
		}

		comp, pkg, exists := getTarget(args)
		if !exists {
			return
		}

		format, _ := cmd.Flags().GetString("format")
		formatString, _ := cmd.Flags().GetString("formatString")
		w := &prettyprint.Writer{
			Out:          os.Stdout,
			Format:       prettyprint.Format(format),
			FormatString: formatString,
		}
		if pkg != nil {
			describePackage(w, pkg)
			return
		}

		describeComponent(w, comp)
	},
}

func getTarget(args []string) (comp leeway.Component, pkg *leeway.Package, exists bool) {
	workspace, err := getWorkspace()
	if err != nil {
		log.Fatal(err)
	}
	log.WithField("origin", workspace.Origin).Debug("found workspace")

	var target string
	if len(args) == 0 {
		target = workspace.DefaultTarget
	} else {
		target = args[0]
	}
	if target == "" {
		log.Fatal("no target")
		return
	}

	if strings.HasPrefix(target, ".:") {
		wd, err := os.Getwd()
		if err != nil {
			log.Fatal(err)
		}

		// This uses seperate trims and is not part of origin to support BUILD files in the workspace root.
		// In that case there's no "/" left over at the origin.
		cn := strings.TrimPrefix(wd, workspace.Origin)
		cn = strings.TrimPrefix(cn, "/")

		pn := strings.TrimPrefix(target, ".:")

		target = fmt.Sprintf("%s:%s", cn, pn)
	} else if target == "." {
		wd, err := os.Getwd()
		if err != nil {
			log.Fatal(err)
		}

		// This uses seperate trims and is not part of origin to support BUILD files in the workspace root.
		// In that case there's no "/" left over at the origin.
		cn := strings.TrimPrefix(wd, workspace.Origin)
		cn = strings.TrimPrefix(cn, "/")
		target = cn
	}

	if isPkg := strings.Contains(target, ":"); isPkg {
		pkg, exists = workspace.Packages[target]
		if !exists {
			log.Fatalf("package \"%s\" does not exist", target)
			return
		}
	} else {
		comp, exists = workspace.Components[target]
		if !exists {
			log.Fatalf("component \"%s\" does not exist", target)
			return
		}
	}

	return
}

type packageMetadataDescription struct {
	Name      string `json:"name" yaml:"name"`
	FullName  string `json:"fullName" yaml:"fullName"`
	Version   string `json:"version" yaml:"version"`
	Emphemral bool   `json:"ephemeral" yaml:"ephemeral"`
}

func newMetadataDescription(pkg *leeway.Package) packageMetadataDescription {
	version, err := pkg.Version()
	if err != nil {
		log.Fatal(err)
	}

	return packageMetadataDescription{
		Name:      pkg.Name,
		FullName:  pkg.FullName(),
		Version:   version,
		Emphemral: pkg.Ephemeral,
	}
}

type packageDescription struct {
	Metadata     packageMetadataDescription   `json:"metadata" yaml:"metadata"`
	Type         string                       `json:"type" yaml:"type"`
	Manifest     map[string]string            `json:"manifest" yaml:"manifest"`
	ArgDeps      []string                     `json:"argdeps,omitempty" yaml:"argdeps,omitempty"`
	Dependencies []packageMetadataDescription `json:"dependencies,omitempty" yaml:"dependencies,omitempty"`
	Config       configDescription            `json:"config,omitempty" yaml:"config,omitempty"`
	Env          []string                     `json:"env,omitempty" yaml:"env,omitempty"`
}

type configDescription map[string]interface{}

func describePackage(out *prettyprint.Writer, pkg *leeway.Package) {
	mf, err := pkg.ContentManifest()
	if err != nil {
		log.Fatal(err)
	}
	manifest := make(map[string]string, len(mf))
	for _, m := range mf {
		segs := strings.Split(m, ":")
		manifest[segs[0]] = segs[1]
	}

	deps := make([]packageMetadataDescription, len(pkg.Dependencies))
	for i, dep := range pkg.GetDependencies() {
		deps[i] = newMetadataDescription(dep)
	}
	sort.Slice(deps, func(i, j int) bool { return deps[i].FullName < deps[j].FullName })

	cfg := make(map[string]interface{})
	switch pkg.Type {
	case leeway.DockerPackage:
		c := pkg.Config.(leeway.DockerPkgConfig)
		cfg["buildArgs"] = c.BuildArgs
		cfg["dockerfile"] = c.Dockerfile
		cfg["image"] = c.Image
		cfg["squash"] = c.Squash
	case leeway.GenericPackage:
		c := pkg.Config.(leeway.GenericPkgConfig)
		cfg["commands"] = c.Commands
	case leeway.GoPackage:
		c := pkg.Config.(leeway.GoPkgConfig)
		cfg["buildFlags"] = c.BuildFlags
		cfg["dontCheckGoFmt"] = c.DontCheckGoFmt
		cfg["dontTest"] = c.DontTest
		cfg["generate"] = c.Generate
		cfg["packaging"] = c.Packaging
	case leeway.TypescriptPackage:
		c := pkg.Config.(leeway.TypescriptPkgConfig)
		cfg["dontTest"] = c.DontTest
		cfg["packaging"] = c.Packaging
		cfg["tsConfig"] = c.TSConfig
		cfg["yarnLock"] = c.YarnLock
		cfg["commands"] = map[string][]string{
			"build":   c.Commands.Build,
			"install": c.Commands.Install,
			"test":    c.Commands.Test,
		}
	}

	dp := packageDescription{
		Metadata:     newMetadataDescription(pkg),
		Type:         string(pkg.Type),
		ArgDeps:      pkg.ArgumentDependencies,
		Dependencies: deps,
		Env:          pkg.Environment,
		Manifest:     manifest,
		Config:       cfg,
	}

	if out.Format == prettyprint.TemplateFormat && out.FormatString == "" {
		out.FormatString = `Name:	{{ .Metadata.FullName }}
Version:	{{ .Metadata.Version }}
{{ if .Config -}}
Configuration:
{{- range $k, $v := .Config }}
{{"\t"}}{{ $k }}: {{ $v -}}
{{ end -}}
{{ end }}
{{ if .ArgDeps -}}
Version Relevant Arguments:
{{- range $k, $v := .ArgDeps }}
{{"\t"}}{{ $v -}}
{{ end -}}
{{ end }}
{{ if .Dependencies -}}
Dependencies:
{{- range $k, $v := .Dependencies }}
{{"\t"}}{{ $v.FullName -}}{{"\t"}}{{ $v.Version -}}
{{ end -}}
{{ end }}
{{ if .Manifest -}}
Sources:
{{- range $k, $v := .Manifest }}
{{"\t"}}{{ $k }}{{"\t"}}{{ $v -}}
{{ end -}}
{{ end }}
`
	}

	err = out.Write(dp)
	if err != nil {
		log.Fatal(err)
	}
}

func describeComponent(out *prettyprint.Writer, comp leeway.Component) {
	type componentDescription struct {
		Name      string                       `json:"name" yaml:"name"`
		Origin    string                       `json:"origin" yaml:"origin"`
		Constants map[string]string            `json:"contants,omitempty" yaml:"constants,omitempty"`
		Packages  []packageMetadataDescription `json:"packages,omitempty" yaml:"packages,omitempty"`
	}

	pkgs := make([]packageMetadataDescription, len(comp.Packages))
	for i := range comp.Packages {
		pkgs[i] = newMetadataDescription(comp.Packages[i])
	}
	desc := componentDescription{
		Name:      comp.Name,
		Origin:    comp.Origin,
		Constants: comp.Constants,
		Packages:  pkgs,
	}

	if out.Format == prettyprint.TemplateFormat && out.FormatString == "" {
		out.FormatString = `Name:{{"\t"}}{{ .Name }}
Origin:{{"\t"}}{{ .Origin }}
{{ if .Constants -}}
Constants:
{{- range $k, $v := .Constants }}
{{"\t"}}{{ $k }}: {{ $v -}}
{{ end -}}
{{ end }}
{{ if .Packages -}}
Packages:
{{- range $k, $v := .Packages }}
{{"\t"}}{{ $v.FullName }}{{"\t"}}{{ $v.Version -}}
{{ end -}}
{{ end }}
`
	}

	err := out.Write(desc)
	if err != nil {
		log.Fatal(err)
	}
}

func describeConfig(cfg leeway.PackageConfig, indent string) string {
	fc, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Sprintf("\t!! cannot present: %v !!", err)
	}

	cfgmap := make(map[string]interface{})
	err = yaml.Unmarshal(fc, &cfgmap)
	if err != nil {
		return fmt.Sprintf("\t!! cannot present: %v !!", err)
	}

	var res string
	for k, v := range cfgmap {
		res += fmt.Sprintf("%s%s:\t%v\n", indent, k, v)
	}
	return res
}

func init() {
	rootCmd.AddCommand(describeCmd)

	describeCmd.Flags().StringP("format", "o", string(prettyprint.TemplateFormat), "the description format. Valid choices are: template, json or yaml")
	describeCmd.Flags().StringP("format-string", "t", "", "format string to use, e.g. the template")
}
