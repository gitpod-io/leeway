package cmd

import (
	"fmt"
	"os"
	"sort"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/gitpod-io/leeway/pkg/leeway"
	"github.com/gitpod-io/leeway/pkg/prettyprint"
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
					subcmd = c
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

		comp, pkg, _, exists := getTarget(args, false)
		if !exists {
			return
		}

		w := getWriterFromFlags(cmd)
		if pkg != nil {
			describePackage(w, pkg)
			return
		}

		describeComponent(w, comp)
	},
}

func getTarget(args []string, findScript bool) (comp *leeway.Component, pkg *leeway.Package, script *leeway.Script, exists bool) {
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

	target = absPackageName(workspace, target)

	if isInCmp := strings.Contains(target, ":"); isInCmp {
		if findScript {
			script, exists = workspace.Scripts[target]
			if !exists {
				log.Fatalf("script \"%s\" does not exist", target)
				return
			}
			return
		}

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

func absPackageName(workspace leeway.Workspace, name string) string {
	if strings.HasPrefix(name, ".:") {
		wd, err := os.Getwd()
		if err != nil {
			log.Fatal(err)
		}

		// This uses seperate trims and is not part of origin to support BUILD files in the workspace root.
		// In that case there's no "/" left over at the origin.
		cn := strings.TrimPrefix(wd, workspace.Origin)
		cn = strings.TrimPrefix(cn, "/")

		pn := strings.TrimPrefix(name, ".:")

		return fmt.Sprintf("%s:%s", cn, pn)
	} else if name == "." {
		wd, err := os.Getwd()
		if err != nil {
			log.Fatal(err)
		}

		// This uses seperate trims and is not part of origin to support BUILD files in the workspace root.
		// In that case there's no "/" left over at the origin.
		cn := strings.TrimPrefix(wd, workspace.Origin)
		cn = strings.TrimPrefix(cn, "/")
		return cn
	}
	return name
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
	Metadata           packageMetadataDescription   `json:"metadata" yaml:"metadata"`
	Type               string                       `json:"type" yaml:"type"`
	Manifest           map[string]string            `json:"manifest" yaml:"manifest"`
	ArgDeps            []string                     `json:"argdeps,omitempty" yaml:"argdeps,omitempty"`
	Dependencies       []packageMetadataDescription `json:"dependencies,omitempty" yaml:"dependencies,omitempty"`
	Layout             map[string]string            `json:"layout,omitempty" yaml:"layout,omitempty"`
	Config             configDescription            `json:"config,omitempty" yaml:"config,omitempty"`
	Env                []string                     `json:"env,omitempty" yaml:"env,omitempty"`
	Definition         string                       `json:"definition,omitempty"`
	FilesystemSafeName string                       `json:"fsSafeName,omitempty"`
	Sources            []string                     `json:"sources,omitempty"`
}

func newPackageDesription(pkg *leeway.Package) packageDescription {
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

	layout := make(map[string]string)
	for _, dep := range pkg.GetDependencies() {
		layout[dep.FullName()] = pkg.BuildLayoutLocation(dep)
	}

	return packageDescription{
		Metadata:           newMetadataDescription(pkg),
		Type:               string(pkg.Type),
		ArgDeps:            pkg.ArgumentDependencies,
		Dependencies:       deps,
		Layout:             layout,
		Env:                pkg.Environment,
		Manifest:           manifest,
		Config:             newConfigDescription(pkg.Type, pkg.Config),
		Definition:         string(pkg.Definition),
		FilesystemSafeName: pkg.FilesystemSafeName(),
		Sources:            pkg.Sources,
	}
}

type configDescription map[string]interface{}

func newConfigDescription(tpe leeway.PackageType, c leeway.PackageConfig) configDescription {
	cfg := make(configDescription)
	switch tpe {
	case leeway.DockerPackage:
		c := c.(leeway.DockerPkgConfig)
		cfg["buildArgs"] = c.BuildArgs
		cfg["dockerfile"] = c.Dockerfile
		cfg["image"] = c.Image
		cfg["squash"] = c.Squash
	case leeway.GenericPackage:
		c := c.(leeway.GenericPkgConfig)
		cfg["commands"] = c.Commands
		cfg["test"] = c.Test
		cfg["dontTest"] = c.DontTest
	case leeway.GoPackage:
		c := c.(leeway.GoPkgConfig)
		cfg["buildFlags"] = c.BuildFlags
		cfg["dontCheckGoFmt"] = c.DontCheckGoFmt
		cfg["dontTest"] = c.DontTest
		cfg["dontLint"] = c.DontLint
		cfg["generate"] = c.Generate
		cfg["packaging"] = c.Packaging
		cfg["lintCommand"] = c.LintCommand
	case leeway.YarnPackage:
		c := c.(leeway.YarnPkgConfig)
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
	return cfg
}

func describePackage(out *prettyprint.Writer, pkg *leeway.Package) {
	if out.Format == prettyprint.TemplateFormat && out.FormatString == "" {
		out.FormatString = `Name:	{{ .Metadata.FullName }}
Version:	{{ .Metadata.Version }}
FS safe name:	{{ .FilesystemSafeName }}
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
{{ end }}
Layout:
{{- range $k, $v := .Layout }}
{{"\t"}}{{ $k -}}{{"\t"}}{{ $v -}}
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

	err := out.Write(newPackageDesription(pkg))
	if err != nil {
		log.Fatal(err)
	}
}

type componentDescription struct {
	Name      string                       `json:"name" yaml:"name"`
	Origin    string                       `json:"origin" yaml:"origin"`
	Constants map[string]string            `json:"contants,omitempty" yaml:"constants,omitempty"`
	Packages  []packageMetadataDescription `json:"packages,omitempty" yaml:"packages,omitempty"`
}

func newComponentDescription(comp *leeway.Component) componentDescription {
	pkgs := make([]packageMetadataDescription, len(comp.Packages))
	for i := range comp.Packages {
		pkgs[i] = newMetadataDescription(comp.Packages[i])
	}
	return componentDescription{
		Name:      comp.Name,
		Origin:    comp.Origin,
		Constants: comp.Constants,
		Packages:  pkgs,
	}
}

func describeComponent(out *prettyprint.Writer, comp *leeway.Component) {
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

	desc := newComponentDescription(comp)
	err := out.Write(desc)
	if err != nil {
		log.Fatal(err)
	}
}

type scriptDescription struct {
	Name            string                       `json:"name" yaml:"name"`
	FullName        string                       `json:"fullName" yaml:"fullName"`
	Description     string                       `json:"description,omitempty"`
	FullDescription string                       `json:"fullDescription,omitempty" yaml:"fullDescription,omitempty"`
	Env             []string                     `json:"env,omitempty" yaml:"env,omitempty"`
	Dependencies    []packageMetadataDescription `json:"dependencies,omitempty" yaml:"dependencies,omitempty"`
	WorkdirLayout   string                       `json:"workdirLayout" yaml:"workdirLayout"`
	Type            string                       `json:"type" yaml:"type"`
}

func newScriptDescription(s *leeway.Script) scriptDescription {
	deps := make([]packageMetadataDescription, len(s.Dependencies))
	for i, d := range s.GetDependencies() {
		deps[i] = newMetadataDescription(d)
	}

	desc := strings.ReplaceAll(s.Description, "\n", " ")
	if len(desc) > 80 {
		desc = desc[:80] + " ..."
	}

	return scriptDescription{
		Name:            s.Name,
		FullName:        s.FullName(),
		Description:     desc,
		FullDescription: s.Description,
		Dependencies:    deps,
		Env:             s.Environment,
		WorkdirLayout:   string(s.WorkdirLayout),
		Type:            string(s.Type),
	}
}

func init() {
	rootCmd.AddCommand(describeCmd)
	addFormatFlags(describeCmd)
}

func addFormatFlags(cmd *cobra.Command) {
	cmd.Flags().StringP("format", "o", string(prettyprint.TemplateFormat), "the description format. Valid choices are: template, json or yaml")
	cmd.Flags().StringP("format-string", "t", "", "format string to use, e.g. the template")
}

func getWriterFromFlags(cmd *cobra.Command) *prettyprint.Writer {
	format, _ := cmd.Flags().GetString("format")
	formatString, _ := cmd.Flags().GetString("format-string")
	return &prettyprint.Writer{
		Out:          os.Stdout,
		Format:       prettyprint.Format(format),
		FormatString: formatString,
	}
}
