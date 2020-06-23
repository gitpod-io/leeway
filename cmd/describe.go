package cmd

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

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
		w := prettyprint.Writer{
			Out:          os.Stdout,
			Format:       prettyprint.Format(format),
			FormatString: formatString,
		}
		if pkg != nil {
			describePackage(&w, pkg)
			return
		}

		describeComponent(comp)
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
	version, err := pkg.Version()
	if err != nil {
		log.Fatal(err)
	}

	deps := make([]packageMetadataDescription, len(pkg.Dependencies))
	for i, dep := range pkg.GetDependencies() {
		ver, err := dep.Version()
		if err != nil {
			log.Fatal(err)
		}
		deps[i] = packageMetadataDescription{
			FullName:  dep.FullName(),
			Name:      dep.Name,
			Emphemral: dep.Ephemeral,
			Version:   ver,
		}
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
		Metadata: packageMetadataDescription{
			Name:      pkg.Name,
			FullName:  pkg.FullName(),
			Version:   version,
			Emphemral: pkg.Ephemeral,
		},
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

	// deps := make([]string, len(pkg.GetDependencies()))
	// for i, dep := range pkg.GetDependencies() {
	// 	version, _ := dep.Version()
	// 	deps[i] = fmt.Sprintf("\t%s\t%s\n", dep.FullName(), version)
	// }
	// sort.Slice(deps, func(i, j int) bool { return deps[i] < deps[j] })

	// w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	// defer w.Flush()

	// fmt.Fprintf(w, "Name:\t%s\n", pkg.FullName())
	// fmt.Fprintf(w, "Version:\t%s\t\n", version)
	// if pkg.Ephemeral {
	// 	fmt.Fprintf(w, "Ephemeral:\ttrue\t\n")
	// }
	// fmt.Fprintf(w, "Configuration:\n%s", describeConfig(pkg.Config, "\t"))
	// if len(pkg.ArgumentDependencies) > 0 {
	// 	fmt.Fprintf(w, "Version Relevant Arguments:\n")
	// 	for _, argdep := range pkg.ArgumentDependencies {
	// 		fmt.Fprintf(w, "\t%s\n", argdep)
	// 	}
	// }
	// if len(pkg.Environment) > 0 {
	// 	fmt.Fprintf(w, "Build Environment Variables:\n")
	// 	for _, env := range pkg.Environment {
	// 		fmt.Fprintf(w, "\t%s\n", env)
	// 	}
	// }
	// if len(pkg.Dependencies) > 0 {
	// 	fmt.Fprintf(w, "Dependencies:\n")
	// 	for _, dep := range deps {
	// 		fmt.Fprint(w, dep)
	// 	}
	// }
	// if len(pkg.Sources) > 0 {
	// 	fmt.Fprintf(w, "Sources:\n")
	// 	for _, src := range manifest {
	// 		segs := strings.Split(src, ":")
	// 		name := segs[0]
	// 		version := segs[1]
	// 		fmt.Fprintf(w, "\t%s\t%s\n", name, version)
	// 	}
	// }
}

func describeComponent(comp leeway.Component) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	defer w.Flush()

	fmt.Fprintf(w, "Name:\t%s\n", comp.Name)
	fmt.Fprintf(w, "Origin:\t%s\n", comp.Origin)
	if len(comp.Constants) > 0 {
		fmt.Fprintf(w, "Constants:\t\n")
		for k, v := range comp.Constants {
			fmt.Fprintf(w, "\t%s:\t%s\n", k, v)
		}
	}
	fmt.Fprintf(w, "Packages:\t\n")
	for _, pkg := range comp.Packages {
		fmt.Fprintf(w, "\t%s\n", pkg.Name)
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

	describeCmd.Flags().StringP("format", "f", string(prettyprint.TemplateFormat), "the description format. Valid choices are: template, json or yaml")
	describeCmd.Flags().String("format-string", "", "format string to use, e.g. the template")
}
