package cmd

import (
	"fmt"
	"io"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/gitpod-io/leeway/pkg/leeway"
)

var (
	dockerfileCandidates      = []string{"Dockerfile", "leeway.Dockerfile"}
	packageTypeDetectionFiles = map[leeway.PackageType][]string{
		leeway.DockerPackage: dockerfileCandidates,
		leeway.GoPackage:     {"go.mod", "go.sum"},
		leeway.YarnPackage:   {"package.json", "yarn.lock"},
	}
	initPackageGenerator = map[leeway.PackageType]func(name string) ([]byte, error){
		leeway.DockerPackage:  initDockerPackage,
		leeway.GoPackage:      initGoPackage,
		leeway.YarnPackage:    initYarnPackage,
		leeway.GenericPackage: initGenericPackage,
	}
)

// initCmd represents the version command
var initCmd = &cobra.Command{
	Use:       "init <name>",
	Short:     "Initializes a new leeway package (and component if need be) in the current directory",
	Args:      cobra.ExactArgs(1),
	ValidArgs: []string{"go", "yarn", "docker", "generic"},
	RunE: func(cmd *cobra.Command, args []string) error {
		var tpe leeway.PackageType
		if tper, _ := cmd.Flags().GetString("type"); tper != "" {
			tpe = leeway.PackageType(tper)
		} else {
			tpe = detectPossiblePackageType()
		}

		generator, ok := initPackageGenerator[tpe]
		if !ok {
			return fmt.Errorf("unknown package type: %q", tpe)
		}

		tpl, err := generator(args[0])
		if err != nil {
			return err
		}
		var pkg yaml.Node
		err = yaml.Unmarshal(tpl, &pkg)
		if err != nil {
			log.WithField("template", string(tpl)).Warn("broken package template")
			return fmt.Errorf("This is a leeway bug. Cannot parse package template: %w", err)
		}

		f, err := os.OpenFile("BUILD.yaml", os.O_CREATE|os.O_RDWR, 0644)
		if err != nil {
			return err
		}
		defer f.Close()

		var cmp yaml.Node
		err = yaml.NewDecoder(f).Decode(&cmp)
		if err == io.EOF {
			err = yaml.Unmarshal([]byte(`packages: []`), &cmp)
		}
		if err != nil {
			return err
		}

		cmps := cmp.Content[0].Content
		for i, nde := range cmps {
			if !(nde.Value == "packages" && i < len(cmps)-1 && cmps[i+1].Kind == yaml.SequenceNode) {
				continue
			}

			pkgs := cmps[i+1]
			pkgs.Style = yaml.FoldedStyle
			pkgs.Content = append(pkgs.Content, pkg.Content[0])
			cmps[i+1] = pkgs
		}
		cmp.Content[0].Content = cmps

		_, err = f.Seek(0, 0)
		if err != nil {
			return err
		}
		err = yaml.NewEncoder(f).Encode(&cmp)
		if err != nil {
			return err
		}

		return nil
	},
}

func detectPossiblePackageType() leeway.PackageType {
	for tpe, fns := range packageTypeDetectionFiles {
		for _, fn := range fns {
			_, err := os.Stat(fn)
			if err != nil {
				continue
			}

			return tpe
		}
	}

	return leeway.GenericPackage
}

func initGoPackage(name string) ([]byte, error) {
	return []byte(fmt.Sprintf(`name: %s
type: go
srcs:
  - go.mod
  - go.sum
  - "**/*.go"
env:
  - CGO_ENABLED=0
config:
  packaging: app
`, name)), nil
}

func initDockerPackage(name string) ([]byte, error) {
	var dockerfile string
	for _, f := range dockerfileCandidates {
		if _, err := os.Stat(f); err == nil {
			dockerfile = f
			break
		}
	}
	if dockerfile == "" {
		return nil, fmt.Errorf("no Dockerfile found")
	}

	log.Warnf("Please update your BUILD.yaml and change the image reference of the new \"%s\" package", name)
	return []byte(fmt.Sprintf(`name: %s
type: docker
config:
  dockerfile: %s
  image: some/imgage/in/some:repo`, name, dockerfile)), nil
}

func initYarnPackage(name string) ([]byte, error) {
	return []byte(fmt.Sprintf(`name: %s
type: yarn
srcs:
  - package.json
  - "src/**"
config:
  yarnLock: yarn.lock
  tsconfig: tsconfig.json
`, name)), nil
}

func initGenericPackage(name string) ([]byte, error) {
	fs, err := os.ReadDir(".")
	if err != nil {
		return nil, err
	}
	var srcs []string
	for _, f := range fs {
		if f.Name() == "BUILD.yaml" {
			continue
		}
		if strings.HasPrefix(f.Name(), ".") {
			continue
		}

		var da string
		if f.IsDir() {
			da = "/**"
		}
		srcs = append(srcs, fmt.Sprintf("  - \"%s%s\"", f.Name(), da))
	}

	log.Warnf("Please update your BUILD.yaml and change the commands of the new \"%s\" package", name)
	return []byte(fmt.Sprintf(`name: %s
type: generic
srcs:
%s
config:
  comamnds:
  - ["echo", "commands", "go", "here"]
`, name, strings.Join(srcs, "\n"))), nil
}

func init() {
	rootCmd.AddCommand(initCmd)

	initCmd.Flags().StringP("type", "t", "", "type of the new package")
}
