package cmd

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/gitpod-io/leeway/pkg/leeway"
	"github.com/gitpod-io/leeway/pkg/leeway/cache"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// sbomExportCmd represents the sbom export command
var sbomExportCmd = &cobra.Command{
	Use:   "export [package]",
	Short: "Exports the SBOM of a (previously built) package",
	Long: `Exports the SBOM of a (previously built) package.
	
When used with --with-dependencies, it exports SBOMs for the package and all its dependencies
to the specified output directory.

If no package is specified, the workspace's default target is used.`,
	Args: cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		// Get the package
		_, pkg, _, _ := getTarget(args, false)
		if pkg == nil {
			log.Fatal("sbom export requires a package or a default target in the workspace")
		}

		// Get build options and cache
		_, localCache, _ := getBuildOpts(cmd)

		// Get output format and file
		format, _ := cmd.Flags().GetString("format")
		outputFile, _ := cmd.Flags().GetString("output")
		withDependencies, _ := cmd.Flags().GetBool("with-dependencies")
		outputDir, _ := cmd.Flags().GetString("output-dir")

		// Validate format using the utility function
		formatValid, validFormats := leeway.ValidateSBOMFormat(format)
		if !formatValid {
			log.Fatalf("Unsupported format: %s. Supported formats are: %s", format, strings.Join(validFormats, ", "))
		}

		// Validate flags for dependency export
		if withDependencies {
			if outputDir == "" {
				log.Fatal("--output-dir is required when using --with-dependencies")
			}
			if outputFile != "" {
				log.Fatal("--output and --output-dir cannot be used together")
			}
		}

		var allpkg []*leeway.Package
		allpkg = append(allpkg, pkg)

		if withDependencies {
			// Get all dependencies
			deps := pkg.GetTransitiveDependencies()

			// Skip ephemeral packages as they're not meant to be cached
			for _, p := range deps {
				if p.Ephemeral {
					log.Infof("Skipping vulnerability scan for ephemeral package %s\n", p.FullName())
					continue
				}
				allpkg = append(allpkg, p)
			}

			log.Infof("Exporting SBOMs for %s and %d dependencies to %s", pkg.FullName(), len(allpkg)-1, outputDir)
		}

		for _, p := range allpkg {
			var outputPath string
			if outputFile == "" {
				safeFilename := p.FilesystemSafeName()
				outputPath = filepath.Join(outputDir, safeFilename+leeway.GetSBOMFileExtension(format))
			} else {
				outputPath = outputFile
			}
			exportSBOM(p, localCache, outputPath, format)
		}
	},
}

func init() {
	sbomExportCmd.Flags().String("format", "cyclonedx", "SBOM format to export (cyclonedx, spdx, syft)")
	sbomExportCmd.Flags().StringP("output", "o", "", "Output file (defaults to stdout)")
	sbomExportCmd.Flags().Bool("with-dependencies", false, "Export SBOMs for the package and all its dependencies")
	sbomExportCmd.Flags().String("output-dir", "", "Output directory for exporting multiple SBOMs (required with --with-dependencies)")

	sbomCmd.AddCommand(sbomExportCmd)
	addBuildFlags(sbomExportCmd)
}

// exportSBOM extracts and writes an SBOM from a package's cached archive.
// It retrieves the package from the cache, creates the output file if needed,
// and extracts the SBOM in the specified format. If outputFile is empty,
// the SBOM is written to stdout.
func exportSBOM(pkg *leeway.Package, localCache cache.LocalCache, outputFile string, format string) {
	pkgFN := GetPackagePath(pkg, localCache)

	var output io.Writer = os.Stdout

	// Create directory if it doesn't exist
	if dir := filepath.Dir(outputFile); dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			log.WithError(err).Fatalf("cannot create output directory %s", dir)
		}
	}

	file, err := os.Create(outputFile)
	if err != nil {
		log.WithError(err).Fatalf("cannot create output file %s", outputFile)
	}
	defer file.Close()
	output = file

	// Extract and output the SBOM
	err = leeway.AccessSBOMInCachedArchive(pkgFN, format, func(sbomReader io.Reader) error {
		log.Infof("Exporting SBOM in %s format", format)
		_, err := io.Copy(output, sbomReader)
		return err
	})

	if err != nil {
		if err == leeway.ErrNoSBOMFile {
			log.Fatalf("no SBOM file found in package %s", pkg.FullName())
		}
		log.WithError(err).Fatal("cannot extract SBOM")
	}

	if outputFile != "" {
		log.Infof("SBOM exported to %s", outputFile)
	}
}

// GetPackagePath retrieves the filesystem path to a package's cached archive.
// It first checks the local cache, and if not found, attempts to download
// the package from the remote cache. This function verifies that SBOM is enabled
// in the workspace settings and returns the path to the package archive.
// If the package cannot be found in either cache, it exits with a fatal error.
func GetPackagePath(pkg *leeway.Package, localCache cache.LocalCache) (packagePath string) {
	// Check if SBOM is enabled in workspace settings
	if !pkg.C.W.SBOM.Enabled {
		log.Fatal("SBOM export/scan requires sbom.enabled=true in workspace settings")
	}

	if log.IsLevelEnabled(log.DebugLevel) {
		v, err := pkg.Version()
		if err != nil {
			log.WithError(err).Fatal("error getting version")
		}
		log.Debugf("Exporting SBOM of package %s (version %s)", pkg.FullName(), v)
	}

	// Get package location in local cache
	pkgFN, ok := localCache.Location(pkg)
	if !ok {
		// Package not found in local cache, check if it's in the remote cache
		log.Debugf("Package %s not found in local cache, checking remote cache", pkg.FullName())

		remoteCache := getRemoteCacheFromEnv()
		remoteCache = &pullOnlyRemoteCache{C: remoteCache}

		// Convert to cache.Package interface
		pkgsToCheck := []cache.Package{pkg}

		if log.IsLevelEnabled(log.DebugLevel) {
			v, err := pkgsToCheck[0].Version()
			if err != nil {
				log.WithError(err).Fatal("error getting version")
			}
			log.Debugf("Checking remote of package %s (version %s)", pkgsToCheck[0].FullName(), v)
		}

		// Check if the package exists in the remote cache
		existingPkgs, err := remoteCache.ExistingPackages(context.Background(), pkgsToCheck)
		if err != nil {
			log.WithError(err).Warnf("Failed to check if package %s exists in remote cache", pkg.FullName())
			log.Fatalf("%s is not built", pkg.FullName())
		} else {
			_, existsInRemote := existingPkgs[pkg]
			if existsInRemote {
				log.Infof("Package %s found in remote cache, downloading...", pkg.FullName())

				// Download the package from the remote cache
				err := remoteCache.Download(context.Background(), localCache, pkgsToCheck)
				if err != nil {
					log.WithError(err).Fatalf("Failed to download package %s from remote cache", pkg.FullName())
				}

				// Check if the download was successful
				pkgFN, ok = localCache.Location(pkg)
				if !ok {
					log.Fatalf("Failed to download package %s from remote cache", pkg.FullName())
				}

				log.Infof("Successfully downloaded package %s from remote cache", pkg.FullName())
			} else {
				log.Fatalf("%s is not built", pkg.FullName())
			}
		}
	}
	return pkgFN
}
