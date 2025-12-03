package leeway

import (
	"archive/tar"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/daemon"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

// ExtractImageFunc is the type for the image extraction function
type ExtractImageFunc func(destDir, imgTag string) error

// ExtractImageWithOCILibs is the function used to extract Docker images
// It can be replaced in tests for mocking
var ExtractImageWithOCILibs ExtractImageFunc = extractImageWithOCILibsImpl

// extractImageWithOCILibsImpl extracts a Docker image's filesystem content
// using the OCI distribution and image libraries
func extractImageWithOCILibsImpl(destDir, imgTag string) error {
	// Create destination directory if it doesn't exist
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return fmt.Errorf("failed to create destination directory: %w", err)
	}

	log.WithFields(log.Fields{
		"image": imgTag,
		"dest":  destDir,
	}).Debug("Extracting image using OCI libraries")

	// Create a temporary directory for initial extraction
	tempExtractDir, err := os.MkdirTemp(destDir, "extract-temp-")
	if err != nil {
		return fmt.Errorf("failed to create temporary extraction directory: %w", err)
	}
	defer os.RemoveAll(tempExtractDir) // Clean up temp dir after we're done

	// Try to load from OCI tar first (when built with --output type=oci)
	// The OCI tar is in the parent directory of destDir (the build directory)
	buildDir := filepath.Dir(filepath.Dir(destDir)) // destDir is buildDir/container/content
	ociTarPath := filepath.Join(buildDir, "image.tar")

	var img v1.Image

	if _, statErr := os.Stat(ociTarPath); statErr == nil {
		// OCI tar exists - extract and load from it
		log.WithField("ociTar", ociTarPath).Debug("Loading image from OCI tar file")

		// Create a temporary directory to extract the OCI layout
		ociLayoutDir, err := os.MkdirTemp(buildDir, "oci-layout-")
		if err != nil {
			return fmt.Errorf("creating temp dir for OCI layout: %w", err)
		}
		defer os.RemoveAll(ociLayoutDir)

		// Extract the OCI tar to the temporary directory
		if err := extractTar(ociTarPath, ociLayoutDir); err != nil {
			return fmt.Errorf("extracting OCI tar: %w", err)
		}

		// Load the image from the OCI layout directory
		layoutPath, err := layout.FromPath(ociLayoutDir)
		if err != nil {
			return fmt.Errorf("loading OCI layout from %s: %w", ociLayoutDir, err)
		}

		// Get the image index
		imageIndex, err := layoutPath.ImageIndex()
		if err != nil {
			return fmt.Errorf("getting image index from OCI layout: %w", err)
		}

		// Get the manifest
		indexManifest, err := imageIndex.IndexManifest()
		if err != nil {
			return fmt.Errorf("getting index manifest: %w", err)
		}

		if len(indexManifest.Manifests) == 0 {
			return fmt.Errorf("no manifests found in OCI layout")
		}

		// Get the first image (there should only be one for single-platform builds)
		img, err = layoutPath.Image(indexManifest.Manifests[0].Digest)
		if err != nil {
			return fmt.Errorf("getting image from OCI layout: %w", err)
		}

		log.Debug("Successfully loaded image from OCI tar")
	} else {
		// OCI tar doesn't exist - fall back to Docker daemon
		log.Debug("OCI tar not found, loading image from Docker daemon")

		ref, err := name.ParseReference(imgTag)
		if err != nil {
			return fmt.Errorf("parsing image reference: %w", err)
		}

		img, err = daemon.Image(ref)
		if err != nil {
			return fmt.Errorf("getting image from daemon: %w", err)
		}
		log.Debug("Successfully loaded image from Docker daemon")
	}

	// Get image config to check if it's a scratch image
	config, err := img.ConfigFile()
	if err != nil {
		return fmt.Errorf("getting image config: %w", err)
	}

	// Get image digest for metadata
	digest, err := img.Digest()
	if err != nil {
		log.WithError(err).Warn("Failed to get image digest")
	}

	// Extract metadata to the final destination directory
	if err := extractImageMetadata(destDir, imgTag, config, digest); err != nil {
		log.WithError(err).Warn("Failed to extract image metadata")
	}

	// Get the layers
	layers, err := img.Layers()
	if err != nil {
		return fmt.Errorf("getting image layers: %w", err)
	}

	// Check if this is a scratch image (no layers)
	if len(layers) == 0 {
		log.Info("Image appears to be a scratch image with no layers")
		return handleScratchImage(destDir, imgTag, config, digest)
	}

	log.WithField("layerCount", len(layers)).Debug("Extracting image layers")

	// Extract the filesystem by flattening the layers to the temp directory
	fs := mutate.Extract(img)
	defer fs.Close()

	// Extract the tar contents to the temporary directory
	if err := extractTarToDir(fs, tempExtractDir); err != nil {
		return fmt.Errorf("extracting filesystem: %w", err)
	}

	// Check if extraction produced any files
	if isEmpty(tempExtractDir) {
		log.Warn("Image extraction produced empty filesystem - might be a scratch or minimal image")
		return handleScratchImage(destDir, imgTag, config, digest)
	}

	// Create content directory in the final destination
	contentDir := filepath.Join(destDir, "content")
	if err := os.MkdirAll(contentDir, 0755); err != nil {
		return fmt.Errorf("failed to create content directory: %w", err)
	}

	// Move content from temp dir to content dir
	if err := organizeContainerContent(tempExtractDir, contentDir); err != nil {
		return fmt.Errorf("failed to organize container content: %w", err)
	}

	log.Debug("Successfully extracted image contents")
	return nil
}

// extractImageMetadata extracts the image metadata and saves it to files
func extractImageMetadata(destDir, imgTag string, config *v1.ConfigFile, digest v1.Hash) error {
	// Create imgnames.txt with the image tag
	if err := os.WriteFile(filepath.Join(destDir, dockerImageNamesFiles), []byte(imgTag+"\n"), 0644); err != nil {
		return fmt.Errorf("creating imgnames.txt: %w", err)
	}

	// Create metadata files with image information
	metadata := map[string]interface{}{
		"image":      imgTag,
		"digest":     digest.String(),
		"created":    config.Created.Time,
		"os":         config.OS,
		"arch":       config.Architecture,
		"env":        config.Config.Env,
		"cmd":        config.Config.Cmd,
		"entrypoint": config.Config.Entrypoint,
		"labels":     config.Config.Labels,
	}

	metadataBytes, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling metadata: %w", err)
	}

	if err := os.WriteFile(filepath.Join(destDir, "image-metadata.json"), metadataBytes, 0644); err != nil {
		return fmt.Errorf("writing image-metadata.json: %w", err)
	}

	return nil
}

// handleScratchImage creates appropriate files for a scratch-based image
func handleScratchImage(destDir, imgTag string, config *v1.ConfigFile, digest v1.Hash) error {
	log.WithField("image", imgTag).Info("Creating marker files for empty/scratch image")

	// Create content directory
	contentDir := filepath.Join(destDir, "content")
	if err := os.MkdirAll(contentDir, 0755); err != nil {
		return fmt.Errorf("creating content directory: %w", err)
	}

	// Create a marker file in the content directory
	markerContent := fmt.Sprintf("Empty or scratch-based Docker image: %s\nDigest: %s\n",
		imgTag, digest.String())
	if err := os.WriteFile(filepath.Join(contentDir, ".empty-image-marker"), []byte(markerContent), 0644); err != nil {
		return fmt.Errorf("creating empty image marker: %w", err)
	}

	// Create a readme with more details in the content directory
	readmeContent := fmt.Sprintf(`# Empty Container Image

This archive represents a Docker image that appears to be empty or scratch-based: %s

Image information:
- Digest: %s
- Created: %s
- Architecture: %s/%s
`, imgTag, digest.String(), config.Created.Format("2006-01-02T15:04:05Z07:00"),
		config.OS, config.Architecture)

	// Add command information if available
	if len(config.Config.Cmd) > 0 {
		readmeContent += fmt.Sprintf("- Command: %v\n", config.Config.Cmd)
	}
	if len(config.Config.Entrypoint) > 0 {
		readmeContent += fmt.Sprintf("- Entrypoint: %v\n", config.Config.Entrypoint)
	}

	if err := os.WriteFile(filepath.Join(contentDir, "README.md"), []byte(readmeContent), 0644); err != nil {
		return fmt.Errorf("creating README: %w", err)
	}

	// Create metadata files in the root directory
	if err := extractImageMetadata(destDir, imgTag, config, digest); err != nil {
		log.WithError(err).Warn("Failed to extract image metadata for scratch image")
	}

	return nil
}

// extractTarToDir extracts a tar archive to a directory
func extractTarToDir(r io.Reader, destDir string) error {
	tr := tar.NewReader(r)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		// Skip whiteout files which are used by Docker to remove files
		if strings.Contains(header.Name, ".wh.") {
			continue
		}

		// Get the target path, with safety checks
		target := filepath.Join(destDir, header.Name)

		// Prevent directory traversal attacks
		if !strings.HasPrefix(filepath.Clean(target), filepath.Clean(destDir)) {
			continue
		}

		switch header.Typeflag {
		case tar.TypeDir:
			// Create directory
			if err := os.MkdirAll(target, 0755); err != nil {
				return err
			}

		case tar.TypeReg:
			// Create containing directory
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return err
			}

			// Create file
			f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY, os.FileMode(header.Mode))
			if err != nil {
				return err
			}

			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return err
			}
			f.Close()

		case tar.TypeSymlink:
			// Create containing directory
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return err
			}

			// Create symlink (with safety check)
			linkTarget := header.Linkname
			if filepath.IsAbs(linkTarget) {
				// Convert absolute symlinks to relative ones contained within the extract directory
				linkTarget = filepath.Join(destDir, linkTarget)
				if !strings.HasPrefix(linkTarget, destDir) {
					// Skip symlinks that point outside the destination directory
					continue
				}
				linkTarget, _ = filepath.Rel(filepath.Dir(target), linkTarget)
			}

			if err := os.Symlink(linkTarget, target); err != nil {
				// Ignore errors on symlinks, which are common in cross-platform extraction
				log.WithError(err).Debugf("Failed to create symlink %s -> %s", target, linkTarget)
			}
		}
	}

	return nil
}

// createDockerMetadataFiles creates the required metadata files in the destination directory
// This function is updated to support structured metadata
func createDockerMetadataFiles(destDir string, imgTag string, metadata map[string]string) error {
	// Create imgnames.txt with the image tag
	if err := os.WriteFile(filepath.Join(destDir, dockerImageNamesFiles), []byte(imgTag+"\n"), 0644); err != nil {
		return fmt.Errorf("failed to create imgnames.txt: %w", err)
	}

	// Create metadata.yaml with the provided metadata
	// Use empty map if metadata is nil
	metadataToWrite := metadata
	if metadataToWrite == nil {
		metadataToWrite = make(map[string]string)
	}

	metadataBytes, err := yaml.Marshal(metadataToWrite)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	if err := os.WriteFile(filepath.Join(destDir, dockerMetadataFile), metadataBytes, 0644); err != nil {
		return fmt.Errorf("failed to create metadata.yaml: %w", err)
	}

	return nil
}

// organizeContainerContent moves filesystem content from the source directory to the content directory
// This function is used to organize Docker image extraction results
func organizeContainerContent(sourceDir, contentDir string) error {
	entries, err := os.ReadDir(sourceDir)
	if err != nil {
		return fmt.Errorf("reading source directory: %w", err)
	}

	// Process all entries in the source directory
	for _, entry := range entries {
		sourcePath := filepath.Join(sourceDir, entry.Name())

		// Skip metadata files - they'll be generated directly in the final directory
		if entry.Name() == dockerImageNamesFiles ||
			entry.Name() == dockerMetadataFile ||
			entry.Name() == "image-metadata.json" {
			continue
		}

		// Move content to the contentDir
		targetPath := filepath.Join(contentDir, entry.Name())

		if entry.IsDir() {
			// For directories, create them and copy contents recursively
			if err := os.MkdirAll(targetPath, 0755); err != nil {
				return fmt.Errorf("creating directory %s: %w", targetPath, err)
			}

			// Read directory contents
			dirEntries, err := os.ReadDir(sourcePath)
			if err != nil {
				return fmt.Errorf("reading directory %s: %w", sourcePath, err)
			}

			// Move each item in the directory
			for _, dirEntry := range dirEntries {
				sourceItemPath := filepath.Join(sourcePath, dirEntry.Name())
				targetItemPath := filepath.Join(targetPath, dirEntry.Name())

				if err := os.Rename(sourceItemPath, targetItemPath); err != nil {
					// If rename fails (e.g., cross-device), fall back to copy and remove
					if err := copyFileOrDirectory(sourceItemPath, targetItemPath); err != nil {
						return fmt.Errorf("copying %s to %s: %w", sourceItemPath, targetItemPath, err)
					}
					os.RemoveAll(sourceItemPath)
				}
			}
		} else {
			// For files, move them directly
			if err := os.Rename(sourcePath, targetPath); err != nil {
				// If rename fails, fall back to copy and remove
				if err := copyFileOrDirectory(sourcePath, targetPath); err != nil {
					return fmt.Errorf("copying %s to %s: %w", sourcePath, targetPath, err)
				}
				os.Remove(sourcePath)
			}
		}
	}

	return nil
}

// copyFileOrDirectory recursively copies a file or directory
func copyFileOrDirectory(src, dst string) error {
	sourceInfo, err := os.Stat(src)
	if err != nil {
		return err
	}

	if sourceInfo.IsDir() {
		// Create destination directory
		if err := os.MkdirAll(dst, sourceInfo.Mode()); err != nil {
			return err
		}

		// Read source directory
		entries, err := os.ReadDir(src)
		if err != nil {
			return err
		}

		// Copy each entry
		for _, entry := range entries {
			sourcePath := filepath.Join(src, entry.Name())
			destPath := filepath.Join(dst, entry.Name())
			if err := copyFileOrDirectory(sourcePath, destPath); err != nil {
				return err
			}
		}
		return nil
	}

	// Handle regular files
	source, err := os.Open(src)
	if err != nil {
		return err
	}
	defer source.Close()

	// Create destination file
	destination, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, sourceInfo.Mode())
	if err != nil {
		return err
	}
	defer destination.Close()

	_, err = io.Copy(destination, source)
	return err
}

// extractTar extracts a tar archive to a destination directory
func extractTar(tarPath, destDir string) error {
	file, err := os.Open(tarPath)
	if err != nil {
		return fmt.Errorf("opening tar file: %w", err)
	}
	defer file.Close()

	return extractTarToDir(file, destDir)
}
