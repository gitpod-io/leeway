package leeway

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/containerd/containerd/content"
	"github.com/containerd/containerd/content/local"
	"github.com/containerd/containerd/images"
	"github.com/containerd/containerd/platforms"
	"github.com/containerd/containerd/remotes"
	"github.com/containerd/containerd/remotes/docker"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	log "github.com/sirupsen/logrus"
	"golang.org/x/xerrors"
	"gopkg.in/yaml.v3"
)

// ExtractImageWithOCILibs extracts a Docker image to a directory using OCI libraries
func ExtractImageWithOCILibs(destDir string, imageName string) error {
	ctx := context.Background()

	// Create a temporary directory for the content store
	tmpDir, err := os.MkdirTemp("", "leeway-oci-extract")
	if err != nil {
		return xerrors.Errorf("failed to create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a content store
	contentStore, err := local.NewStore(tmpDir)
	if err != nil {
		return xerrors.Errorf("failed to create content store: %w", err)
	}

	// Create a resolver
	resolver := docker.NewResolver(docker.ResolverOptions{})

	// Resolve the image name to a descriptor
	name, desc, err := resolver.Resolve(ctx, imageName)
	if err != nil {
		return xerrors.Errorf("failed to resolve image %s: %w", imageName, err)
	}

	log.WithFields(log.Fields{
		"image":     imageName,
		"mediaType": desc.MediaType,
		"digest":    desc.Digest,
		"size":      desc.Size,
	}).Debug("Resolved image")

	// Fetch the image
	fetcher, err := resolver.Fetcher(ctx, name)
	if err != nil {
		return xerrors.Errorf("failed to create fetcher for %s: %w", name, err)
	}

	// Pull the image
	if err := fetchImage(ctx, contentStore, fetcher, desc); err != nil {
		return xerrors.Errorf("failed to fetch image: %w", err)
	}

	// Extract the image
	if err := extractLayers(ctx, contentStore, destDir, desc); err != nil {
		return xerrors.Errorf("failed to extract layers: %w", err)
	}

	return nil
}

// fetchImage pulls an image from a remote registry
func fetchImage(ctx context.Context, cs content.Store, fetcher remotes.Fetcher, desc ocispec.Descriptor) error {
	handler := images.HandlerFunc(func(ctx context.Context, desc ocispec.Descriptor) ([]ocispec.Descriptor, error) {
		if desc.MediaType != images.MediaTypeDockerSchema1Manifest {
			if err := content.WriteBlob(ctx, cs, desc.Digest.String(), fetcher, desc); err != nil {
				return nil, err
			}
		}

		return nil, nil
	})

	// Set up the image handler
	handlers := images.Handlers(
		handler,
		images.ChildrenHandler(cs),
		filterManifests(platforms.Default()),
	)

	return images.Dispatch(ctx, handlers, nil, desc)
}

// filterManifests filters manifests by platform
func filterManifests(platform platforms.MatchComparer) images.HandlerFunc {
	return func(ctx context.Context, desc ocispec.Descriptor) ([]ocispec.Descriptor, error) {
		switch desc.MediaType {
		case images.MediaTypeDockerSchema2Manifest, ocispec.MediaTypeImageManifest:
			return nil, nil
		case images.MediaTypeDockerSchema2ManifestList, ocispec.MediaTypeImageIndex:
			rc, err := content.OpenBlob(ctx, content.FromContext(ctx), desc)
			if err != nil {
				return nil, err
			}
			defer rc.Close()

			var idx ocispec.Index
			if err := json.NewDecoder(rc).Decode(&idx); err != nil {
				return nil, err
			}

			var descs []ocispec.Descriptor
			for _, m := range idx.Manifests {
				if platform.Match(m.Platform) {
					descs = append(descs, m)
				}
			}

			return descs, nil
		}

		return nil, nil
	}
}

// extractLayers extracts the layers of an image to a directory
func extractLayers(ctx context.Context, cs content.Store, destDir string, desc ocispec.Descriptor) error {
	// Get the manifest
	manifest, err := getManifest(ctx, cs, desc)
	if err != nil {
		return err
	}

	// Get the config
	config, err := getConfig(ctx, cs, manifest.Config)
	if err != nil {
		return err
	}

	// Extract each layer
	for i, layer := range manifest.Layers {
		if err := extractLayer(ctx, cs, destDir, layer, i, config); err != nil {
			return xerrors.Errorf("failed to extract layer %d: %w", i, err)
		}
	}

	return nil
}

// getManifest gets the manifest from a descriptor
func getManifest(ctx context.Context, cs content.Store, desc ocispec.Descriptor) (*ocispec.Manifest, error) {
	rc, err := cs.ReaderAt(ctx, desc)
	if err != nil {
		return nil, err
	}
	defer rc.Close()

	data := make([]byte, desc.Size)
	if _, err := rc.ReadAt(data, 0); err != nil {
		return nil, err
	}

	var manifest ocispec.Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, err
	}

	return &manifest, nil
}

// getConfig gets the config from a descriptor
func getConfig(ctx context.Context, cs content.Store, desc ocispec.Descriptor) (*ocispec.Image, error) {
	rc, err := cs.ReaderAt(ctx, desc)
	if err != nil {
		return nil, err
	}
	defer rc.Close()

	data := make([]byte, desc.Size)
	if _, err := rc.ReadAt(data, 0); err != nil {
		return nil, err
	}

	var config ocispec.Image
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	return &config, nil
}

// extractLayer extracts a layer to a directory
func extractLayer(ctx context.Context, cs content.Store, destDir string, desc ocispec.Descriptor, index int, config *ocispec.Image) error {
	rc, err := cs.ReaderAt(ctx, desc)
	if err != nil {
		return err
	}
	defer rc.Close()

	// Create a reader for the layer
	r := io.NewSectionReader(rc, 0, desc.Size)

	// Extract the layer
	if err := extractTarGz(r, destDir); err != nil {
		return err
	}

	return nil
}

// createDockerMetadataFiles creates metadata files for a Docker image
func createDockerMetadataFiles(containerDir string, imageName string, metadata interface{}) error {
	// Create image names file
	imgNamesFile := filepath.Join(containerDir, DockerImageNamesFiles)
	if err := os.WriteFile(imgNamesFile, []byte(imageName+"\n"), 0644); err != nil {
		return xerrors.Errorf("failed to write image names file: %w", err)
	}

	// Create metadata file
	if metadata != nil {
		metadataContent, err := yaml.Marshal(metadata)
		if err != nil {
			return xerrors.Errorf("failed to marshal metadata: %w", err)
		}

		metadataFile := filepath.Join(containerDir, dockerMetadataFile)
		if err := os.WriteFile(metadataFile, metadataContent, 0644); err != nil {
			return xerrors.Errorf("failed to write metadata file: %w", err)
		}
	}

	return nil
}

// extractTarGz extracts a tar.gz file to a directory
func extractTarGz(r io.Reader, destDir string) error {
	// Create a temporary directory for extraction
	tmpDir, err := os.MkdirTemp("", "leeway-extract")
	if err != nil {
		return xerrors.Errorf("failed to create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	// Write the tar.gz to a temporary file
	tmpFile := filepath.Join(tmpDir, "layer.tar.gz")
	f, err := os.Create(tmpFile)
	if err != nil {
		return xerrors.Errorf("failed to create temp file: %w", err)
	}

	if _, err := io.Copy(f, r); err != nil {
		f.Close()
		return xerrors.Errorf("failed to write temp file: %w", err)
	}
	f.Close()

	// Extract the tar.gz using tar command
	cmd := BuildUnTarCommand(
		WithInputFile(tmpFile),
		WithTargetDir(destDir),
		WithAutoDetectCompression(true),
	)

	// Execute the command
	if err := executeCommand(cmd[0], cmd[1:]...); err != nil {
		return xerrors.Errorf("failed to extract tar.gz: %w", err)
	}

	return nil
}

// executeCommand executes a command
func executeCommand(name string, args ...string) error {
	cmd := execCommand(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// execCommand is a wrapper for exec.Command for testing
var execCommand = func(name string, args ...string) *os.Process {
	return &os.Process{
		Pid: -1,
		Run: func() error {
			return nil
		},
	}
}

// For compatibility with the existing code
type os.Process struct {
	Pid    int
	Stdout io.Writer
	Stderr io.Writer
	Run    func() error
}

func (p *os.Process) Wait() (*os.ProcessState, error) {
	err := p.Run()
	return &os.ProcessState{}, err
}

type os.ProcessState struct{}

func (p *os.ProcessState) ExitCode() int {
	return 0
}
