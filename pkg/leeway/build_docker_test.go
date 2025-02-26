package leeway

import (
	"archive/tar"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/gitpod-io/leeway/pkg/leeway/cache"
	"github.com/google/go-cmp/cmp"
)

// testPackage is a wrapper around Package that allows us to override methods for testing
type testPackage struct {
	*Package
	versionFn             func() (string, error)
	getDependenciesFn     func() []*Package
	buildLayoutLocationFn func(dependency *Package) string
}

func newTestPackage(pkg *Package, opts ...func(*testPackage)) *testPackage {
	// Initialize the dependencies field to make the package "linked"
	if pkg.dependencies == nil {
		pkg.dependencies = make([]*Package, 0)
		pkg.layout = make(map[*Package]string)
	}
	tp := &testPackage{
		Package: pkg,
	}
	// Apply options
	for _, opt := range opts {
		opt(tp)
	}
	return tp
}

func withVersionFn(fn func() (string, error)) func(*testPackage) {
	return func(tp *testPackage) {
		tp.versionFn = fn
	}
}

func withGetDependenciesFn(fn func() []*Package) func(*testPackage) {
	return func(tp *testPackage) {
		tp.getDependenciesFn = fn
	}
}

func withBuildLayoutLocationFn(fn func(dependency *Package) string) func(*testPackage) {
	return func(tp *testPackage) {
		tp.buildLayoutLocationFn = fn
	}
}

func (tp *testPackage) Version() (string, error) {
	if tp.versionFn != nil {
		return tp.versionFn()
	}
	return tp.Package.Version()
}

func (tp *testPackage) GetDependencies() []*Package {
	if tp.getDependenciesFn != nil {
		return tp.getDependenciesFn()
	}
	return tp.Package.GetDependencies()
}

func (tp *testPackage) BuildLayoutLocation(dependency *Package) string {
	if tp.buildLayoutLocationFn != nil {
		return tp.buildLayoutLocationFn(dependency)
	}
	return tp.Package.BuildLayoutLocation(dependency)
}

func TestBuildDocker(t *testing.T) {
	// Create a temporary directory for our test
	tmpDir, err := os.MkdirTemp("", "leeway-docker-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a test Dockerfile
	dockerfileContent := "FROM alpine:latest\nRUN echo 'hello world'\n"
	dockerfilePath := filepath.Join(tmpDir, "Dockerfile")
	if err := os.WriteFile(dockerfilePath, []byte(dockerfileContent), 0644); err != nil {
		t.Fatalf("failed to write Dockerfile: %v", err)
	}

	// Create a mock workspace
	workspace := &Workspace{
		Origin:     tmpDir,
		Components: make(map[string]*Component),
		Packages:   make(map[string]*Package),
		Scripts:    make(map[string]*Script),
		Provenance: WorkspaceProvenance{
			Enabled: false,
			SLSA:    false,
		},
	}

	// Create a mock component
	component := &Component{
		W:      workspace,
		Origin: tmpDir,
		Name:   "test-component",
		git: &GitInfo{
			Commit: "test-commit",
		},
	}

	// Add the component to the workspace
	workspace.Components["test-component"] = component

	// Create test cases
	tests := []struct {
		name           string
		createPackage  func() *testPackage
		wantCommands   map[PackageBuildPhase][][]string
		wantErr        bool
		setupMockCache func(t *testing.T, tmpDir string) cache.LocalCache
	}{
		{
			name: "basic docker build with no image",
			createPackage: func() *testPackage {
				pkg := &Package{
					C: component,
					PackageInternal: PackageInternal{
						Name: "test-pkg",
						Type: DockerPackage,
					},
					Config: DockerPkgConfig{
						Dockerfile: "Dockerfile",
					},
				}

				return newTestPackage(pkg, withVersionFn(func() (string, error) {
					return "4956649c308a4fdefad9b1b793e86df975e8aca8", nil
				}))
			},
			wantCommands: map[PackageBuildPhase][][]string{
				PackageBuildPhasePrep: {
					{"cp", dockerfilePath, "Dockerfile"},
				},
				PackageBuildPhaseBuild: {
					{"docker", "build", "--pull", "-t", "4956649c308a4fdefad9b1b793e86df975e8aca8", "--build-arg", "__GIT_COMMIT=test-commit", "."},
					{"docker", "save", "-o", filepath.Join(tmpDir, "result"), "4956649c308a4fdefad9b1b793e86df975e8aca8"},
				},
				PackageBuildPhasePackage: {
					{"mkdir", "-p", "_mirror"},
					{"tar", "--sparse", "-cf", filepath.Join(tmpDir, "result.gz"), "--use-compress-program=/usr/bin/pigz", "-C", "_mirror", "."},
				},
			},
			wantErr: false,
			setupMockCache: func(t *testing.T, tmpDir string) cache.LocalCache {
				return &mockLocalCache{}
			},
		},
		{
			name: "docker build with image push",
			createPackage: func() *testPackage {
				pkg := &Package{
					C: component,
					PackageInternal: PackageInternal{
						Name: "test-pkg",
						Type: DockerPackage,
					},
					Config: DockerPkgConfig{
						Dockerfile: "Dockerfile",
						Image:      []string{"test-image:latest"},
					},
				}

				return newTestPackage(pkg, withVersionFn(func() (string, error) {
					return "4956649c308a4fdefad9b1b793e86df975e8aca8", nil
				}))
			},
			wantCommands: map[PackageBuildPhase][][]string{
				PackageBuildPhasePrep: {
					{"cp", dockerfilePath, "Dockerfile"},
				},
				PackageBuildPhaseBuild: {
					{"docker", "build", "--pull", "-t", "4956649c308a4fdefad9b1b793e86df975e8aca8", "--build-arg", "__GIT_COMMIT=test-commit", "."},
				},
				PackageBuildPhasePackage: {
					{"docker", "tag", "4956649c308a4fdefad9b1b793e86df975e8aca8", "test-image:latest"},
					{"docker", "push", "test-image:latest"},
					{"mkdir", "-p", "_mirror"},
					{"sh", "-c", "echo test-image:latest >> imgnames.txt"},
					{"sh", "-c", "echo built image: test-image:latest"},
					{"sh", "-c", "echo e30K | base64 -d > metadata.yaml"},
					{"tar", "--sparse", "-cf", filepath.Join(tmpDir, "result.gz"), "--use-compress-program=/usr/bin/pigz", "./imgnames.txt", "./metadata.yaml"},
				},
			},
			wantErr: false,
			setupMockCache: func(t *testing.T, tmpDir string) cache.LocalCache {
				return &mockLocalCache{}
			},
		},
		{
			name: "docker build with build args",
			createPackage: func() *testPackage {
				pkg := &Package{
					C: component,
					PackageInternal: PackageInternal{
						Name: "test-pkg",
						Type: DockerPackage,
					},
					Config: DockerPkgConfig{
						Dockerfile: "Dockerfile",
						BuildArgs: map[string]string{
							"ARG1": "value1",
							"ARG2": "value2",
						},
					},
				}
				return newTestPackage(pkg, withVersionFn(func() (string, error) {
					return "4956649c308a4fdefad9b1b793e86df975e8aca8", nil
				}))
			},
			wantCommands: map[PackageBuildPhase][][]string{
				PackageBuildPhasePrep: {
					{"cp", dockerfilePath, "Dockerfile"},
				},
				PackageBuildPhaseBuild: {
					{"docker", "build", "--pull", "-t", "4956649c308a4fdefad9b1b793e86df975e8aca8", "--build-arg", "ARG1=value1", "--build-arg", "ARG2=value2", "--build-arg", "__GIT_COMMIT=test-commit", "."},
					{"docker", "save", "-o", filepath.Join(tmpDir, "result"), "4956649c308a4fdefad9b1b793e86df975e8aca8"},
				},
				PackageBuildPhasePackage: {
					{"mkdir", "-p", "_mirror"},
					{"tar", "--sparse", "-cf", filepath.Join(tmpDir, "result.gz"), "--use-compress-program=/usr/bin/pigz", "-C", "_mirror", "."},
				},
			},
			wantErr: false,
			setupMockCache: func(t *testing.T, tmpDir string) cache.LocalCache {
				return &mockLocalCache{}
			},
		},
		{
			name: "docker build with dependencies",
			createPackage: func() *testPackage {
				pkg := &Package{
					C: component,
					PackageInternal: PackageInternal{
						Name:         "test-pkg",
						Type:         DockerPackage,
						Dependencies: []string{":dep-pkg"},
					},
					Config: DockerPkgConfig{
						Dockerfile: "Dockerfile",
					},
				}

				return newTestPackage(pkg,
					withVersionFn(func() (string, error) {
						return "4956649c308a4fdefad9b1b793e86df975e8aca8", nil
					}),
					withGetDependenciesFn(func() []*Package {
						deps := make([]*Package, 0, len(pkg.PackageInternal.Dependencies))
						for _, depName := range pkg.PackageInternal.Dependencies {
							// Create a mock dependency package
							depPkg := &Package{
								C: component,
								PackageInternal: PackageInternal{
									Name: depName[1:], // Remove the leading ":"
									Type: DockerPackage,
								},
							}
							deps = append(deps, depPkg)
						}
						return deps
					}),
					withBuildLayoutLocationFn(func(dependency *Package) string {
						return dependency.Name
					}),
				)
			},
			wantCommands: map[PackageBuildPhase][][]string{
				PackageBuildPhasePrep: {
					{"cp", dockerfilePath, "Dockerfile"},
				},
				PackageBuildPhaseBuild: {
					{"docker", "build", "--pull", "-t", "4956649c308a4fdefad9b1b793e86df975e8aca8", "--build-arg", "__GIT_COMMIT=test-commit", "."},
					{"docker", "save", "-o", filepath.Join(tmpDir, "result"), "4956649c308a4fdefad9b1b793e86df975e8aca8"},
				},
				PackageBuildPhasePackage: {
					{"mkdir", "-p", "_mirror"},
					{"tar", "--sparse", "-cf", filepath.Join(tmpDir, "result.gz"), "--use-compress-program=/usr/bin/pigz", "-C", "_mirror", "."},
				},
			},
			wantErr: false,
			setupMockCache: func(t *testing.T, tmpDir string) cache.LocalCache {
				// Create a mock dependency package
				depPkgPath := filepath.Join(tmpDir, "dep-pkg.tar.gz")
				if err := os.WriteFile(depPkgPath, []byte("mock dependency package"), 0644); err != nil {
					t.Fatalf("failed to create mock dependency package: %v", err)
				}

				return &mockLocalCache{
					locations: map[string]string{
						"dep-pkg": depPkgPath,
					},
				}
			},
		},
		{
			name: "docker build with docker image dependency",
			createPackage: func() *testPackage {
				pkg := &Package{
					C: component,
					PackageInternal: PackageInternal{
						Name:         "test-pkg",
						Type:         DockerPackage,
						Dependencies: []string{":docker-dep-pkg"},
					},
					Config: DockerPkgConfig{
						Dockerfile: "Dockerfile",
					},
				}

				return newTestPackage(pkg,
					withVersionFn(func() (string, error) {
						return "4956649c308a4fdefad9b1b793e86df975e8aca8", nil
					}),
					withGetDependenciesFn(func() []*Package {
						deps := make([]*Package, 0, len(pkg.PackageInternal.Dependencies))
						for _, depName := range pkg.PackageInternal.Dependencies {
							// Create a mock dependency package
							depPkg := &Package{
								C: component,
								PackageInternal: PackageInternal{
									Name: depName[1:], // Remove the leading ":"
									Type: DockerPackage,
								},
							}
							deps = append(deps, depPkg)
						}
						return deps
					}),
					withBuildLayoutLocationFn(func(dependency *Package) string {
						return dependency.Name
					}),
				)
			},
			wantCommands: map[PackageBuildPhase][][]string{
				PackageBuildPhasePrep: {
					{"cp", dockerfilePath, "Dockerfile"},
				},
				PackageBuildPhaseBuild: {
					{"docker", "build", "--pull", "-t", "4956649c308a4fdefad9b1b793e86df975e8aca8", "--build-arg", "__GIT_COMMIT=test-commit", "."},
					{"docker", "save", "-o", filepath.Join(tmpDir, "result"), "4956649c308a4fdefad9b1b793e86df975e8aca8"},
				},
				PackageBuildPhasePackage: {
					{"mkdir", "-p", "_mirror"},
					{"tar", "--sparse", "-cf", filepath.Join(tmpDir, "result.gz"), "--use-compress-program=/usr/bin/pigz", "-C", "_mirror", "."},
				},
			},
			wantErr: false,
			setupMockCache: func(t *testing.T, tmpDir string) cache.LocalCache {
				// Create a mock Docker dependency package with imgnames.txt
				depPkgPath := filepath.Join(tmpDir, "docker-dep-pkg.tar.gz")

				// Create a temporary tar.gz file with imgnames.txt
				f, err := os.Create(depPkgPath)
				if err != nil {
					t.Fatalf("failed to create mock docker dependency package: %v", err)
				}
				defer f.Close()

				gzw := gzip.NewWriter(f)
				defer gzw.Close()

				tw := tar.NewWriter(gzw)
				defer tw.Close()

				// Add imgnames.txt to the tar
				imgnames := []byte("test-docker-image:latest\n")
				hdr := &tar.Header{
					Name: dockerImageNamesFiles,
					Mode: 0644,
					Size: int64(len(imgnames)),
				}

				if err := tw.WriteHeader(hdr); err != nil {
					t.Fatalf("failed to write tar header: %v", err)
				}

				if _, err := tw.Write(imgnames); err != nil {
					t.Fatalf("failed to write imgnames.txt: %v", err)
				}

				// Close everything to flush the data
				tw.Close()
				gzw.Close()

				return &mockLocalCache{
					locations: map[string]string{
						"docker-dep-pkg": depPkgPath,
					},
				}
			},
		},
		{
			name: "missing dockerfile",
			createPackage: func() *testPackage {
				pkg := &Package{
					C: component,
					PackageInternal: PackageInternal{
						Name: "test-pkg",
						Type: DockerPackage,
					},
					Config: DockerPkgConfig{
						Dockerfile: "NonExistentDockerfile",
					},
				}
				return newTestPackage(pkg, withVersionFn(func() (string, error) {
					return "test-version", nil
				}))
			},
			wantErr: true,
			setupMockCache: func(t *testing.T, tmpDir string) cache.LocalCache {
				return &mockLocalCache{}
			},
		},
		{
			name: "empty dockerfile",
			createPackage: func() *testPackage {
				pkg := &Package{
					C: component,
					PackageInternal: PackageInternal{
						Name: "test-pkg",
						Type: DockerPackage,
					},
					Config: DockerPkgConfig{},
				}
				return newTestPackage(pkg, withVersionFn(func() (string, error) {
					return "test-version", nil
				}))
			},
			wantErr: true,
			setupMockCache: func(t *testing.T, tmpDir string) cache.LocalCache {
				return &mockLocalCache{}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mock cache
			mockCache := tt.setupMockCache(t, tmpDir)

			// Create build context
			buildctx := &buildContext{
				buildOptions: buildOptions{
					LocalCache: mockCache,
				},
				buildDir: tmpDir,
			}

			// Create the package
			pkg := tt.createPackage()

			// Debug: Print package details
			t.Logf("Package: %+v", pkg.Package)
			t.Logf("Package.C: %+v", pkg.Package.C)
			t.Logf("Package.dependencies: %+v", pkg.Package.dependencies)
			t.Logf("Package.layout: %+v", pkg.Package.layout)

			// Call the function under test
			result := filepath.Join(tmpDir, "result.gz")
			bld, err := pkg.Package.buildDocker(buildctx, tmpDir, result)

			// Check error
			if (err != nil) != tt.wantErr {
				t.Errorf("buildDocker() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err != nil {
				return
			}

			// Check commands
			if diff := cmp.Diff(tt.wantCommands, bld.Commands); diff != "" {
				t.Errorf("buildDocker() commands mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestDockerTarNotEmpty(t *testing.T) {
	// Create a temporary directory for our test
	tmpDir, err := os.MkdirTemp("", "leeway-docker-tar-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a test Docker tar file
	testTarPath := filepath.Join(tmpDir, "test-docker.tar")

	// Create a temporary tar file with some test files to simulate a Docker image
	f, err := os.Create(testTarPath)
	if err != nil {
		t.Fatalf("failed to create test tar file: %v", err)
	}

	tw := tar.NewWriter(f)

	// Add some test files to the tar to simulate a Docker image
	testFiles := []struct {
		name    string
		content string
	}{
		{
			name:    "manifest.json",
			content: `[{"Config":"config.json","Layers":["layer1/layer.tar","layer2/layer.tar"]}]`,
		},
		{
			name:    "config.json",
			content: `{"architecture":"amd64","config":{"Env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"]}}`,
		},
		{
			name:    "layer1/layer.tar",
			content: "layer1 content",
		},
		{
			name:    "layer2/layer.tar",
			content: "layer2 content",
		},
	}

	for _, tf := range testFiles {
		hdr := &tar.Header{
			Name: tf.name,
			Mode: 0644,
			Size: int64(len(tf.content)),
		}

		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("failed to write tar header for %s: %v", tf.name, err)
		}

		if _, err := tw.Write([]byte(tf.content)); err != nil {
			t.Fatalf("failed to write content for %s: %v", tf.name, err)
		}
	}

	// Close the tar writer to flush the data
	tw.Close()
	f.Close()

	// Now create an empty tar file for comparison
	emptyTarPath := filepath.Join(tmpDir, "empty-docker.tar")
	emptyF, err := os.Create(emptyTarPath)
	if err != nil {
		t.Fatalf("failed to create empty tar file: %v", err)
	}
	emptyTW := tar.NewWriter(emptyF)
	emptyTW.Close()
	emptyF.Close()

	// Test cases
	tests := []struct {
		name     string
		tarPath  string
		wantErr  bool
		isEmpty  bool
		fileSize int64
	}{
		{
			name:     "valid docker tar with content",
			tarPath:  testTarPath,
			wantErr:  false,
			isEmpty:  false,
			fileSize: -1, // Will be set during test
		},
		{
			name:     "empty docker tar",
			tarPath:  emptyTarPath,
			wantErr:  false,
			isEmpty:  true,
			fileSize: -1, // Will be set during test
		},
		{
			name:     "non-existent tar file",
			tarPath:  filepath.Join(tmpDir, "non-existent.tar"),
			wantErr:  true,
			isEmpty:  true,
			fileSize: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Get file info if the file exists
			if !tt.wantErr {
				info, err := os.Stat(tt.tarPath)
				if err != nil {
					t.Fatalf("failed to stat tar file: %v", err)
				}
				tt.fileSize = info.Size()
			}

			// Open the tar file
			f, err := os.Open(tt.tarPath)
			if (err != nil) != tt.wantErr {
				t.Errorf("os.Open() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}
			defer f.Close()

			// Check file size
			if tt.fileSize == 0 {
				t.Errorf("Docker tar file is empty (0 bytes)")
				return
			}

			// Read the tar file
			tr := tar.NewReader(f)

			// Try to read the first header
			header, err := tr.Next()
			if err != nil && err != io.EOF {
				t.Errorf("tar.Next() error = %v", err)
				return
			}

			// Check if the tar is empty (no headers)
			isEmpty := header == nil || err == io.EOF
			if isEmpty != tt.isEmpty {
				t.Errorf("Docker tar emptiness = %v, want %v", isEmpty, tt.isEmpty)
				return
			}

			// If we expect content, verify we can read all entries
			if !tt.isEmpty {
				fileCount := 0
				// Count the first header we already read
				if header != nil {
					fileCount++
				}

				// Read the rest of the headers
				for {
					header, err := tr.Next()
					if err == io.EOF {
						break
					}
					if err != nil {
						t.Errorf("tar.Next() error = %v", err)
						return
					}
					fileCount++

					// Verify the header has a name
					if header.Name == "" {
						t.Errorf("Docker tar contains a header with an empty name")
					}
				}

				// Verify we found all the expected files
				if fileCount != len(testFiles) {
					t.Errorf("Docker tar contains %d files, want %d", fileCount, len(testFiles))
				}
			}
		})
	}
}

func TestVerifyDockerTarContents(t *testing.T) {
	// Create a temporary directory for our test
	tmpDir, err := os.MkdirTemp("", "leeway-docker-tar-verify-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a test Docker tar file
	testTarPath := filepath.Join(tmpDir, "test-docker.tar")

	// Create a temporary tar file with some test files to simulate a Docker image
	f, err := os.Create(testTarPath)
	if err != nil {
		t.Fatalf("failed to create test tar file: %v", err)
	}

	tw := tar.NewWriter(f)

	// Add some test files to the tar to simulate a Docker image
	testFiles := []struct {
		name    string
		content string
	}{
		{
			name:    "manifest.json",
			content: `[{"Config":"config.json","Layers":["layer1/layer.tar","layer2/layer.tar"]}]`,
		},
		{
			name:    "config.json",
			content: `{"architecture":"amd64","config":{"Env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"]}}`,
		},
		{
			name:    "layer1/layer.tar",
			content: "layer1 content",
		},
		{
			name:    "layer2/layer.tar",
			content: "layer2 content",
		},
	}

	for _, tf := range testFiles {
		hdr := &tar.Header{
			Name: tf.name,
			Mode: 0644,
			Size: int64(len(tf.content)),
		}

		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("failed to write tar header for %s: %v", tf.name, err)
		}

		if _, err := tw.Write([]byte(tf.content)); err != nil {
			t.Fatalf("failed to write content for %s: %v", tf.name, err)
		}
	}

	// Close the tar writer to flush the data
	tw.Close()
	f.Close()

	// Test the tar file
	t.Run("verify docker tar contents", func(t *testing.T) {
		// Open the tar file
		f, err := os.Open(testTarPath)
		if err != nil {
			t.Fatalf("failed to open tar file: %v", err)
		}
		defer f.Close()

		// Read the tar file
		tr := tar.NewReader(f)

		// Create a map to track which files we've found
		foundFiles := make(map[string]bool)

		// Read all entries
		for {
			header, err := tr.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatalf("tar.Next() error = %v", err)
			}

			// Mark this file as found
			foundFiles[header.Name] = true

			// Read the content
			content := make([]byte, header.Size)
			_, err = io.ReadFull(tr, content)
			if err != nil {
				t.Fatalf("failed to read content for %s: %v", header.Name, err)
			}

			// Find the expected content for this file
			var expectedContent string
			for _, tf := range testFiles {
				if tf.name == header.Name {
					expectedContent = tf.content
					break
				}
			}

			// Verify the content matches
			if string(content) != expectedContent {
				t.Errorf("content mismatch for %s: got %q, want %q", header.Name, string(content), expectedContent)
			}
		}

		// Verify we found all the expected files
		for _, tf := range testFiles {
			if !foundFiles[tf.name] {
				t.Errorf("missing file %s in tar", tf.name)
			}
		}

		// Verify we didn't find any unexpected files
		if len(foundFiles) != len(testFiles) {
			t.Errorf("found %d files in tar, want %d", len(foundFiles), len(testFiles))
		}
	})
}

func TestExtractImageNameFromCache(t *testing.T) {
	// Create a temporary directory for our test
	tmpDir, err := os.MkdirTemp("", "leeway-docker-extract-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a test cache bundle with imgnames.txt
	testCachePath := filepath.Join(tmpDir, "test-cache.tar.gz")

	// Create a temporary tar.gz file with imgnames.txt
	f, err := os.Create(testCachePath)
	if err != nil {
		t.Fatalf("failed to create test cache file: %v", err)
	}

	gzw := gzip.NewWriter(f)
	tw := tar.NewWriter(gzw)

	// Add imgnames.txt to the tar
	imgnames := []byte("test-image:latest\ntest-image:v1.0.0\n")
	hdr := &tar.Header{
		Name: dockerImageNamesFiles,
		Mode: 0644,
		Size: int64(len(imgnames)),
	}

	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatalf("failed to write tar header: %v", err)
	}

	if _, err := tw.Write(imgnames); err != nil {
		t.Fatalf("failed to write imgnames.txt: %v", err)
	}

	// Close everything to flush the data
	tw.Close()
	gzw.Close()
	f.Close()

	// Test cases
	tests := []struct {
		name        string
		pkgName     string
		cachePath   string
		wantImgName string
		wantErr     bool
	}{
		{
			name:        "valid cache with imgnames.txt",
			pkgName:     "test-pkg",
			cachePath:   testCachePath,
			wantImgName: "test-image:latest",
			wantErr:     false,
		},
		{
			name:        "non-existent cache file",
			pkgName:     "test-pkg",
			cachePath:   filepath.Join(tmpDir, "non-existent.tar.gz"),
			wantImgName: "",
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			imgName, err := extractImageNameFromCache(tt.pkgName, tt.cachePath)

			if (err != nil) != tt.wantErr {
				t.Errorf("extractImageNameFromCache() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if imgName != tt.wantImgName {
				t.Errorf("extractImageNameFromCache() = %v, want %v", imgName, tt.wantImgName)
			}
		})
	}
}

func TestDockerExportPostBuild(t *testing.T) {
	// Create a temporary directory for our test
	tmpDir, err := os.MkdirTemp("", "leeway-docker-export-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a test Docker export file
	testExportPath := filepath.Join(tmpDir, "test-export.tar")

	// Create a temporary tar file with some test files
	f, err := os.Create(testExportPath)
	if err != nil {
		t.Fatalf("failed to create test export file: %v", err)
	}

	tw := tar.NewWriter(f)

	// Add some test files to the tar
	testFiles := []struct {
		name    string
		content string
	}{
		{
			name:    "layer1/layer.tar",
			content: "layer1 content",
		},
		{
			name:    "layer2/layer.tar",
			content: "layer2 content",
		},
		{
			name:    "manifest.json",
			content: `[{"Config":"config.json","Layers":["layer1/layer.tar","layer2/layer.tar"]}]`,
		},
		{
			name:    "config.json",
			content: `{"architecture":"amd64","config":{"Env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"]}}`,
		},
	}

	for _, tf := range testFiles {
		hdr := &tar.Header{
			Name: tf.name,
			Mode: 0644,
			Size: int64(len(tf.content)),
		}

		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("failed to write tar header for %s: %v", tf.name, err)
		}

		if _, err := tw.Write([]byte(tf.content)); err != nil {
			t.Fatalf("failed to write content for %s: %v", tf.name, err)
		}
	}

	// Close the tar writer to flush the data
	tw.Close()
	f.Close()

	// Call the function under test
	postBuildFn := dockerExportPostBuild(tmpDir, testExportPath)

	// Create a mock fileset
	mockFileset := fileset{}

	// Call the post-build function
	subjects, resultDir, err := postBuildFn(mockFileset)
	if err != nil {
		t.Fatalf("dockerExportPostBuild() error = %v", err)
	}

	// Check the result directory
	if resultDir != tmpDir {
		t.Errorf("dockerExportPostBuild() resultDir = %v, want %v", resultDir, tmpDir)
	}

	// Check the subjects
	if len(subjects) != len(testFiles) {
		t.Errorf("dockerExportPostBuild() returned %d subjects, want %d", len(subjects), len(testFiles))
	}

	// Verify that all expected files are in the subjects
	fileNames := make(map[string]bool)
	for _, subj := range subjects {
		fileNames[subj.Name] = true
	}

	for _, tf := range testFiles {
		if !fileNames[tf.name] {
			t.Errorf("dockerExportPostBuild() missing subject for file %s", tf.name)
		}
	}
}

// Mock cache package implementation
type mockCachePackage struct {
	name string
}

func (m *mockCachePackage) FullName() string {
	return m.name
}

func (m *mockCachePackage) Version() string {
	return "test-version"
}

// Mock LocalCache implementation for testing
type mockLocalCache struct {
	locations map[string]string
}

func (m *mockLocalCache) Location(pkg cache.Package) (string, bool) {
	if m.locations == nil {
		return "", false
	}

	loc, ok := m.locations[pkg.FullName()]
	return loc, ok
}

func (m *mockLocalCache) Store(pkg cache.Package, content string) error {
	return nil
}

func (m *mockLocalCache) Delete(pkg cache.Package) error {
	return nil
}

func (m *mockLocalCache) Exists(pkg cache.Package) bool {
	_, ok := m.Location(pkg)
	return ok
}

func (m *mockLocalCache) Versions() ([]string, error) {
	return nil, nil
}

func (m *mockLocalCache) PackagesByVersion(version string) ([]cache.Package, error) {
	return nil, nil
}

func TestBuildDockerTarContents(t *testing.T) {
	// Create a temporary directory for our test
	tmpDir, err := os.MkdirTemp("", "leeway-docker-build-tar-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a test Dockerfile
	dockerfileContent := "FROM alpine:latest\nRUN echo 'hello world'\n"
	dockerfilePath := filepath.Join(tmpDir, "Dockerfile")
	if err := os.WriteFile(dockerfilePath, []byte(dockerfileContent), 0644); err != nil {
		t.Fatalf("failed to write Dockerfile: %v", err)
	}

	// Create a mock workspace
	workspace := &Workspace{
		Origin:     tmpDir,
		Components: make(map[string]*Component),
		Packages:   make(map[string]*Package),
		Scripts:    make(map[string]*Script),
		Provenance: WorkspaceProvenance{
			Enabled: false,
			SLSA:    false,
		},
	}

	// Create a mock component
	component := &Component{
		W:      workspace,
		Origin: tmpDir,
		Name:   "test-component",
		git: &GitInfo{
			Commit: "test-commit",
		},
	}

	// Add the component to the workspace
	workspace.Components["test-component"] = component

	// Create a basic Docker package
	pkg := &Package{
		C: component,
		PackageInternal: PackageInternal{
			Name: "test-pkg",
			Type: DockerPackage,
		},
		Config: DockerPkgConfig{
			Dockerfile: "Dockerfile",
		},
	}

	// Create a test package with a fixed version
	testPkg := newTestPackage(pkg, withVersionFn(func() (string, error) {
		return "4956649c308a4fdefad9b1b793e86df975e8aca8", nil
	}))

	// Create build context
	buildctx := &buildContext{
		buildOptions: buildOptions{
			LocalCache: &mockLocalCache{},
		},
		buildDir: tmpDir,
	}

	// Call the function under test
	resultPath := filepath.Join(tmpDir, "result.tar.gz")
	bld, err := testPkg.Package.buildDocker(buildctx, tmpDir, resultPath)
	if err != nil {
		t.Fatalf("buildDocker() error = %v", err)
	}

	// Execute the build commands to create the Docker tar file
	for _, cmds := range bld.Commands {
		for _, cmd := range cmds {
			// Skip commands that would require Docker to be installed
			if cmd[0] == "docker" {
				// Instead, create a mock Docker tar file for testing
				if len(cmd) > 2 && cmd[1] == "save" && cmd[2] == "-o" {
					// This is the docker save command, create a mock tar file
					mockDockerTarPath := cmd[3]

					// Create a temporary tar file with some test files to simulate a Docker image
					f, err := os.Create(mockDockerTarPath)
					if err != nil {
						t.Fatalf("failed to create mock Docker tar file: %v", err)
					}

					tw := tar.NewWriter(f)

					// Add some test files to the tar to simulate a Docker image
					testFiles := []struct {
						name    string
						content string
					}{
						{
							name:    "manifest.json",
							content: `[{"Config":"config.json","Layers":["layer1/layer.tar","layer2/layer.tar"]}]`,
						},
						{
							name:    "config.json",
							content: `{"architecture":"amd64","config":{"Env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"]}}`,
						},
						{
							name:    "layer1/layer.tar",
							content: "layer1 content",
						},
						{
							name:    "layer2/layer.tar",
							content: "layer2 content",
						},
					}

					for _, tf := range testFiles {
						hdr := &tar.Header{
							Name: tf.name,
							Mode: 0644,
							Size: int64(len(tf.content)),
						}

						if err := tw.WriteHeader(hdr); err != nil {
							t.Fatalf("failed to write tar header for %s: %v", tf.name, err)
						}

						if _, err := tw.Write([]byte(tf.content)); err != nil {
							t.Fatalf("failed to write content for %s: %v", tf.name, err)
						}
					}

					// Close the tar writer to flush the data
					tw.Close()
					f.Close()
				}
				continue
			}

			// For tar commands, create a mock tar.gz file
			if cmd[0] == "tar" {
				// Find the output file path
				var outputPath string
				for i, arg := range cmd {
					if arg == "-cf" && i+1 < len(cmd) {
						outputPath = cmd[i+1]
						break
					}
				}

				if outputPath != "" {
					// Create the directory structure if it doesn't exist
					if err := os.MkdirAll(filepath.Dir(outputPath), 0755); err != nil {
						t.Fatalf("failed to create directory for tar output: %v", err)
					}

					// Create a mock tar.gz file
					f, err := os.Create(outputPath)
					if err != nil {
						t.Fatalf("failed to create mock tar.gz file: %v", err)
					}

					gzw := gzip.NewWriter(f)
					tw := tar.NewWriter(gzw)

					// Add a test file to the tar.gz
					content := "test content"
					hdr := &tar.Header{
						Name: "test-file.txt",
						Mode: 0644,
						Size: int64(len(content)),
					}

					if err := tw.WriteHeader(hdr); err != nil {
						t.Fatalf("failed to write tar header: %v", err)
					}

					if _, err := tw.Write([]byte(content)); err != nil {
						t.Fatalf("failed to write content: %v", err)
					}

					// Close everything to flush the data
					tw.Close()
					gzw.Close()
					f.Close()
				}
				continue
			}

			// Execute other commands (mkdir, cp, etc.)
			if cmd[0] == "mkdir" {
				dirPath := cmd[len(cmd)-1]
				if err := os.MkdirAll(dirPath, 0755); err != nil {
					t.Fatalf("failed to create directory: %v", err)
				}
			} else if cmd[0] == "cp" {
				// Skip cp commands for simplicity
				continue
			}
		}
	}

	// Now verify the Docker tar file
	if cmds, ok := bld.Commands[PackageBuildPhaseBuild]; ok && len(cmds) > 0 {
		for _, cmd := range cmds {
			if len(cmd) > 2 && cmd[0] == "docker" && cmd[1] == "save" && cmd[2] == "-o" {
				dockerTarPath := cmd[3]

				// Verify the Docker tar file exists
				if _, err := os.Stat(dockerTarPath); err != nil {
					t.Fatalf("Docker tar file does not exist: %v", err)
				}

				// Open the tar file
				f, err := os.Open(dockerTarPath)
				if err != nil {
					t.Fatalf("failed to open Docker tar file: %v", err)
				}
				defer f.Close()

				// Read the tar file
				tr := tar.NewReader(f)

				// Create a map to track which files we've found
				foundFiles := make(map[string]bool)

				// Read all entries
				for {
					header, err := tr.Next()
					if err == io.EOF {
						break
					}
					if err != nil {
						t.Fatalf("tar.Next() error = %v", err)
					}

					// Mark this file as found
					foundFiles[header.Name] = true

					// Verify the file has content
					if header.Size == 0 {
						t.Errorf("file %s in Docker tar has zero size", header.Name)
					}
				}

				// Verify we found at least some files
				if len(foundFiles) == 0 {
					t.Errorf("Docker tar file is empty (no files)")
				}

				// Verify we found the expected files
				expectedFiles := []string{
					"manifest.json",
					"config.json",
					"layer1/layer.tar",
					"layer2/layer.tar",
				}

				for _, expectedFile := range expectedFiles {
					if !foundFiles[expectedFile] {
						t.Errorf("missing file %s in Docker tar", expectedFile)
					}
				}
			}
		}
	}

	// Verify the final tar.gz file
	if _, err := os.Stat(resultPath); err != nil {
		t.Fatalf("result tar.gz file does not exist: %v", err)
	}

	// Open the tar.gz file
	f, err := os.Open(resultPath)
	if err != nil {
		t.Fatalf("failed to open result tar.gz file: %v", err)
	}
	defer f.Close()

	// Read the tar.gz file
	gzr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("failed to create gzip reader: %v", err)
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)

	// Create a map to track which files we've found
	foundFiles := make(map[string]bool)

	// Read all entries
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar.Next() error = %v", err)
		}

		// Mark this file as found
		foundFiles[header.Name] = true

		// Verify the file has content
		if header.Size == 0 && header.Typeflag != tar.TypeDir {
			t.Errorf("file %s in result tar.gz has zero size", header.Name)
		}
	}

	// Verify we found at least some files
	if len(foundFiles) == 0 {
		t.Errorf("result tar.gz file is empty (no files)")
	}

	// Verify we found at least the test file
	if !foundFiles["test-file.txt"] {
		t.Errorf("missing test-file.txt in result tar.gz")
	}
}
