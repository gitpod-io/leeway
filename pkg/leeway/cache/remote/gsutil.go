package remote

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	log "github.com/sirupsen/logrus"

	"github.com/gitpod-io/leeway/pkg/leeway/cache"
)

// GSUtilCache uses the gsutil command to implement a remote cache
type GSUtilCache struct {
	BucketName string
}

// NewGSUtilCache creates a new GSUtil cache implementation
func NewGSUtilCache(cfg *cache.RemoteConfig) *GSUtilCache {
	return &GSUtilCache{
		BucketName: cfg.BucketName,
	}
}

// ExistingPackages returns existing cached build artifacts in the remote cache
func (rs *GSUtilCache) ExistingPackages(ctx context.Context, pkgs []cache.Package) (map[cache.Package]struct{}, error) {
	fmt.Printf("☁️  checking remote cache for past build artifacts for %d packages\n", len(pkgs))

	// Map to store both .tar.gz and .tar URLs for each package
	type urlPair struct {
		gzURL  string
		tarURL string
	}
	packageToURLMap := make(map[cache.Package]urlPair)

	// Create a list of all possible URLs
	var urls []string
	for _, p := range pkgs {
		version, err := p.Version()
		if err != nil {
			log.WithField("package", p.FullName()).Debug("Failed to get version for package. Will not check remote cache for package.")
			continue
		}

		pair := urlPair{
			gzURL:  fmt.Sprintf("gs://%s/%s.tar.gz", rs.BucketName, version),
			tarURL: fmt.Sprintf("gs://%s/%s.tar", rs.BucketName, version),
		}
		packageToURLMap[p] = pair
		urls = append(urls, pair.gzURL, pair.tarURL)
	}

	if len(urls) == 0 {
		return map[cache.Package]struct{}{}, nil
	}

	log.Debugf("Checking if %d packages exist in the remote cache using gsutil", len(urls))
	args := append([]string{"stat"}, urls...)
	cmd := exec.Command("gsutil", args...)

	var stdoutBuffer, stderrBuffer strings.Builder
	cmd.Stdout = &stdoutBuffer
	cmd.Stderr = &stderrBuffer

	err := cmd.Run()
	if err != nil && (!strings.Contains(stderrBuffer.String(), "No URLs matched")) {
		log.Debugf("gsutil stat returned non-zero exit code: [%v], stderr: [%v]", err, stderrBuffer.String())
		return map[cache.Package]struct{}{}, nil
	}

	existingURLs := parseGSUtilStatOutput(strings.NewReader(stdoutBuffer.String()))
	existingPackages := make(map[cache.Package]struct{})

	for p, urls := range packageToURLMap {
		if _, exists := existingURLs[urls.gzURL]; exists {
			existingPackages[p] = struct{}{}
			continue
		}
		if _, exists := existingURLs[urls.tarURL]; exists {
			existingPackages[p] = struct{}{}
		}
	}

	return existingPackages, nil
}

// Download makes a best-effort attempt at downloading previously cached build artifacts
func (rs *GSUtilCache) Download(ctx context.Context, dst cache.LocalCache, pkgs []cache.Package) error {
	fmt.Printf("☁️  downloading %d cached build artifacts\n", len(pkgs))
	var (
		files []string
		dest  string
	)
	for _, pkg := range pkgs {
		fn, exists := dst.Location(pkg)
		if exists {
			continue
		}

		if dest == "" {
			dest = filepath.Dir(fn)
		} else if dest != filepath.Dir(fn) {
			return fmt.Errorf("gsutil only supports one target folder, not %s and %s", dest, filepath.Dir(fn))
		}

		files = append(files, fmt.Sprintf("gs://%s/%s", rs.BucketName, filepath.Base(fn)))
	}
	return gsutilTransfer(dest, files)
}

// Upload makes a best effort to upload the build artifacts to a remote cache
func (rs *GSUtilCache) Upload(ctx context.Context, src cache.LocalCache, pkgs []cache.Package) error {
	fmt.Printf("☁️  uploading build artifacts to remote cache\n")
	var files []string
	for _, pkg := range pkgs {
		file, exists := src.Location(pkg)
		if !exists {
			continue
		}
		files = append(files, file)
	}
	return gsutilTransfer(fmt.Sprintf("gs://%s", rs.BucketName), files)
}

func parseGSUtilStatOutput(reader io.Reader) map[string]struct{} {
	exists := make(map[string]struct{})
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "gs://") {
			url := strings.TrimSuffix(line, ":")
			exists[url] = struct{}{}
			continue
		}
	}
	return exists
}

func gsutilTransfer(target string, files []string) error {
	log.WithField("target", target).WithField("files", files).Debug("Transferring files using gsutil")

	cmd := exec.Command("gsutil", "-m", "cp", "-I", target)
	cmd.Stdout = os.Stdout
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	err = cmd.Start()
	if err != nil {
		return err
	}

	for _, fn := range files {
		_, err = fmt.Fprintln(stdin, fn)
		if err != nil {
			return err
		}
	}
	err = stdin.Close()
	if err != nil {
		return err
	}

	err = cmd.Wait()
	if err != nil {
		if exiterr, ok := err.(*exec.ExitError); ok {
			if _, ok := exiterr.Sys().(syscall.WaitStatus); ok {
				// we just swallow non-zero exit codes here as remote caching is best effort
				return nil
			}
		}

		return err
	}
	return nil
}
