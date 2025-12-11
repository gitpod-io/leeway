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

// Download makes a best-effort attempt at downloading previously cached build artifacts.
// Returns detailed results for each package to enable smarter retry decisions.
func (rs *GSUtilCache) Download(ctx context.Context, dst cache.LocalCache, pkgs []cache.Package) map[string]cache.DownloadResult {
	results := make(map[string]cache.DownloadResult)
	fmt.Printf("☁️  downloading %d cached build artifacts\n", len(pkgs))

	var (
		files []string
		dest  string
	)
	type urlPair struct {
		gzURL  string
		tarURL string
	}

	// Create a list of all possible URLs
	var urls []string
	packageToURLMap := make(map[cache.Package]urlPair)
	for _, pkg := range pkgs {
		fn, exists := dst.Location(pkg)
		if exists {
			results[pkg.FullName()] = cache.DownloadResult{Status: cache.DownloadStatusSkipped}
			continue
		}
		version, err := pkg.Version()
		if err != nil {
			log.WithError(err).WithField("package", pkg.FullName()).Warn("Failed to get version for package, skipping")
			results[pkg.FullName()] = cache.DownloadResult{Status: cache.DownloadStatusFailed, Err: err}
			continue
		}
		if dest == "" {
			dest = filepath.Dir(fn)
		} else if dest != filepath.Dir(fn) {
			err := fmt.Errorf("gsutil only supports one target folder, not %s and %s", dest, filepath.Dir(fn))
			results[pkg.FullName()] = cache.DownloadResult{Status: cache.DownloadStatusFailed, Err: err}
			continue
		}

		pair := urlPair{
			gzURL:  fmt.Sprintf("gs://%s/%s.tar.gz", rs.BucketName, version),
			tarURL: fmt.Sprintf("gs://%s/%s.tar", rs.BucketName, version),
		}
		packageToURLMap[pkg] = pair
		urls = append(urls, pair.gzURL, pair.tarURL)
	}
	if len(urls) == 0 {
		return results
	}

	args := append([]string{"stat"}, urls...)
	cmd := exec.Command("gsutil", args...)

	var stdoutBuffer, stderrBuffer strings.Builder
	cmd.Stdout = &stdoutBuffer
	cmd.Stderr = &stderrBuffer

	err := cmd.Run()
	if err != nil && (!strings.Contains(stderrBuffer.String(), "No URLs matched")) {
		log.Debugf("gsutil stat returned non-zero exit code: [%v], stderr: [%v]", err, stderrBuffer.String())
		// Mark all pending packages as failed
		for pkg := range packageToURLMap {
			if _, exists := results[pkg.FullName()]; !exists {
				results[pkg.FullName()] = cache.DownloadResult{Status: cache.DownloadStatusFailed, Err: err}
			}
		}
		return results
	}

	existingURLs := parseGSUtilStatOutput(strings.NewReader(stdoutBuffer.String()))
	packagesToDownload := make(map[cache.Package]bool)
	for pkg, urls := range packageToURLMap {
		if _, exists := existingURLs[urls.gzURL]; exists {
			files = append(files, urls.gzURL)
			packagesToDownload[pkg] = true
			continue
		}
		if _, exists := existingURLs[urls.tarURL]; exists {
			files = append(files, urls.tarURL)
			packagesToDownload[pkg] = true
			continue
		}
		// Package not found in remote cache
		results[pkg.FullName()] = cache.DownloadResult{Status: cache.DownloadStatusNotFound}
	}

	if len(files) > 0 {
		transferErr := gsutilTransfer(dest, files)
		for pkg := range packagesToDownload {
			if transferErr != nil {
				results[pkg.FullName()] = cache.DownloadResult{Status: cache.DownloadStatusFailed, Err: transferErr}
			} else {
				// Verify the file was actually downloaded
				if _, exists := dst.Location(pkg); exists {
					results[pkg.FullName()] = cache.DownloadResult{Status: cache.DownloadStatusSuccess}
				} else {
					results[pkg.FullName()] = cache.DownloadResult{Status: cache.DownloadStatusFailed, Err: fmt.Errorf("file not found after transfer")}
				}
			}
		}
	}

	return results
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

// UploadFile uploads a single file to the remote cache with the given key
func (rs *GSUtilCache) UploadFile(ctx context.Context, filePath string, key string) error {
	target := fmt.Sprintf("gs://%s/%s", rs.BucketName, key)
	log.WithFields(log.Fields{
		"file":   filePath,
		"target": target,
	}).Debug("Uploading file using gsutil")

	cmd := exec.CommandContext(ctx, "gsutil", "cp", filePath, target)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to upload file %s to %s: %w", filePath, target, err)
	}

	return nil
}

// HasFile checks if a file exists in the remote cache with the given key
func (rs *GSUtilCache) HasFile(ctx context.Context, key string) (bool, error) {
	target := fmt.Sprintf("gs://%s/%s", rs.BucketName, key)

	cmd := exec.CommandContext(ctx, "gsutil", "stat", target)
	if err := cmd.Run(); err != nil {
		// gsutil stat returns non-zero exit code if file doesn't exist
		if exitErr, ok := err.(*exec.ExitError); ok {
			if status, ok := exitErr.Sys().(syscall.WaitStatus); ok {
				if status.ExitStatus() == 1 {
					// File doesn't exist
					return false, nil
				}
			}
		}
		return false, fmt.Errorf("failed to check if file exists at %s: %w", target, err)
	}

	return true, nil
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
