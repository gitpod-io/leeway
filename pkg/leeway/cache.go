package leeway

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	log "github.com/sirupsen/logrus"
	"golang.org/x/xerrors"
)

// Cache provides filesystem locations for package build artifacts.
type Cache interface {
	// Location returns the absolute filesystem path for a package build artifact
	Location(pkg *Package) (path string, exists bool)
}

// NewFilesystemCache creates a new filesystem cache
func NewFilesystemCache(location string) (*FilesystemCache, error) {
	err := os.MkdirAll(location, 0755)
	if err != nil {
		return nil, err
	}

	return &FilesystemCache{location}, nil
}

// FilesystemCache implements a flat folder cache
type FilesystemCache struct {
	Origin string
}

// Location computes the name of a packages build result artifact.
// Returns ok == true if that build artifact actually exists.
func (fsc *FilesystemCache) Location(pkg *Package) (path string, exists bool) {
	version, err := pkg.Version()
	if err != nil {
		return "", false
	}

	fn := filepath.Join(fsc.Origin, fmt.Sprintf("%s.tar.gz", version))
	if _, err := os.Stat(fn); os.IsNotExist(err) {
		return fn, false
	}

	return fn, true
}

// RemoteCache can download and upload build artifacts into a local cache
type RemoteCache interface {
	// ExistingPackages returns existing cached build artifacts in the remote cache
	ExistingPackages(pkgs []*Package) (map[*Package]struct{}, error)

	// Download makes a best-effort attempt at downloading previously cached build artifacts for the given packages
	// in their current version. A cache miss (i.e. a build artifact not being available) does not constitute an
	// error. Get should try and download as many artifacts as possible.
	Download(dst Cache, pkgs []*Package) error

	// Upload makes a best effort to upload the build arfitacts to a remote cache. If uploading an artifact fails, that
	// does not constitute an error.
	Upload(src Cache, pkgs []*Package) error
}

// NoRemoteCache implements the default no-remote cache behavior
type NoRemoteCache struct{}

// ExistingPackages returns existing cached build artifacts in the remote cache
func (NoRemoteCache) ExistingPackages(pkgs []*Package) (map[*Package]struct{}, error) {
	return map[*Package]struct{}{}, nil
}

// Download makes a best-effort attempt at downloading previously cached build artifacts
func (NoRemoteCache) Download(dst Cache, pkgs []*Package) error {
	return nil
}

// Upload makes a best effort to upload the build arfitacts to a remote cache
func (NoRemoteCache) Upload(src Cache, pkgs []*Package) error {
	return nil
}

// GSUtilRemoteCache uses the gsutil command to implement a remote cache
type GSUtilRemoteCache struct {
	BucketName string
}

// ExistingPackages returns existing cached build artifacts in the remote cache
func (rs GSUtilRemoteCache) ExistingPackages(pkgs []*Package) (map[*Package]struct{}, error) {
	fmt.Printf("☁️  checking remote cache for past build artifacts for %d packages\n", len(pkgs))

	packageToURLMap := make(map[*Package]string)
	for _, p := range pkgs {
		version, err := p.Version()
		if err != nil {
			log.WithField("package", p.FullName()).Debug("Failed to get version for package. Will not check remote cache for package.")
			continue
		}

		url := fmt.Sprintf("gs://%s/%s", rs.BucketName, fmt.Sprintf("%s.tar.gz", version))
		packageToURLMap[p] = url
	}

	urls := make([]string, 0, len(packageToURLMap))
	for _, url := range packageToURLMap {
		urls = append(urls, url)
	}

	if len(urls) == 0 {
		return map[*Package]struct{}{}, nil
	}

	log.Debugf("Checking if %d packages exist in the remote cache using gsutil", len(urls))
	args := append([]string{"stat"}, urls...)
	cmd := exec.Command("gsutil", args...)

	var stdoutBuffer, stderrBuffer bytes.Buffer
	cmd.Stdout = &stdoutBuffer
	cmd.Stderr = &stderrBuffer

	err := cmd.Run()
	if err != nil && (!strings.Contains(stderrBuffer.String(), "No URLs matched")) {
		log.Debugf("gsutil stat returned non-zero exit code: [%v], stderr: [%v]", err, stderrBuffer.String())
		return map[*Package]struct{}{}, nil
	}

	existingURLs := parseGSUtilStatOutput(bytes.NewReader(stdoutBuffer.Bytes()))
	existingPackages := make(map[*Package]struct{})
	for _, p := range pkgs {
		url := packageToURLMap[p]
		if _, exists := existingURLs[url]; exists {
			existingPackages[p] = struct{}{}
		}
	}

	return existingPackages, nil
}

// Download makes a best-effort attempt at downloading previously cached build artifacts
func (rs GSUtilRemoteCache) Download(dst Cache, pkgs []*Package) error {
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
			return xerrors.Errorf("gsutil only supports one target folder, not %s and %s", dest, filepath.Dir(fn))
		}

		files = append(files, fmt.Sprintf("gs://%s/%s", rs.BucketName, filepath.Base(fn)))
	}
	return gsutilTransfer(dest, files)
}

// Upload makes a best effort to upload the build arfitacts to a remote cache
func (rs GSUtilRemoteCache) Upload(src Cache, pkgs []*Package) error {
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

// S3RemoteCache uses the AWS Go SDK to implement a remote cache
type S3RemoteCache struct {
	BucketName string
	s3Config   *aws.Config
	s3Client   *s3.Client
}

func NewS3RemoteCache(bucketName string, cfg *aws.Config) (*S3RemoteCache, error) {
	if cfg == nil {
		v, err := config.LoadDefaultConfig(context.TODO())
		cfg = &v
		if err != nil {
			return nil, fmt.Errorf("cannot load s3 config: %s", err)
		}
	}
	s3Client := s3.NewFromConfig(*cfg)

	log.DebugFn(func() []interface{} {
		stsClient := sts.NewFromConfig(*cfg)
		identity, err := stsClient.GetCallerIdentity(context.TODO(), &sts.GetCallerIdentityInput{})
		if err != nil {
			log.Warnf("Cannot get AWS caller identity: %s", err)
			return nil
		}

		log.WithFields(log.Fields{
			"Account": aws.ToString(identity.Account),
			"Arn":     aws.ToString(identity.Arn),
			"Region":  cfg.Region,
		}).Debug("Loaded AWS account")

		return nil
	})

	return &S3RemoteCache{bucketName, cfg, s3Client}, nil
}

// ExistingPackages returns existing cached build artifacts in the remote cache
func (rs *S3RemoteCache) ExistingPackages(pkgs []*Package) (map[*Package]struct{}, error) {
	packagesToKeys := make(map[*Package]string)
	for _, p := range pkgs {
		version, err := p.Version()
		if err != nil {
			log.WithField("package", p.FullName()).Debug("Failed to get version for package. Will not check remote cache for package.")
			continue
		}

		packagesToKeys[p] = fmt.Sprintf("%s.tar.gz", version)
	}

	if len(packagesToKeys) == 0 {
		return map[*Package]struct{}{}, nil
	}
	log.Debugf("Checking if %d packages exist in the remote cache using s3", len(packagesToKeys))

	ch := make(chan *Package, len(packagesToKeys))
	defer close(ch)

	existingPackages := make(map[*Package]struct{})
	wg := sync.WaitGroup{}

	for pkg, key := range packagesToKeys {
		go func(pkg *Package, key string) {
			defer wg.Done()

			stat, _ := rs.hasObject(context.TODO(), key)
			// TODO error handling
			if stat {
				ch <- pkg
			}
		}(pkg, key)

		wg.Add(1)
	}
	wg.Wait()

	return existingPackages, nil
}

// Download makes a best-effort attempt at downloading previously cached build artifacts for the given packages
// in their current version. A cache miss (i.e. a build artifact not being available) does not constitute an
// error. Get should try and download as many artifacts as possible.
func (s3 *S3RemoteCache) Download(dst Cache, pkgs []*Package) error {
	panic("not implemented") // TODO: Implement
}

// Upload makes a best effort to upload the build arfitacts to a remote cache. If uploading an artifact fails, that
// does not constitute an error.
func (s3 *S3RemoteCache) Upload(src Cache, pkgs []*Package) error {
	panic("not implemented") // TODO: Implement
}

func (rs *S3RemoteCache) hasBucket(ctx context.Context) (bool, error) {
	cfg := *rs.s3Config
	fields := log.Fields{
		"bucket": rs.BucketName,
		"region": cfg.Region,
	}
	log.WithFields(fields).Debugf("Checking s3 for cache bucket")

	_, err := rs.s3Client.HeadBucket(ctx, &s3.HeadBucketInput{
		Bucket: aws.String(rs.BucketName),
	})

	if err != nil {
		var nsk *types.NoSuchBucket
		if errors.As(err, &nsk) {
			return false, nil
		}
		log.WithFields(fields).Errorf("Failed to get bucket: %s", err)
		return false, err
	}
	return true, nil
}

func (rs *S3RemoteCache) hasObject(ctx context.Context, key string) (bool, error) {
	cfg := *rs.s3Config
	fields := log.Fields{
		"key":    key,
		"bucket": rs.BucketName,
		"region": cfg.Region,
	}
	log.WithFields(fields).Debugf("Checking s3 for cached package")

	_, err := rs.s3Client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(rs.BucketName),
		Key:    aws.String(key),
		Range:  aws.String("bytes=0-0"),
	})

	if err != nil {
		var nsk *types.NoSuchKey
		if errors.As(err, &nsk) {
			return false, nil
		}

		// We've received an error that's not a simple missing key error. Collect more information
		_, _ = rs.hasBucket(ctx)

		log.WithFields(fields).Warnf("S3 GetObject failed: %s", err)
		return false, err
	}

	// XXX
	return true, nil
}
