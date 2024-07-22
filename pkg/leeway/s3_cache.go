package leeway

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	log "github.com/sirupsen/logrus"
)

// S3Config encapsulates the configuration for S3RemoteCache
type S3Config struct {
	BucketName string
	AWSConfig  *aws.Config
}

type S3RemoteCache struct {
	config     S3Config
	s3Client   S3Client
	stsClient  STSClient
	uploader   *manager.Uploader
	downloader *manager.Downloader
}

func NewS3RemoteCache(ctx context.Context, bucketName string, s3Client S3Client, stsClient STSClient) (*S3RemoteCache, error) {
	cache := &S3RemoteCache{
		config: S3Config{
			BucketName: bucketName,
		},
		s3Client:   s3Client,
		stsClient:  stsClient,
		uploader:   manager.NewUploader(s3Client),
		downloader: manager.NewDownloader(s3Client),
	}

	if err := cache.validateConfig(ctx); err != nil {
		return nil, err
	}

	return cache, nil
}

func (rs *S3RemoteCache) validateConfig(ctx context.Context) error {
	identity, err := rs.stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return fmt.Errorf("cannot get AWS caller identity: %w", err)
	}

	log.WithFields(log.Fields{
		"Account": aws.ToString(identity.Account),
		"Arn":     aws.ToString(identity.Arn),
		"Bucket":  rs.config.BucketName,
	}).Debug("Loaded AWS account and S3 configuration")

	return nil
}

// ExistingPackages returns existing cached build artifacts in the remote cache
func (rs *S3RemoteCache) ExistingPackages(ctx context.Context, pkgs []*Package) (map[*Package]struct{}, error) {
	existingPkgs := make(map[*Package]struct{})

	for _, pkg := range pkgs {
		version, err := pkg.Version()
		if err != nil {
			return nil, fmt.Errorf("failed to get version for package %s: %w", pkg.Name, err)
		}

		key := fmt.Sprintf("%s.tar.gz", version)
		_, err = rs.s3Client.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket: aws.String(rs.config.BucketName),
			Key:    aws.String(key),
		})

		if err == nil {
			existingPkgs[pkg] = struct{}{}
		} else if _, ok := err.(*types.NoSuchKey); !ok {
			return nil, fmt.Errorf("failed to check for package %s: %w", pkg.Name, err)
		}
	}

	return existingPkgs, nil
}

// Download makes a best-effort attempt at downloading previously cached build artifacts
func (rs *S3RemoteCache) Download(ctx context.Context, dst Cache, pkgs []*Package) error {
	fmt.Printf("☁️  downloading %d cached build artifacts from s3 remote cache\n", len(pkgs))

	var wg sync.WaitGroup
	errs := make(chan error, len(pkgs))
	semaphore := make(chan struct{}, 10) // Limit concurrent goroutines

	for _, pkg := range pkgs {
		wg.Add(1)
		go func(pkg *Package) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			if err := rs.downloadPackage(context.Background(), dst, pkg); err != nil {
				errs <- err
			}
		}(pkg)
	}

	wg.Wait()
	close(errs)

	var errSlice []error
	for err := range errs {
		errSlice = append(errSlice, err)
	}

	if len(errSlice) > 0 {
		return fmt.Errorf("errors occurred while downloading packages: %v", errSlice)
	}

	return nil
}

func (rs *S3RemoteCache) downloadPackage(ctx context.Context, dst Cache, pkg *Package) error {
	fn, exists := dst.Location(pkg)
	if exists {
		return nil
	}

	key := filepath.Base(fn)
	destPath := filepath.Join(filepath.Dir(fn), key)

	file, err := os.Create(destPath)
	if err != nil {
		return fmt.Errorf("failed to create file for s3 download: %w", err)
	}
	defer file.Close()

	n, err := rs.downloader.Download(ctx, file, &s3.GetObjectInput{
		Bucket: aws.String(rs.config.BucketName),
		Key:    aws.String(key),
	})
	if err != nil {
		return fmt.Errorf("failed to download object from s3: %w", err)
	}

	log.WithFields(log.Fields{
		"key":    key,
		"bucket": rs.config.BucketName,
		"region": rs.config.AWSConfig.Region,
		"bytes":  n,
		"file":   destPath,
	}).Debug("Downloaded object from s3")

	return nil
}

// Upload makes a best effort to upload the build artifacts to a remote cache
func (rs *S3RemoteCache) Upload(ctx context.Context, src Cache, pkgs []*Package) error {
	fmt.Printf("☁️  uploading %d build artifacts to s3 remote cache\n", len(pkgs))

	var wg sync.WaitGroup
	errs := make(chan error, len(pkgs))
	semaphore := make(chan struct{}, 10) // Limit concurrent goroutines

	for _, pkg := range pkgs {
		wg.Add(1)
		go func(pkg *Package) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			if err := rs.uploadPackage(ctx, src, pkg); err != nil {
				errs <- err
			}
		}(pkg)
	}

	wg.Wait()
	close(errs)

	var errSlice []error
	for err := range errs {
		errSlice = append(errSlice, err)
	}

	if len(errSlice) > 0 {
		return fmt.Errorf("errors occurred while uploading packages: %v", errSlice)
	}

	return nil
}

func (rs *S3RemoteCache) uploadPackage(ctx context.Context, src Cache, pkg *Package) error {
	file, exists := src.Location(pkg)
	if !exists {
		return nil
	}

	key := filepath.Base(file)
	f, err := os.Open(file)
	if err != nil {
		return fmt.Errorf("cannot open %s for S3 upload: %w", file, err)
	}
	defer f.Close()

	res, err := rs.uploader.Upload(ctx, &s3.PutObjectInput{
		Bucket: aws.String(rs.config.BucketName),
		Key:    aws.String(key),
		Body:   f,
	})
	if err != nil {
		return fmt.Errorf("failed to upload object to s3: %w", err)
	}

	log.WithFields(log.Fields{
		"key":      key,
		"bucket":   rs.config.BucketName,
		"region":   rs.config.AWSConfig.Region,
		"location": res.Location,
	}).Debug("Uploaded object to s3")

	return nil
}
