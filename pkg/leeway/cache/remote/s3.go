package remote

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	log "github.com/sirupsen/logrus"

	"github.com/gitpod-io/leeway/pkg/leeway/cache"
)

const (
	// defaultS3PartSize is the default part size for S3 multipart operations
	defaultS3PartSize = 5 * 1024 * 1024
	// defaultWorkerCount is the default number of concurrent workers
	defaultWorkerCount = 10
)

// S3Config holds the configuration for S3Cache
type S3Config struct {
	BucketName  string
	Region      string
	PartSize    int64
	WorkerCount int
}

// S3Cache implements RemoteCache using AWS S3
type S3Cache struct {
	storage     cache.ObjectStorage
	cfg         *cache.RemoteConfig
	workerCount int
}

// NewS3Cache creates a new S3 cache implementation
func NewS3Cache(cfg *cache.RemoteConfig) (*S3Cache, error) {
	if cfg.BucketName == "" {
		return nil, fmt.Errorf("bucket name is required")
	}

	awsCfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		return nil, fmt.Errorf("cannot load AWS config: %w", err)
	}

	if cfg.Region != "" {
		awsCfg.Region = cfg.Region
	}

	storage := NewS3Storage(cfg.BucketName, &awsCfg)
	return &S3Cache{
		storage:     storage,
		cfg:         cfg,
		workerCount: defaultWorkerCount,
	}, nil
}

// processPackages processes packages using a worker pool
func (s *S3Cache) processPackages(ctx context.Context, pkgs []cache.Package, fn func(context.Context, cache.Package) error) error {
	jobs := make(chan cache.Package, len(pkgs))
	results := make(chan error, len(pkgs))
	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < s.workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for pkg := range jobs {
				if err := fn(ctx, pkg); err != nil {
					select {
					case results <- fmt.Errorf("failed to process package %s: %w", pkg.FullName(), err):
					case <-ctx.Done():
						return
					}
				}
			}
		}()
	}

	// Send jobs
	for _, pkg := range pkgs {
		select {
		case jobs <- pkg:
		case <-ctx.Done():
			close(jobs)
			return ctx.Err()
		}
	}
	close(jobs)

	// Wait for completion
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect errors
	var errs []error
	for err := range results {
		errs = append(errs, err)
	}

	if len(errs) > 0 {
		// For upload operations, we want to log errors but not fail the entire build
		// This is determined by the caller (Upload vs Download vs ExistingPackages)
		log.WithField("errorCount", len(errs)).Debug("Some packages had errors during processing")
		return fmt.Errorf("multiple errors occurred: %v", errs)
	}

	return nil
}

// ExistingPackages implements RemoteCache
func (s *S3Cache) ExistingPackages(ctx context.Context, pkgs []cache.Package) (map[cache.Package]struct{}, error) {
	result := make(map[cache.Package]struct{})
	var mu sync.Mutex

	err := s.processPackages(ctx, pkgs, func(ctx context.Context, p cache.Package) error {
		version, err := p.Version()
		if err != nil {
			return fmt.Errorf("failed to get version: %w", err)
		}

		// Try .tar.gz first
		gzKey := fmt.Sprintf("%s.tar.gz", version)
		exists, err := s.storage.HasObject(ctx, gzKey)
		if err != nil {
			log.WithFields(log.Fields{
				"package": p.FullName(),
				"key":     gzKey,
				"error":   err,
			}).Debug("failed to check .tar.gz in remote cache, will try .tar")
			// Continue to check .tar format - don't return error here
		} else if exists {
			log.WithFields(log.Fields{
				"package": p.FullName(),
				"key":     gzKey,
			}).Debug("found package in remote cache (.tar.gz)")
			mu.Lock()
			result[p] = struct{}{}
			mu.Unlock()
			return nil
		}

		// Fall back to .tar if .tar.gz doesn't exist or had error
		tarKey := fmt.Sprintf("%s.tar", version)
		exists, err = s.storage.HasObject(ctx, tarKey)
		if err != nil {
			log.WithFields(log.Fields{
				"package": p.FullName(),
				"key":     tarKey,
				"error":   err,
			}).Debug("failed to check .tar in remote cache")
			// Don't return error for missing objects - this is expected
			return nil // Continue with next package, will trigger local build
		}

		if exists {
			log.WithFields(log.Fields{
				"package": p.FullName(),
				"key":     tarKey,
			}).Debug("found package in remote cache (.tar)")
			mu.Lock()
			result[p] = struct{}{}
			mu.Unlock()
		} else {
			log.WithFields(log.Fields{
				"package": p.FullName(),
				"version": version,
			}).Debug("package not found in remote cache, will build locally")
		}

		return nil
	})

	if err != nil {
		log.WithError(err).Warn("failed to check existing packages in remote cache")
		// Return partial results even if some checks failed
		return result, nil
	}

	return result, nil
}

// withRetry attempts an operation with retries and exponential backoff
func withRetry(maxRetries int, operation func() error) error {
	var err error
	for i := 0; i < maxRetries; i++ {
		err = operation()
		if err == nil {
			return nil
		}

		// Don't retry if the object doesn't exist
		if strings.Contains(err.Error(), "NotFound") || strings.Contains(err.Error(), "404") {
			return err
		}

		log.WithError(err).WithField("retry", i+1).Debug("Operation failed, retrying...")
		// Exponential backoff with jitter
		sleepTime := time.Duration(50*(i+1)*int(1+rand.Intn(10))) * time.Millisecond
		time.Sleep(sleepTime)
	}
	return fmt.Errorf("operation failed after %d retries: %w", maxRetries, err)
}

// Download implements RemoteCache
func (s *S3Cache) Download(ctx context.Context, dst cache.LocalCache, pkgs []cache.Package) error {
	var multiErr []error

	err := s.processPackages(ctx, pkgs, func(ctx context.Context, p cache.Package) error {
		version, err := p.Version()
		if err != nil {
			log.WithError(err).WithField("package", p.FullName()).Warn("Failed to get version for package, skipping")
			return nil // Skip but don't fail everything
		}

		localPath, exists := dst.Location(p)
		if exists {
			log.WithField("package", p.FullName()).Debug("Package already exists in local cache, skipping download")
			return nil
		}

		if localPath == "" {
			log.WithField("package", p.FullName()).Warn("Failed to get local path for package, skipping download")
			return nil // Skip but don't fail everything
		}

		// Ensure parent directory exists
		if err := os.MkdirAll(filepath.Dir(localPath), 0755); err != nil {
			log.WithError(err).WithFields(log.Fields{
				"package": p.FullName(),
				"dir":     filepath.Dir(localPath),
			}).Warn("Failed to create directory for package, skipping download")
			return nil
		}

		// Try downloading .tar.gz first with retry
		gzKey := fmt.Sprintf("%s.tar.gz", version)
		gzErr := withRetry(3, func() error {
			_, err := s.storage.GetObject(ctx, gzKey, localPath)
			return err
		})

		if gzErr == nil {
			log.WithFields(log.Fields{
				"package": p.FullName(),
				"key":     gzKey,
				"path":    localPath,
			}).Debug("Successfully downloaded package from remote cache (.tar.gz)")
			return nil
		}

		// Check if this is a "not found" error
		if strings.Contains(gzErr.Error(), "NotFound") || strings.Contains(gzErr.Error(), "404") {
			log.WithFields(log.Fields{
				"package": p.FullName(),
				"key":     gzKey,
			}).Debug("Package not found in remote cache (.tar.gz), trying .tar")
		} else {
			log.WithFields(log.Fields{
				"package": p.FullName(),
				"key":     gzKey,
				"error":   gzErr,
			}).Debug("Failed to download .tar.gz from remote cache, trying .tar")
		}

		// Try .tar if .tar.gz fails, also with retry
		tarKey := fmt.Sprintf("%s.tar", version)
		tarErr := withRetry(3, func() error {
			_, err := s.storage.GetObject(ctx, tarKey, localPath)
			return err
		})

		if tarErr != nil {
			// Check if this is a "not found" error
			if strings.Contains(tarErr.Error(), "NotFound") || strings.Contains(tarErr.Error(), "404") {
				log.WithFields(log.Fields{
					"package": p.FullName(),
					"key":     tarKey,
				}).Debug("Package not found in remote cache (.tar), will build locally")
				return nil // Not an error, just not found
			}

			log.WithFields(log.Fields{
				"package": p.FullName(),
				"key":     tarKey,
				"error":   tarErr,
			}).Debug("Failed to download package from remote cache, will build locally")
			return nil // Continue with local build
		}

		log.WithFields(log.Fields{
			"package": p.FullName(),
			"key":     tarKey,
			"path":    localPath,
		}).Debug("Successfully downloaded package from remote cache (.tar)")
		return nil
	})

	if err != nil {
		log.WithError(err).Warn("Errors occurred during download from remote cache, continuing with local builds")
		multiErr = append(multiErr, err)
	}

	// Even if there were errors with some packages, don't fail the entire build
	// Just log warnings and continue with local builds for those packages
	if len(multiErr) > 0 {
		log.WithField("errors", len(multiErr)).Warn("Some packages could not be downloaded, falling back to local builds")
		// Return nil instead of the error to allow the build to continue with local builds
		return nil
	}

	return nil
}

// Upload implements RemoteCache
func (s *S3Cache) Upload(ctx context.Context, src cache.LocalCache, pkgs []cache.Package) error {
	var uploadErrors []error

	err := s.processPackages(ctx, pkgs, func(ctx context.Context, p cache.Package) error {
		localPath, exists := src.Location(p)
		if !exists {
			log.WithField("package", p.FullName()).Warn("package not found in local cache - skipping upload")
			return nil // Skip but don't fail everything
		}

		key := filepath.Base(localPath)
		if err := s.storage.UploadObject(ctx, key, localPath); err != nil {
			log.WithError(err).WithFields(log.Fields{
				"package": p.FullName(),
				"key":     key,
			}).Warn("failed to upload package to remote cache - continuing")
			uploadErrors = append(uploadErrors, fmt.Errorf("package %s: %w", p.FullName(), err))
			return nil // Don't fail the entire operation
		}

		log.WithFields(log.Fields{
			"package": p.FullName(),
			"key":     key,
		}).Debug("successfully uploaded package to remote cache")
		return nil
	})

	if err != nil {
		log.WithError(err).Warn("errors occurred during upload to remote cache - continuing")
		// Don't return the error to allow the build to continue
	}

	if len(uploadErrors) > 0 {
		log.WithField("errorCount", len(uploadErrors)).Warn("some packages failed to upload to remote cache - continuing with build")
	}

	return nil // Always return nil to allow the build to continue
}

// s3ClientAPI is a subset of the S3 client interface we need
type s3ClientAPI interface {
	HeadObject(ctx context.Context, params *s3.HeadObjectInput, optFns ...func(*s3.Options)) (*s3.HeadObjectOutput, error)
	GetObject(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error)
	PutObject(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error)
	AbortMultipartUpload(ctx context.Context, params *s3.AbortMultipartUploadInput, optFns ...func(*s3.Options)) (*s3.AbortMultipartUploadOutput, error)
	CompleteMultipartUpload(ctx context.Context, params *s3.CompleteMultipartUploadInput, optFns ...func(*s3.Options)) (*s3.CompleteMultipartUploadOutput, error)
	CreateMultipartUpload(ctx context.Context, params *s3.CreateMultipartUploadInput, optFns ...func(*s3.Options)) (*s3.CreateMultipartUploadOutput, error)
	UploadPart(ctx context.Context, params *s3.UploadPartInput, optFns ...func(*s3.Options)) (*s3.UploadPartOutput, error)
	ListObjectsV2(ctx context.Context, params *s3.ListObjectsV2Input, optFns ...func(*s3.Options)) (*s3.ListObjectsV2Output, error)
}

// S3Storage implements ObjectStorage using AWS S3
type S3Storage struct {
	client     s3ClientAPI
	bucketName string
}

// NewS3Storage creates a new S3 storage implementation
func NewS3Storage(bucketName string, cfg *aws.Config) *S3Storage {
	client := s3.NewFromConfig(*cfg, func(o *s3.Options) {
		o.DisableLogOutputChecksumValidationSkipped = true
	})
	return &S3Storage{
		client:     client,
		bucketName: bucketName,
	}
}

// HasObject implements ObjectStorage
func (s *S3Storage) HasObject(ctx context.Context, key string) (bool, error) {
	_, err := s.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(s.bucketName),
		Key:    aws.String(key),
	})

	if err != nil {
		// Check for various "not found" error types
		var nsk *types.NoSuchKey
		if errors.As(err, &nsk) {
			return false, nil
		}

		// Also handle 404 NotFound errors which might not be properly wrapped as NoSuchKey
		if strings.Contains(err.Error(), "NotFound") || strings.Contains(err.Error(), "404") {
			return false, nil
		}

		return false, err
	}

	return true, nil
}

// ValidateObject checks if a downloaded object exists and has a valid size
func (s *S3Storage) ValidateObject(ctx context.Context, key, localPath string) error {
	// Check if the file exists
	info, err := os.Stat(localPath)
	if err != nil {
		return fmt.Errorf("downloaded file not found: %w", err)
	}

	// If the file size is 0, the download likely failed
	if info.Size() == 0 {
		return fmt.Errorf("downloaded file is empty")
	}

	log.WithFields(log.Fields{
		"path": localPath,
		"size": info.Size(),
	}).Debug("Validated downloaded file")

	return nil
}

// GetObject implements ObjectStorage
func (s *S3Storage) GetObject(ctx context.Context, key string, dest string) (int64, error) {
	downloader := manager.NewDownloader(s.client, func(d *manager.Downloader) {
		d.PartSize = defaultS3PartSize
	})

	// Ensure parent directory exists
	if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
		return 0, fmt.Errorf("failed to create parent directory: %w", err)
	}

	file, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return 0, fmt.Errorf("failed to create destination file: %w", err)
	}
	defer file.Close()

	// Set up cleanup in case of error
	var downloadErr error
	defer func() {
		if downloadErr != nil {
			os.Remove(dest)
		}
	}()

	input := &s3.GetObjectInput{
		Bucket: aws.String(s.bucketName),
		Key:    aws.String(key),
	}

	n, downloadErr := downloader.Download(ctx, file, input)
	if downloadErr != nil {
		// Check for various "not found" error types
		var nsk *types.NoSuchKey
		if errors.As(downloadErr, &nsk) {
			return 0, fmt.Errorf("object not found: %w", downloadErr)
		}

		// Also handle 404 NotFound errors which might not be properly wrapped
		if strings.Contains(downloadErr.Error(), "NotFound") || strings.Contains(downloadErr.Error(), "404") {
			return 0, fmt.Errorf("object not found: %w", downloadErr)
		}

		return 0, fmt.Errorf("failed to download object: %w", downloadErr)
	}

	// Validate the downloaded file
	if err := s.ValidateObject(ctx, key, dest); err != nil {
		downloadErr = err
		return 0, fmt.Errorf("downloaded object validation failed: %w", err)
	}

	return n, nil
}

// UploadObject implements ObjectStorage
func (s *S3Storage) UploadObject(ctx context.Context, key string, src string) error {
	file, err := os.Open(src)
	if err != nil {
		log.WithError(err).WithField("key", key).Warn("failed to open source file for upload")
		return fmt.Errorf("failed to open source file: %w", err)
	}
	defer file.Close()

	uploader := manager.NewUploader(s.client, func(u *manager.Uploader) {
		u.PartSize = defaultS3PartSize
	})

	input := &s3.PutObjectInput{
		Bucket: aws.String(s.bucketName),
		Key:    aws.String(key),
		Body:   file,
	}

	_, err = uploader.Upload(ctx, input)
	if err != nil {
		var apiErr smithy.APIError
		if errors.As(err, &apiErr) {
			if apiErr.ErrorCode() == "Forbidden" {
				log.WithError(err).Warnf("permission denied while uploading object %s to S3 - continuing", key)
				return nil
			}
			// Handle other API errors as warnings too
			log.WithError(err).WithFields(log.Fields{
				"key":       key,
				"errorCode": apiErr.ErrorCode(),
			}).Warn("S3 API error while uploading object - continuing")
			return fmt.Errorf("S3 API error: %w", err)
		}
		// Handle non-API errors
		log.WithError(err).WithField("key", key).Warn("failed to upload object - continuing")
		return fmt.Errorf("failed to upload object: %w", err)
	}

	return nil
}

// ListObjects implements ObjectStorage
func (s *S3Storage) ListObjects(ctx context.Context, prefix string) ([]string, error) {
	var result []string
	paginator := s3.NewListObjectsV2Paginator(s.client, &s3.ListObjectsV2Input{
		Bucket: aws.String(s.bucketName),
		Prefix: aws.String(prefix),
	})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list objects: %w", err)
		}

		for _, obj := range page.Contents {
			result = append(result, *obj.Key)
		}
	}

	return result, nil
}
