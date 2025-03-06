package remote

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
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
		log.WithError(err).Error("failed to check existing packages in remote cache")
		// Return partial results even if some checks failed
		return result, err
	}

	return result, nil
}

// Download implements RemoteCache
func (s *S3Cache) Download(ctx context.Context, dst cache.LocalCache, pkgs []cache.Package) error {
	return s.processPackages(ctx, pkgs, func(ctx context.Context, p cache.Package) error {
		version, err := p.Version()
		if err != nil {
			return fmt.Errorf("failed to get version for package %s: %w", p.FullName(), err)
		}

		localPath, exists := dst.Location(p)
		if !exists || localPath == "" {
			return fmt.Errorf("failed to get local path for package %s", p.FullName())
		}

		// Try downloading .tar.gz first
		gzKey := fmt.Sprintf("%s.tar.gz", version)
		_, err = s.storage.GetObject(ctx, gzKey, localPath)
		if err == nil {
			log.WithFields(log.Fields{
				"package": p.FullName(),
				"key":     gzKey,
			}).Debug("successfully downloaded package from remote cache (.tar.gz)")
			return nil
		}
		log.WithFields(log.Fields{
			"package": p.FullName(),
			"key":     gzKey,
			"error":   err,
		}).Debug("failed to download .tar.gz from remote cache, trying .tar")

		// Try .tar if .tar.gz fails
		tarKey := fmt.Sprintf("%s.tar", version)
		_, err = s.storage.GetObject(ctx, tarKey, localPath)
		if err != nil {
			log.WithFields(log.Fields{
				"package": p.FullName(),
				"key":     tarKey,
				"error":   err,
			}).Debug("failed to download package from remote cache, will build locally")
			return fmt.Errorf("failed to download package %s: %w", p.FullName(), err)
		}

		log.WithFields(log.Fields{
			"package": p.FullName(),
			"key":     tarKey,
		}).Debug("successfully downloaded package from remote cache (.tar)")
		return nil
	})
}

// Upload implements RemoteCache
func (s *S3Cache) Upload(ctx context.Context, src cache.LocalCache, pkgs []cache.Package) error {
	return s.processPackages(ctx, pkgs, func(ctx context.Context, p cache.Package) error {
		localPath, exists := src.Location(p)
		if !exists {
			return fmt.Errorf("package %s not found in local cache", p.FullName())
		}

		key := filepath.Base(localPath)
		if err := s.storage.UploadObject(ctx, key, localPath); err != nil {
			return fmt.Errorf("failed to upload package %s: %w", p.FullName(), err)
		}

		return nil
	})
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
	client := s3.NewFromConfig(*cfg)
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
		var nsk *types.NoSuchKey
		if errors.As(err, &nsk) {
			return false, nil
		}
		return false, err
	}

	return true, nil
}

// GetObject implements ObjectStorage
func (s *S3Storage) GetObject(ctx context.Context, key string, dest string) (int64, error) {
	downloader := manager.NewDownloader(s.client, func(d *manager.Downloader) {
		d.PartSize = defaultS3PartSize
	})

	file, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return 0, fmt.Errorf("failed to create destination file: %w", err)
	}
	defer file.Close()

	n, err := downloader.Download(ctx, file, &s3.GetObjectInput{
		Bucket: aws.String(s.bucketName),
		Key:    aws.String(key),
	})
	if err != nil {
		return 0, fmt.Errorf("failed to download object: %w", err)
	}

	return n, nil
}

// UploadObject implements ObjectStorage
func (s *S3Storage) UploadObject(ctx context.Context, key string, src string) error {
	file, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("failed to open source file: %w", err)
	}
	defer file.Close()

	uploader := manager.NewUploader(s.client, func(u *manager.Uploader) {
		u.PartSize = defaultS3PartSize
	})

	_, err = uploader.Upload(ctx, &s3.PutObjectInput{
		Bucket: aws.String(s.bucketName),
		Key:    aws.String(key),
		Body:   file,
	})
	if err != nil {
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
