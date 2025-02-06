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
	// S3PartSize is the part size for S3 multipart operations
	S3PartSize = 5 * 1024 * 1024
)

// S3Cache implements RemoteCache using AWS S3
type S3Cache struct {
	storage cache.ObjectStorage
	cfg     *cache.RemoteConfig
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
		storage: storage,
		cfg:     cfg,
	}, nil
}

// ExistingPackages implements RemoteCache
func (s *S3Cache) ExistingPackages(ctx context.Context, pkgs []cache.Package) (map[cache.Package]struct{}, error) {
	result := make(map[cache.Package]struct{})
	var mu sync.Mutex
	wg := sync.WaitGroup{}

	for _, pkg := range pkgs {
		wg.Add(1)
		go func(p cache.Package) {
			defer wg.Done()

			version, err := p.Version()
			if err != nil {
				log.WithError(err).WithField("package", p.FullName()).Debug("failed to get version")
				return
			}

			// Check for .tar.gz first
			gzKey := fmt.Sprintf("%s.tar.gz", version)
			exists, err := s.storage.HasObject(ctx, gzKey)
			if err != nil {
				log.WithError(err).WithField("key", gzKey).Debug("failed to check object")
				return
			}

			if exists {
				mu.Lock()
				result[p] = struct{}{}
				mu.Unlock()
				return
			}

			// Fall back to .tar
			tarKey := fmt.Sprintf("%s.tar", version)
			exists, err = s.storage.HasObject(ctx, tarKey)
			if err != nil {
				log.WithError(err).WithField("key", tarKey).Debug("failed to check object")
				return
			}

			if exists {
				mu.Lock()
				result[p] = struct{}{}
				mu.Unlock()
			}
		}(pkg)
	}

	wg.Wait()
	return result, nil
}

// Download implements RemoteCache
func (s *S3Cache) Download(ctx context.Context, dst cache.LocalCache, pkgs []cache.Package) error {
	var wg sync.WaitGroup

	for _, pkg := range pkgs {
		wg.Add(1)
		go func(p cache.Package) {
			defer wg.Done()

			version, err := p.Version()
			if err != nil {
				log.WithError(err).WithField("package", p.FullName()).Debug("failed to get version")
				return
			}

			// Try downloading .tar.gz first
			gzKey := fmt.Sprintf("%s.tar.gz", version)
			localPath, _ := dst.Location(p)
			if localPath == "" {
				log.WithField("package", p.FullName()).Debug("failed to get local path")
				return
			}

			_, err = s.storage.GetObject(ctx, gzKey, localPath)
			if err != nil {
				// Try .tar if .tar.gz fails
				tarKey := fmt.Sprintf("%s.tar", version)
				_, err = s.storage.GetObject(ctx, tarKey, localPath)
				if err != nil {
					log.WithError(err).WithField("package", p.FullName()).Debug("failed to download")
				}
			}
		}(pkg)
	}

	wg.Wait()
	return nil
}

// Upload implements RemoteCache
func (s *S3Cache) Upload(ctx context.Context, src cache.LocalCache, pkgs []cache.Package) error {
	var wg sync.WaitGroup

	for _, pkg := range pkgs {
		wg.Add(1)
		go func(p cache.Package) {
			defer wg.Done()

			localPath, exists := src.Location(p)
			if !exists {
				log.WithField("package", p.FullName()).Debug("package not found in local cache")
				return
			}

			key := filepath.Base(localPath)
			err := s.storage.UploadObject(ctx, key, localPath)
			if err != nil {
				log.WithError(err).WithField("package", p.FullName()).Debug("failed to upload")
			}
		}(pkg)
	}

	wg.Wait()
	return nil
}

// S3Storage implements ObjectStorage using AWS S3
type S3Storage struct {
	client     *s3.Client
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
		d.PartSize = S3PartSize
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
		u.PartSize = S3PartSize
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
