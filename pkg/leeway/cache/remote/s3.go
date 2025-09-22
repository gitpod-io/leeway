package remote

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
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
	"golang.org/x/time/rate"

	"github.com/gitpod-io/leeway/pkg/leeway/cache"
	"github.com/gitpod-io/leeway/pkg/leeway/cache/slsa"
)

const (
	// defaultS3PartSize is the default part size for S3 multipart operations
	defaultS3PartSize = 5 * 1024 * 1024
	// defaultWorkerCount is the default number of concurrent workers
	defaultWorkerCount = 10
	// defaultRateLimit is the default rate limit for S3 API calls (requests per second)
	defaultRateLimit = 100
	// defaultBurstLimit is the default burst limit for S3 API calls
	defaultBurstLimit = 200
	// maxConcurrentOperations is the maximum number of concurrent goroutines for parallel operations
	maxConcurrentOperations = 50
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
	storage      cache.ObjectStorage
	cfg          *cache.RemoteConfig
	workerCount  int
	slsaVerifier slsa.VerifierInterface
	cleanupMu    sync.Mutex // Protects concurrent file cleanup operations
	rateLimiter  *rate.Limiter // Rate limiter for S3 API calls
	semaphore    chan struct{} // Semaphore for limiting concurrent operations
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
	
	// Initialize SLSA verifier if enabled
	var slsaVerifier slsa.VerifierInterface
	if cfg.SLSAVerification && cfg.SourceURI != "" {
		slsaVerifier = slsa.NewVerifier(cfg.SourceURI, cfg.TrustedRoots)
		log.WithFields(log.Fields{
			"sourceURI":    cfg.SourceURI,
			"trustedRoots": len(cfg.TrustedRoots),
		}).Debug("SLSA verification enabled for cache")
	}
	
	// Initialize rate limiter with default limits
	rateLimiter := rate.NewLimiter(rate.Limit(defaultRateLimit), defaultBurstLimit)
	
	// Initialize semaphore for goroutine limiting
	semaphore := make(chan struct{}, maxConcurrentOperations)
	
	return &S3Cache{
		storage:      storage,
		cfg:          cfg,
		workerCount:  defaultWorkerCount,
		slsaVerifier: slsaVerifier,
		rateLimiter:  rateLimiter,
		semaphore:    semaphore,
	}, nil
}

// waitForRateLimit waits for rate limiter permission before making S3 API calls
func (s *S3Cache) waitForRateLimit(ctx context.Context) error {
	return s.rateLimiter.Wait(ctx)
}

// acquireSemaphore acquires a semaphore slot to limit concurrent operations
func (s *S3Cache) acquireSemaphore(ctx context.Context) error {
	select {
	case s.semaphore <- struct{}{}:
		// Log when approaching capacity
		if len(s.semaphore) > maxConcurrentOperations*8/10 { // 80% capacity
			log.WithField("active_operations", len(s.semaphore)).Debug("High goroutine usage in S3 cache")
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// releaseSemaphore releases a semaphore slot
func (s *S3Cache) releaseSemaphore() {
	select {
	case <-s.semaphore:
	default:
		// Should not happen, but protect against panic
	}
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
		// Wait for rate limiter permission
		if err := s.waitForRateLimit(ctx); err != nil {
			log.WithError(err).Debug("Rate limiter error during .tar.gz check")
			// Continue to .tar check even if rate limited
		}
		
		timeoutCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		exists, err := s.storage.HasObject(timeoutCtx, gzKey)
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
		// Wait for rate limiter permission
		if err := s.waitForRateLimit(ctx); err != nil {
			log.WithError(err).Debug("Rate limiter error during .tar check")
		}
		
		timeoutCtx2, cancel2 := context.WithTimeout(ctx, 30*time.Second)
		defer cancel2()
		exists, err = s.storage.HasObject(timeoutCtx2, tarKey)
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

		// Branch based on SLSA verification configuration
		if s.slsaVerifier != nil && s.cfg.SLSAVerification {
			return s.downloadWithSLSAVerification(ctx, p, version, localPath)
		} else {
			return s.downloadOriginal(ctx, p, version, localPath)
		}
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

// downloadOriginal preserves the original download behavior when SLSA verification is disabled
func (s *S3Cache) downloadOriginal(ctx context.Context, p cache.Package, version, localPath string) error {
	// Try downloading .tar.gz first with retry
	gzKey := fmt.Sprintf("%s.tar.gz", version)
	gzErr := withRetry(3, func() error {
		// Wait for rate limiter permission
		if err := s.waitForRateLimit(ctx); err != nil {
			return err
		}
		
		timeoutCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()
		_, err := s.storage.GetObject(timeoutCtx, gzKey, localPath)
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
		// Wait for rate limiter permission
		if err := s.waitForRateLimit(ctx); err != nil {
			return err
		}
		
		timeoutCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()
		_, err := s.storage.GetObject(timeoutCtx, tarKey, localPath)
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
}

// downloadWithSLSAVerification downloads and verifies artifacts using SLSA attestations
func (s *S3Cache) downloadWithSLSAVerification(ctx context.Context, p cache.Package, version, localPath string) error {
	log.WithFields(log.Fields{
		"package": p.FullName(),
		"version": version,
	}).Debug("Starting SLSA-verified download")

	// Try both .tar.gz and .tar with their attestations
	downloadAttempts := []struct {
		extension string
		priority  int
	}{
		{".tar.gz", 1},
		{".tar", 2},
	}

	for _, attempt := range downloadAttempts {
		artifactKey := fmt.Sprintf("%s%s", version, attempt.extension)
		attestationKey := slsa.AttestationKey(artifactKey)

		log.WithFields(log.Fields{
			"package":     p.FullName(),
			"artifact":    artifactKey,
			"attestation": attestationKey,
		}).Debug("Attempting SLSA-verified download")

		// Step 1: Check if both artifact and attestation exist (with context-aware parallel checks)
		artifactExists, attestationExists, err := s.checkBothExist(ctx, artifactKey, attestationKey)
		if err != nil {
			log.WithError(err).Debug("Failed to check object existence")
			continue
		}

		// Step 2: Handle missing attestation based on configuration
		if !attestationExists {
			if s.cfg.RequireAttestation {
				log.WithFields(log.Fields{
					"package":     p.FullName(),
					"attestation": attestationKey,
				}).Debug("Required attestation missing, skipping this attempt")
				continue
			} else {
				log.WithFields(log.Fields{
					"package":     p.FullName(),
					"attestation": attestationKey,
				}).Warn("Attestation missing but not required, downloading without verification")
				return s.downloadUnverified(ctx, p, version, localPath, attempt.extension)
			}
		}

		if !artifactExists {
			log.WithFields(log.Fields{
				"package": p.FullName(),
				"key":     artifactKey,
			}).Debug("Artifact not found, trying next option")
			continue
		}

		// Step 3: Download both artifact and attestation in parallel with context awareness
		tmpArtifactPath := localPath + ".tmp"
		tmpAttestationPath := localPath + ".att.tmp"

		downloadStart := time.Now()
		artifactErr, attestationErr := s.downloadBothParallel(ctx, artifactKey, attestationKey, tmpArtifactPath, tmpAttestationPath)

		if artifactErr != nil {
			log.WithError(artifactErr).WithField("key", artifactKey).Debug("Failed to download artifact")
			s.cleanupTempFiles(tmpArtifactPath, tmpAttestationPath)
			continue
		}

		if attestationErr != nil {
			log.WithError(attestationErr).WithField("key", attestationKey).Debug("Failed to download attestation")
			s.cleanupTempFiles(tmpArtifactPath, tmpAttestationPath)
			continue
		}

		// Step 4: Verify the artifact against attestation
		verifyStart := time.Now()
		verifyErr := s.slsaVerifier.VerifyArtifact(ctx, tmpArtifactPath, tmpAttestationPath)
		verifyDuration := time.Since(verifyStart)

		if verifyErr != nil {
			log.WithError(verifyErr).WithFields(log.Fields{
				"package":     p.FullName(),
				"artifact":    artifactKey,
				"attestation": attestationKey,
				"duration":    verifyDuration,
			}).Warn("SLSA verification failed, artifact rejected")
			
			s.cleanupTempFiles(tmpArtifactPath, tmpAttestationPath)
			continue
		}

		// Step 5: Atomically move verified artifact to final location
		if err := s.atomicMove(tmpArtifactPath, localPath); err != nil {
			log.WithError(err).WithField("package", p.FullName()).Warn("Failed to move verified artifact")
			s.cleanupTempFiles(tmpArtifactPath, tmpAttestationPath)
			continue
		}

		// Clean up temporary attestation file
		s.cleanupTempFiles(tmpAttestationPath)

		totalDuration := time.Since(downloadStart)
		log.WithFields(log.Fields{
			"package":         p.FullName(),
			"key":             artifactKey,
			"path":            localPath,
			"verified":        true,
			"downloadTime":    totalDuration,
			"verificationTime": verifyDuration,
		}).Info("Successfully downloaded and verified package with SLSA attestation")

		return nil
	}

	// All attempts failed
	log.WithFields(log.Fields{
		"package": p.FullName(),
		"version": version,
	}).Debug("No SLSA-verified artifacts found, will build locally")

	return nil // Not an error - allows local build fallback
}

// checkBothExist checks if both artifact and attestation exist in parallel
func (s *S3Cache) checkBothExist(ctx context.Context, artifactKey, attestationKey string) (bool, bool, error) {
	type existResult struct {
		key    string
		exists bool
		err    error
	}

	results := make(chan existResult, 2)
	var wg sync.WaitGroup
	wg.Add(2)

	// Check artifact existence with timeout protection
	go func() {
		defer wg.Done()
		
		// Acquire semaphore slot
		if err := s.acquireSemaphore(ctx); err != nil {
			select {
			case results <- existResult{artifactKey, false, err}:
			case <-ctx.Done():
			}
			return
		}
		defer s.releaseSemaphore()
		
		// Wait for rate limiter permission
		if err := s.waitForRateLimit(ctx); err != nil {
			select {
			case results <- existResult{artifactKey, false, err}:
			case <-ctx.Done():
			}
			return
		}
		
		// Create timeout context for storage operation
		timeoutCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		
		exists, err := s.storage.HasObject(timeoutCtx, artifactKey)
		select {
		case results <- existResult{artifactKey, exists, err}:
		case <-ctx.Done():
		}
	}()

	// Check attestation existence with timeout protection
	go func() {
		defer wg.Done()
		
		// Acquire semaphore slot
		if err := s.acquireSemaphore(ctx); err != nil {
			select {
			case results <- existResult{attestationKey, false, err}:
			case <-ctx.Done():
			}
			return
		}
		defer s.releaseSemaphore()
		
		// Wait for rate limiter permission
		if err := s.waitForRateLimit(ctx); err != nil {
			select {
			case results <- existResult{attestationKey, false, err}:
			case <-ctx.Done():
			}
			return
		}
		
		// Create timeout context for storage operation
		timeoutCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		
		exists, err := s.storage.HasObject(timeoutCtx, attestationKey)
		select {
		case results <- existResult{attestationKey, exists, err}:
		case <-ctx.Done():
		}
	}()

	// Wait for completion with timeout
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// All checks completed
	case <-ctx.Done():
		return false, false, ctx.Err()
	}

	var artifactExists, attestationExists bool
	var artifactErr, attestationErr error
	
	// Block until all results arrive - no default case to avoid race condition
	for i := 0; i < 2; i++ {
		select {
		case result := <-results:
			if result.key == artifactKey {
				artifactExists = result.exists
				artifactErr = result.err
			} else {
				attestationExists = result.exists
				attestationErr = result.err
			}
		case <-ctx.Done():
			return false, false, ctx.Err()
		}
	}
	
	// Log any errors but don't fail the check - let caller decide
	if artifactErr != nil {
		log.WithError(artifactErr).WithField("key", artifactKey).Debug("Failed to check artifact existence")
	}
	if attestationErr != nil {
		log.WithError(attestationErr).WithField("key", attestationKey).Debug("Failed to check attestation existence")
	}

	return artifactExists, attestationExists, nil
}

// downloadBothParallel downloads artifact and attestation in parallel with context awareness
func (s *S3Cache) downloadBothParallel(ctx context.Context, artifactKey, attestationKey, artifactPath, attestationPath string) (error, error) {
	type downloadResult struct {
		err      error
		kind     string
		duration time.Duration
	}

	results := make(chan downloadResult, 2)
	var wg sync.WaitGroup
	wg.Add(2)

	// Download artifact
	go func() {
		defer wg.Done()
		start := time.Now()
		
		// Acquire semaphore slot
		if err := s.acquireSemaphore(ctx); err != nil {
			select {
			case results <- downloadResult{err: err, kind: "artifact", duration: time.Since(start)}:
			case <-ctx.Done():
			}
			return
		}
		defer s.releaseSemaphore()
		
		err := withRetry(3, func() error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
				// Wait for rate limiter permission
				if err := s.waitForRateLimit(ctx); err != nil {
					return err
				}
				
				// Create timeout context for storage operation
				timeoutCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
				defer cancel()
				_, err := s.storage.GetObject(timeoutCtx, artifactKey, artifactPath)
				return err
			}
		})
		
		select {
		case results <- downloadResult{err: err, kind: "artifact", duration: time.Since(start)}:
		case <-ctx.Done():
			// Context cancelled, clean up with race protection
			s.cleanupMu.Lock()
			_ = os.Remove(artifactPath) // Ignore error during cleanup
			s.cleanupMu.Unlock()
		}
	}()

	// Download attestation
	go func() {
		defer wg.Done()
		start := time.Now()
		
		// Acquire semaphore slot
		if err := s.acquireSemaphore(ctx); err != nil {
			select {
			case results <- downloadResult{err: err, kind: "attestation", duration: time.Since(start)}:
			case <-ctx.Done():
			}
			return
		}
		defer s.releaseSemaphore()
		
		err := withRetry(3, func() error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
				// Wait for rate limiter permission
				if err := s.waitForRateLimit(ctx); err != nil {
					return err
				}
				
				// Create timeout context for storage operation
				timeoutCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
				defer cancel()
				_, err := s.storage.GetObject(timeoutCtx, attestationKey, attestationPath)
				return err
			}
		})
		
		select {
		case results <- downloadResult{err: err, kind: "attestation", duration: time.Since(start)}:
		case <-ctx.Done():
			// Context cancelled, clean up with race protection
			s.cleanupMu.Lock()
			_ = os.Remove(attestationPath) // Ignore error during cleanup
			s.cleanupMu.Unlock()
		}
	}()

	// Wait for completion
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// All downloads completed
	case <-ctx.Done():
		// Context cancelled, cleanup
		s.cleanupTempFiles(artifactPath, attestationPath)
		return ctx.Err(), ctx.Err()
	}

	var artifactErr, attestationErr error
	// Block until all results arrive - no default case to avoid race condition
	for i := 0; i < 2; i++ {
		select {
		case result := <-results:
			if result.kind == "artifact" {
				artifactErr = result.err
			} else {
				attestationErr = result.err
			}
		case <-ctx.Done():
			return ctx.Err(), ctx.Err()
		}
	}

	return artifactErr, attestationErr
}

// atomicMove performs cross-platform atomic file move
func (s *S3Cache) atomicMove(src, dst string) error {
	// Ensure destination directory exists
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return fmt.Errorf("failed to create destination directory: %w", err)
	}
	
	// On Windows, os.Rename fails if destination exists
	if runtime.GOOS == "windows" {
		if _, err := os.Stat(dst); err == nil {
			s.cleanupMu.Lock()
			removeErr := os.Remove(dst)
			s.cleanupMu.Unlock()
			if removeErr != nil {
				return fmt.Errorf("failed to remove existing file: %w", removeErr)
			}
		}
	}
	
	return os.Rename(src, dst)
}

// cleanupTempFiles removes temporary files with error logging and race condition protection
func (s *S3Cache) cleanupTempFiles(paths ...string) {
	s.cleanupMu.Lock()
	defer s.cleanupMu.Unlock()
	
	for _, path := range paths {
		if removeErr := os.Remove(path); removeErr != nil && !os.IsNotExist(removeErr) {
			log.WithError(removeErr).WithField("path", path).Debug("Failed to cleanup temporary file")
		}
	}
}

// downloadUnverified handles backward compatibility for missing attestations
func (s *S3Cache) downloadUnverified(ctx context.Context, p cache.Package, version, localPath, extension string) error {
	key := fmt.Sprintf("%s%s", version, extension)
	
	err := withRetry(3, func() error {
		// Wait for rate limiter permission
		if err := s.waitForRateLimit(ctx); err != nil {
			return err
		}
		
		timeoutCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()
		_, err := s.storage.GetObject(timeoutCtx, key, localPath)
		return err
	})

	if err != nil {
		if strings.Contains(err.Error(), "NotFound") || strings.Contains(err.Error(), "404") {
			log.WithFields(log.Fields{
				"package": p.FullName(),
				"key":     key,
			}).Debug("Package not found in remote cache, will build locally")
		} else {
			log.WithFields(log.Fields{
				"package": p.FullName(),
				"key":     key,
				"error":   err,
			}).Debug("Failed to download package from remote cache, will build locally")
		}
		return nil
	}

	log.WithFields(log.Fields{
		"package":  p.FullName(),
		"key":      key,
		"path":     localPath,
		"verified": false,
	}).Warn("Successfully downloaded unverified package from remote cache")

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
		// Wait for rate limiter permission
		if err := s.waitForRateLimit(ctx); err != nil {
			log.WithError(err).WithFields(log.Fields{
				"package": p.FullName(),
				"key":     key,
			}).Warn("rate limiter error during upload - continuing")
			uploadErrors = append(uploadErrors, fmt.Errorf("package %s: rate limit error: %w", p.FullName(), err))
			return nil // Don't fail the entire operation
		}
		
		timeoutCtx, cancel := context.WithTimeout(ctx, 120*time.Second)
		defer cancel()
		if err := s.storage.UploadObject(timeoutCtx, key, localPath); err != nil {
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
	defer func() { _ = file.Close() }() // Ignore error on close

	// Set up cleanup in case of error
	var downloadErr error
	defer func() {
		if downloadErr != nil {
			_ = os.Remove(dest) // Ignore error during cleanup
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
	defer func() { _ = file.Close() }() // Ignore error on close

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
