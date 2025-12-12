package remote

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
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
	// defaultWorkerCount is the default number of concurrent workers for general operations
	// (existence checks, uploads). Can be overridden via LEEWAY_S3_WORKER_COUNT.
	defaultWorkerCount = 10
	// defaultDownloadWorkerCount is the number of concurrent workers for download operations
	// Higher than default to maximize download throughput.
	// Can be overridden via LEEWAY_S3_DOWNLOAD_WORKERS environment variable.
	defaultDownloadWorkerCount = 30
	// defaultRateLimit is the default rate limit for S3 API calls (requests per second)
	// Can be overridden via LEEWAY_S3_RATE_LIMIT environment variable.
	defaultRateLimit = 100
	// defaultBurstLimit is the default burst limit for S3 API calls
	// Can be overridden via LEEWAY_S3_BURST_LIMIT environment variable.
	defaultBurstLimit = 200
	// maxConcurrentOperations is the maximum number of concurrent goroutines for parallel operations
	maxConcurrentOperations = 50

	// Environment variable names for S3 cache tuning
	envvarS3WorkerCount     = "LEEWAY_S3_WORKER_COUNT"
	envvarS3DownloadWorkers = "LEEWAY_S3_DOWNLOAD_WORKERS"
	envvarS3RateLimit       = "LEEWAY_S3_RATE_LIMIT"
	envvarS3BurstLimit      = "LEEWAY_S3_BURST_LIMIT"
)

// downloadResult represents the result of a download operation with proper error attribution
type downloadResult struct {
	err  error
	kind string // "artifact" or "attestation"
}

// VerificationFailedError is returned when SLSA verification fails
type VerificationFailedError struct {
	Package string
	Reason  string
}

func (e VerificationFailedError) Error() string {
	return fmt.Sprintf("SLSA verification failed for %s: %s", e.Package, e.Reason)
}

// S3Config holds the configuration for S3Cache
type S3Config struct {
	BucketName  string
	Region      string
	PartSize    int64
	WorkerCount int
}

// S3Cache implements RemoteCache using AWS S3
type S3Cache struct {
	storage             cache.ObjectStorage
	cfg                 *cache.RemoteConfig
	workerCount         int
	downloadWorkerCount int
	slsaVerifier        slsa.VerifierInterface
	cleanupMu           sync.Mutex    // Protects concurrent file cleanup operations
	rateLimiter         *rate.Limiter // Rate limiter for S3 API calls
	semaphore           chan struct{} // Semaphore for limiting concurrent operations
}

// getEnvInt reads an integer from an environment variable, returning the default if not set or invalid
func getEnvInt(envvar string, defaultVal int) int {
	if v := os.Getenv(envvar); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
			return parsed
		}
	}
	return defaultVal
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
	if cfg.SLSA != nil && cfg.SLSA.Verification && cfg.SLSA.SourceURI != "" {
		slsaVerifier = slsa.NewVerifier(cfg.SLSA.SourceURI, cfg.SLSA.TrustedRoots)
		log.WithFields(log.Fields{
			"sourceURI":    cfg.SLSA.SourceURI,
			"trustedRoots": len(cfg.SLSA.TrustedRoots),
		}).Debug("SLSA verification enabled for cache")
	}

	// Read tuning parameters from environment variables (with defaults)
	workerCount := getEnvInt(envvarS3WorkerCount, defaultWorkerCount)
	downloadWorkers := getEnvInt(envvarS3DownloadWorkers, defaultDownloadWorkerCount)
	rateLimit := getEnvInt(envvarS3RateLimit, defaultRateLimit)
	burstLimit := getEnvInt(envvarS3BurstLimit, defaultBurstLimit)

	// Log if non-default values are used
	if workerCount != defaultWorkerCount || downloadWorkers != defaultDownloadWorkerCount || rateLimit != defaultRateLimit || burstLimit != defaultBurstLimit {
		log.WithFields(log.Fields{
			"workerCount":     workerCount,
			"downloadWorkers": downloadWorkers,
			"rateLimit":       rateLimit,
			"burstLimit":      burstLimit,
		}).Debug("S3 cache using custom tuning parameters")
	}

	// Initialize rate limiter
	rateLimiter := rate.NewLimiter(rate.Limit(rateLimit), burstLimit)

	// Initialize semaphore for goroutine limiting
	semaphore := make(chan struct{}, maxConcurrentOperations)

	return &S3Cache{
		storage:             storage,
		cfg:                 cfg,
		workerCount:         workerCount,
		downloadWorkerCount: downloadWorkers,
		slsaVerifier:        slsaVerifier,
		rateLimiter:         rateLimiter,
		semaphore:           semaphore,
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

// processPackages processes packages using a worker pool with the specified worker count
func (s *S3Cache) processPackages(ctx context.Context, pkgs []cache.Package, workerCount int, fn func(context.Context, cache.Package) error) error {
	jobs := make(chan cache.Package, len(pkgs))
	results := make(chan error, len(pkgs))
	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < workerCount; i++ {
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

	// Build a map of version -> package for quick lookup
	versionToPackage := make(map[string]cache.Package, len(pkgs))
	for _, p := range pkgs {
		version, err := p.Version()
		if err != nil {
			log.WithError(err).WithField("package", p.FullName()).Debug("Failed to get version for package, skipping")
			continue
		}
		versionToPackage[version] = p
	}

	if len(versionToPackage) == 0 {
		return result, nil
	}

	// Use ListObjectsV2 to batch check all packages in 1-2 API calls
	// We list all objects and check which packages exist
	// This is much faster than 2N HeadObject calls (2 per package)
	if err := s.waitForRateLimit(ctx); err != nil {
		log.WithError(err).Debug("Rate limiter error during batch existence check")
		// Fall back to sequential checks if rate limited
		return s.existingPackagesSequential(ctx, pkgs)
	}

	timeoutCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// List all objects with empty prefix to get all cached artifacts
	// In practice, this could be optimized with a common prefix if versions share one
	objects, err := s.storage.ListObjects(timeoutCtx, "")
	if err != nil {
		log.WithError(err).Debug("Failed to list objects in remote cache, falling back to sequential checks")
		// Fall back to sequential checks on error
		return s.existingPackagesSequential(ctx, pkgs)
	}

	// Build a set of existing keys for O(1) lookup
	existingKeys := make(map[string]bool, len(objects))
	for _, key := range objects {
		existingKeys[key] = true
	}

	// Check which packages exist by looking up their keys
	for version, p := range versionToPackage {
		gzKey := fmt.Sprintf("%s.tar.gz", version)
		tarKey := fmt.Sprintf("%s.tar", version)

		if existingKeys[gzKey] {
			log.WithFields(log.Fields{
				"package": p.FullName(),
				"key":     gzKey,
			}).Debug("found package in remote cache (.tar.gz)")
			result[p] = struct{}{}
		} else if existingKeys[tarKey] {
			log.WithFields(log.Fields{
				"package": p.FullName(),
				"key":     tarKey,
			}).Debug("found package in remote cache (.tar)")
			result[p] = struct{}{}
		} else {
			log.WithFields(log.Fields{
				"package": p.FullName(),
				"version": version,
			}).Debug("package not found in remote cache, will build locally")
		}
	}

	return result, nil
}

// existingPackagesSequential is the fallback implementation using sequential HeadObject calls
// This is used when ListObjects fails or is rate limited
func (s *S3Cache) existingPackagesSequential(ctx context.Context, pkgs []cache.Package) (map[cache.Package]struct{}, error) {
	result := make(map[cache.Package]struct{})
	var mu sync.Mutex

	err := s.processPackages(ctx, pkgs, s.workerCount, func(ctx context.Context, p cache.Package) error {
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

// Download implements RemoteCache.
// Returns detailed results for each package, enabling callers to distinguish between
// transient failures (retry may help) and permanent failures (rebuild required).
func (s *S3Cache) Download(ctx context.Context, dst cache.LocalCache, pkgs []cache.Package) map[string]cache.DownloadResult {
	results := make(map[string]cache.DownloadResult)
	var mu sync.Mutex

	// Use higher worker count for downloads to maximize throughput
	_ = s.processPackages(ctx, pkgs, s.downloadWorkerCount, func(ctx context.Context, p cache.Package) error {
		result := s.downloadPackage(ctx, dst, p)

		mu.Lock()
		results[p.FullName()] = result
		mu.Unlock()

		return nil // Never fail the batch - results are tracked individually
	})

	return results
}

// downloadPackage downloads a single package and returns detailed status
func (s *S3Cache) downloadPackage(ctx context.Context, dst cache.LocalCache, p cache.Package) cache.DownloadResult {
	version, err := p.Version()
	if err != nil {
		log.WithError(err).WithField("package", p.FullName()).Warn("Failed to get version for package, skipping")
		return cache.DownloadResult{Status: cache.DownloadStatusFailed, Err: err}
	}

	localPath, exists := dst.Location(p)
	if exists {
		log.WithField("package", p.FullName()).Debug("Package already exists in local cache, skipping download")
		return cache.DownloadResult{Status: cache.DownloadStatusSkipped}
	}

	if localPath == "" {
		err := fmt.Errorf("failed to get local path for package")
		log.WithField("package", p.FullName()).Warn("Failed to get local path for package, skipping download")
		return cache.DownloadResult{Status: cache.DownloadStatusFailed, Err: err}
	}

	// Ensure parent directory exists
	if err := os.MkdirAll(filepath.Dir(localPath), 0755); err != nil {
		log.WithError(err).WithFields(log.Fields{
			"package": p.FullName(),
			"dir":     filepath.Dir(localPath),
		}).Warn("Failed to create directory for package, skipping download")
		return cache.DownloadResult{Status: cache.DownloadStatusFailed, Err: err}
	}

	// Branch based on SLSA verification configuration
	if s.slsaVerifier != nil {
		return s.downloadWithSLSAVerificationResult(ctx, p, version, localPath)
	}
	return s.downloadOriginalResult(ctx, p, version, localPath)
}

// downloadOriginal preserves the original download behavior when SLSA verification is disabled
// downloadOriginalResult downloads without SLSA verification and returns detailed status
func (s *S3Cache) downloadOriginalResult(ctx context.Context, p cache.Package, version, localPath string) cache.DownloadResult {
	// Try downloading .tar.gz first with retry
	gzKey := fmt.Sprintf("%s.tar.gz", version)
	gzNotFound := false
	gzErr := withRetry(3, func() error {
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

		// Download provenance bundle if it exists (best effort, non-blocking)
		s.downloadProvenanceBundle(ctx, p.FullName(), gzKey, localPath)

		// Download SBOM files if they exist (best effort, non-blocking)
		s.downloadSBOMFiles(ctx, p.FullName(), gzKey, localPath)

		return cache.DownloadResult{Status: cache.DownloadStatusSuccess}
	}

	// Check if this is a "not found" error
	if strings.Contains(gzErr.Error(), "NotFound") || strings.Contains(gzErr.Error(), "404") {
		gzNotFound = true
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
		if err := s.waitForRateLimit(ctx); err != nil {
			return err
		}
		timeoutCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()
		_, err := s.storage.GetObject(timeoutCtx, tarKey, localPath)
		return err
	})

	if tarErr == nil {
		log.WithFields(log.Fields{
			"package": p.FullName(),
			"key":     tarKey,
			"path":    localPath,
		}).Debug("Successfully downloaded package from remote cache (.tar)")

		// Download provenance bundle if it exists (best effort, non-blocking)
		s.downloadProvenanceBundle(ctx, p.FullName(), tarKey, localPath)

		// Download SBOM files if they exist (best effort, non-blocking)
		s.downloadSBOMFiles(ctx, p.FullName(), tarKey, localPath)

		return cache.DownloadResult{Status: cache.DownloadStatusSuccess}
	}

	// Determine if this was a "not found" or a transient failure
	tarNotFound := strings.Contains(tarErr.Error(), "NotFound") || strings.Contains(tarErr.Error(), "404")

	if gzNotFound && tarNotFound {
		log.WithFields(log.Fields{
			"package": p.FullName(),
		}).Debug("Package not found in remote cache, will build locally")
		return cache.DownloadResult{Status: cache.DownloadStatusNotFound}
	}

	// At least one attempt failed with a non-404 error - this is a transient failure
	log.WithFields(log.Fields{
		"package": p.FullName(),
		"gzErr":   gzErr,
		"tarErr":  tarErr,
	}).Debug("Failed to download package from remote cache (transient failure)")
	return cache.DownloadResult{Status: cache.DownloadStatusFailed, Err: tarErr}
}

// downloadWithSLSAVerification downloads and verifies artifacts using SLSA attestations.
//
// Behavior based on RequireAttestation configuration:
//   - RequireAttestation=false (default): Missing attestation → download without verification (graceful degradation)
//   - RequireAttestation=true: Missing attestation → skip download, return nil to allow local build fallback
//
// This function tries multiple extensions (.tar.gz, .tar) and their corresponding attestations.
// Returns nil (not an error) when no suitable artifacts are found to allow graceful fallback to local builds.
//
// Configuration:
// RequireAttestation can be set via:
//   - Environment variable: LEEWAY_SLSA_REQUIRE_ATTESTATION=true
//   - CLI flag: --slsa-require-attestation
//   - Workspace config: Automatically enabled when provenance.slsa=true in WORKSPACE.yaml
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

	// Track whether we attempted verification and it failed
	var verificationAttempted bool
	var lastVerificationError error

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

		// Step 2: Handle missing attestation based on RequireAttestation configuration
		if !attestationExists {
			if s.cfg.SLSA != nil && s.cfg.SLSA.RequireAttestation {
				// RequireAttestation=true: missing attestation → skip download, try next extension
				// If all extensions fail, function returns nil to allow local build fallback
				log.WithFields(log.Fields{
					"package":     p.FullName(),
					"attestation": attestationKey,
				}).Debug("Required attestation missing, skipping this attempt")
				continue
			} else {
				// RequireAttestation=false: missing attestation → download without verification
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
		log.WithFields(log.Fields{
			"package":     p.FullName(),
			"artifact":    artifactKey,
			"attestation": attestationKey,
		}).Debug("Starting SLSA verification")

		verifyStart := time.Now()
		verifyErr := s.slsaVerifier.VerifyArtifact(ctx, tmpArtifactPath, tmpAttestationPath)
		verifyDuration := time.Since(verifyStart)

		if verifyErr != nil {
			verificationAttempted = true
			lastVerificationError = verifyErr
			log.WithError(verifyErr).WithFields(log.Fields{
				"package":     p.FullName(),
				"artifact":    artifactKey,
				"attestation": attestationKey,
				"duration":    verifyDuration,
			}).Warn("SLSA verification failed, artifact rejected")

			s.cleanupTempFiles(tmpArtifactPath, tmpAttestationPath)
			continue
		}

		log.WithFields(log.Fields{
			"package":  p.FullName(),
			"artifact": artifactKey,
			"duration": verifyDuration,
		}).Debug("SLSA verification succeeded")

		// Step 5: Atomically move verified artifact to final location
		if err := s.atomicMove(tmpArtifactPath, localPath); err != nil {
			log.WithError(err).WithField("package", p.FullName()).Warn("Failed to move verified artifact")
			s.cleanupTempFiles(tmpArtifactPath, tmpAttestationPath)
			continue
		}

		// Step 6: Download provenance bundle if it exists (best effort, non-blocking)
		s.downloadProvenanceBundle(ctx, p.FullName(), artifactKey, localPath)

		// Step 7: Download SBOM files if they exist (best effort, non-blocking)
		s.downloadSBOMFiles(ctx, p.FullName(), artifactKey, localPath)

		// Clean up temporary attestation file
		s.cleanupTempFiles(tmpAttestationPath)

		totalDuration := time.Since(downloadStart)
		log.WithFields(log.Fields{
			"package":          p.FullName(),
			"key":              artifactKey,
			"path":             localPath,
			"verified":         true,
			"downloadTime":     totalDuration,
			"verificationTime": verifyDuration,
		}).Info("Successfully downloaded and verified package with SLSA attestation")

		return nil
	}

	// All attempts failed
	if verificationAttempted {
		// Verification was attempted but failed - return error to distinguish from "no artifacts"
		log.WithFields(log.Fields{
			"package": p.FullName(),
			"version": version,
		}).Warn("SLSA verification failed for all attempts, will build locally")
		return VerificationFailedError{
			Package: p.FullName(),
			Reason:  fmt.Sprintf("verification failed: %v", lastVerificationError),
		}
	}

	// No artifacts found or no verification attempted
	log.WithFields(log.Fields{
		"package": p.FullName(),
		"version": version,
	}).Debug("No SLSA-verified artifacts found, will build locally")

	// IMPORTANT: Return nil (not an error) to allow local build fallback.
	// This behavior is critical when RequireAttestation=true and no attestations are found.
	// The cache system is designed to gracefully degrade to local builds rather than fail.
	return nil
}

// downloadWithSLSAVerificationResult wraps downloadWithSLSAVerification to return detailed status
func (s *S3Cache) downloadWithSLSAVerificationResult(ctx context.Context, p cache.Package, version, localPath string) cache.DownloadResult {
	err := s.downloadWithSLSAVerification(ctx, p, version, localPath)
	if err == nil {
		// Check if file was actually downloaded
		if _, statErr := os.Stat(localPath); statErr == nil {
			return cache.DownloadResult{Status: cache.DownloadStatusSuccess}
		}
		// No error but no file - means not found
		return cache.DownloadResult{Status: cache.DownloadStatusNotFound}
	}

	// Check if it's a verification failure
	if _, ok := err.(VerificationFailedError); ok {
		return cache.DownloadResult{Status: cache.DownloadStatusVerificationFailed, Err: err}
	}

	// Other errors are transient failures
	return cache.DownloadResult{Status: cache.DownloadStatusFailed, Err: err}
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

// downloadFileAsync downloads a single file asynchronously with proper concurrency control
func (s *S3Cache) downloadFileAsync(ctx context.Context, key, localPath, kind string,
	wg *sync.WaitGroup, resultChan chan<- downloadResult) {
	defer wg.Done()

	// Acquire semaphore for concurrency control
	if err := s.acquireSemaphore(ctx); err != nil {
		resultChan <- downloadResult{
			err:  fmt.Errorf("semaphore acquire failed for %s: %w", key, err),
			kind: kind,
		}
		return
	}
	defer s.releaseSemaphore()

	// Download with retry logic
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
			_, err := s.storage.GetObject(timeoutCtx, key, localPath)
			return err
		}
	})

	// NEW: Structured result reporting
	if err != nil {
		// Clean up on error with race protection
		s.cleanupMu.Lock()
		_ = os.Remove(localPath) // Ignore error during cleanup
		s.cleanupMu.Unlock()
		resultChan <- downloadResult{
			err:  fmt.Errorf("failed to download %s: %w", key, err),
			kind: kind,
		}
	} else {
		resultChan <- downloadResult{
			err:  nil,
			kind: kind,
		}
	}
}

// downloadBothParallel downloads artifact and attestation in parallel with context awareness
func (s *S3Cache) downloadBothParallel(ctx context.Context, artifactKey, attestationKey, artifactPath, attestationPath string) (error, error) {
	resultChan := make(chan downloadResult, 2)
	var wg sync.WaitGroup

	// Download artifact
	wg.Add(1)
	go s.downloadFileAsync(ctx, artifactKey, artifactPath, "artifact", &wg, resultChan)

	// Download attestation
	wg.Add(1)
	go s.downloadFileAsync(ctx, attestationKey, attestationPath, "attestation", &wg, resultChan)

	// Wait and close channel when done
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	var artifactErr, attestationErr error
	var resultsCollected int

	// Collect results with proper context handling
	for resultsCollected < 2 {
		select {
		case result, ok := <-resultChan:
			if !ok {
				// Channel closed, all results collected
				break
			}
			resultsCollected++
			switch result.kind {
			case "artifact":
				artifactErr = result.err
			case "attestation":
				attestationErr = result.err
			}

		case <-ctx.Done():
			// Context cancelled - provide specific errors based on what we know
			ctxErr := ctx.Err()

			// Set errors for operations that haven't completed
			if resultsCollected < 2 {
				if artifactErr == nil {
					artifactErr = fmt.Errorf("artifact download cancelled: %w", ctxErr)
				}
				if attestationErr == nil {
					attestationErr = fmt.Errorf("attestation download cancelled: %w", ctxErr)
				}
			}

			return artifactErr, attestationErr
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

	err := s.processPackages(ctx, pkgs, s.workerCount, func(ctx context.Context, p cache.Package) error {
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

		// Upload provenance bundle if it exists (non-blocking)
		s.uploadProvenanceBundle(ctx, p.FullName(), key, localPath)

		// Upload SBOM files if they exist (non-blocking)
		s.uploadSBOMFiles(ctx, p.FullName(), key, localPath)

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

// UploadFile uploads a single file to the remote cache with the given key
func (s *S3Cache) UploadFile(ctx context.Context, filePath string, key string) error {
	// Wait for rate limiter permission
	if err := s.waitForRateLimit(ctx); err != nil {
		return fmt.Errorf("rate limiter error: %w", err)
	}

	// Use timeout for the upload operation
	timeoutCtx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()

	if err := s.storage.UploadObject(timeoutCtx, key, filePath); err != nil {
		return fmt.Errorf("failed to upload file %s with key %s: %w", filePath, key, err)
	}

	log.WithFields(log.Fields{
		"file": filePath,
		"key":  key,
	}).Debug("successfully uploaded file to remote cache")

	return nil
}

// HasFile checks if a file exists in the remote cache with the given key
func (s *S3Cache) HasFile(ctx context.Context, key string) (bool, error) {
	// Wait for rate limiter permission
	if err := s.waitForRateLimit(ctx); err != nil {
		log.WithError(err).Debug("Rate limiter error during file existence check")
		return false, fmt.Errorf("rate limiter error: %w", err)
	}

	// Use timeout for the check operation
	timeoutCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	exists, err := s.storage.HasObject(timeoutCtx, key)
	if err != nil {
		log.WithFields(log.Fields{
			"key":   key,
			"error": err,
		}).Debug("failed to check file existence in remote cache")
		return false, fmt.Errorf("failed to check if file exists: %w", err)
	}

	return exists, nil
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

// fileExists checks if a file exists and is not a directory
func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if err != nil {
		return false
	}
	return !info.IsDir()
}

// uploadProvenanceBundle uploads a provenance bundle to S3 with retry logic.
// This is a non-blocking operation - failures are logged but don't fail the build.
// Provenance bundles are stored alongside artifacts as <artifact>.provenance.jsonl
// and are needed for dependency provenance collection during local builds.
func (s *S3Cache) uploadProvenanceBundle(ctx context.Context, packageName, artifactKey, localPath string) {
	provenancePath := localPath + ".provenance.jsonl"

	// Check if provenance file exists
	if !fileExists(provenancePath) {
		log.WithFields(log.Fields{
			"package": packageName,
			"path":    provenancePath,
		}).Debug("Provenance bundle not found locally, skipping upload")
		return
	}

	provenanceKey := artifactKey + ".provenance.jsonl"

	// Wait for rate limiter permission
	if err := s.waitForRateLimit(ctx); err != nil {
		log.WithError(err).WithFields(log.Fields{
			"package": packageName,
			"key":     provenanceKey,
		}).Warn("Rate limiter error during provenance upload, skipping")
		return
	}

	// Upload with timeout and retry logic (via storage layer)
	uploadCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	if err := s.storage.UploadObject(uploadCtx, provenanceKey, provenancePath); err != nil {
		log.WithError(err).WithFields(log.Fields{
			"package": packageName,
			"key":     provenanceKey,
			"path":    provenancePath,
		}).Warn("Failed to upload provenance bundle to remote cache")
		return
	}

	log.WithFields(log.Fields{
		"package": packageName,
		"key":     provenanceKey,
	}).Debug("Successfully uploaded provenance bundle to remote cache")
}

// SBOM file extensions - must match pkg/leeway/sbom.go constants
const (
	sbomBaseFilename           = "sbom"
	sbomCycloneDXFileExtension = ".cdx.json"
	sbomSPDXFileExtension      = ".spdx.json"
	sbomSyftFileExtension      = ".json"
)

// uploadSBOMFiles uploads SBOM files to S3 with retry logic.
// This is a non-blocking operation - failures are logged but don't fail the build.
// SBOM files are stored alongside artifacts as <artifact>.sbom.<ext>
func (s *S3Cache) uploadSBOMFiles(ctx context.Context, packageName, artifactKey, localPath string) {
	sbomExtensions := []string{
		"." + sbomBaseFilename + sbomCycloneDXFileExtension,
		"." + sbomBaseFilename + sbomSPDXFileExtension,
		"." + sbomBaseFilename + sbomSyftFileExtension,
	}

	for _, ext := range sbomExtensions {
		sbomPath := localPath + ext
		sbomKey := artifactKey + ext

		// Check if SBOM file exists
		if !fileExists(sbomPath) {
			log.WithFields(log.Fields{
				"package": packageName,
				"path":    sbomPath,
			}).Debug("SBOM file not found locally, skipping upload")
			continue
		}

		// Wait for rate limiter permission
		if err := s.waitForRateLimit(ctx); err != nil {
			log.WithError(err).WithFields(log.Fields{
				"package": packageName,
				"key":     sbomKey,
			}).Warn("Rate limiter error during SBOM upload, skipping")
			continue
		}

		// Upload with timeout
		uploadCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
		if err := s.storage.UploadObject(uploadCtx, sbomKey, sbomPath); err != nil {
			log.WithError(err).WithFields(log.Fields{
				"package": packageName,
				"key":     sbomKey,
				"path":    sbomPath,
			}).Warn("Failed to upload SBOM file to remote cache")
			cancel()
			continue
		}
		cancel()

		log.WithFields(log.Fields{
			"package": packageName,
			"key":     sbomKey,
		}).Debug("Successfully uploaded SBOM file to remote cache")
	}
}

// downloadSBOMFiles downloads SBOM files from S3.
// This is a best-effort operation - missing SBOMs are expected for older artifacts.
// SBOM files are stored alongside artifacts as <artifact>.sbom.<ext>
func (s *S3Cache) downloadSBOMFiles(ctx context.Context, packageName, artifactKey, localPath string) {
	sbomExtensions := []string{
		"." + sbomBaseFilename + sbomCycloneDXFileExtension,
		"." + sbomBaseFilename + sbomSPDXFileExtension,
		"." + sbomBaseFilename + sbomSyftFileExtension,
	}

	for _, ext := range sbomExtensions {
		sbomPath := localPath + ext
		sbomKey := artifactKey + ext
		tmpSBOMPath := sbomPath + ".tmp"

		// Wait for rate limiter permission
		if err := s.waitForRateLimit(ctx); err != nil {
			log.WithError(err).WithFields(log.Fields{
				"package": packageName,
				"key":     sbomKey,
			}).Debug("Rate limiter error during SBOM download, skipping")
			continue
		}

		// Download with timeout
		downloadCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		bytesDownloaded, err := s.storage.GetObject(downloadCtx, sbomKey, tmpSBOMPath)
		cancel()

		if err != nil {
			// SBOM not found - expected for older artifacts
			log.WithFields(log.Fields{
				"package": packageName,
				"key":     sbomKey,
			}).Debug("SBOM file not found in remote cache (expected for older artifacts)")
			s.cleanupTempFiles(tmpSBOMPath)
			continue
		}

		// Verify the downloaded file exists and has content
		if !fileExists(tmpSBOMPath) {
			log.WithFields(log.Fields{
				"package": packageName,
				"key":     sbomKey,
			}).Warn("SBOM download reported success but file not found")
			s.cleanupTempFiles(tmpSBOMPath)
			continue
		}

		if bytesDownloaded == 0 {
			log.WithFields(log.Fields{
				"package": packageName,
				"key":     sbomKey,
			}).Warn("SBOM downloaded but file is empty")
			s.cleanupTempFiles(tmpSBOMPath)
			continue
		}

		// Atomically move to final location
		if err := s.atomicMove(tmpSBOMPath, sbomPath); err != nil {
			log.WithError(err).WithFields(log.Fields{
				"package": packageName,
				"key":     sbomKey,
			}).Warn("Failed to move SBOM file to final location")
			s.cleanupTempFiles(tmpSBOMPath)
			continue
		}

		log.WithFields(log.Fields{
			"package": packageName,
			"key":     sbomKey,
			"bytes":   bytesDownloaded,
		}).Debug("Successfully downloaded SBOM file")
	}
}

// downloadProvenanceBundle downloads a provenance bundle from S3 with verification.
// This is a best-effort operation - missing provenance is expected for older artifacts.
// Returns true if provenance was successfully downloaded, false otherwise.
func (s *S3Cache) downloadProvenanceBundle(ctx context.Context, packageName, artifactKey, localPath string) bool {
	provenanceKey := artifactKey + ".provenance.jsonl"
	provenancePath := localPath + ".provenance.jsonl"
	tmpProvenancePath := provenancePath + ".tmp"

	// Wait for rate limiter permission
	if err := s.waitForRateLimit(ctx); err != nil {
		log.WithError(err).WithFields(log.Fields{
			"package": packageName,
			"key":     provenanceKey,
		}).Debug("Rate limiter error during provenance download, skipping")
		return false
	}

	// Download with timeout
	downloadCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	bytesDownloaded, err := s.storage.GetObject(downloadCtx, provenanceKey, tmpProvenancePath)
	if err != nil {
		// Provenance not found - this is expected for older artifacts
		log.WithFields(log.Fields{
			"package": packageName,
			"key":     provenanceKey,
		}).Debug("Provenance bundle not found in remote cache (expected for older artifacts)")
		s.cleanupTempFiles(tmpProvenancePath)
		return false
	}

	// Verify the downloaded file exists and has content
	if !fileExists(tmpProvenancePath) {
		log.WithFields(log.Fields{
			"package": packageName,
			"key":     provenanceKey,
		}).Warn("Provenance bundle download reported success but file not found")
		s.cleanupTempFiles(tmpProvenancePath)
		return false
	}

	if bytesDownloaded == 0 {
		log.WithFields(log.Fields{
			"package": packageName,
			"key":     provenanceKey,
		}).Warn("Provenance bundle downloaded but file is empty")
		s.cleanupTempFiles(tmpProvenancePath)
		return false
	}

	// Atomically move to final location
	if err := s.atomicMove(tmpProvenancePath, provenancePath); err != nil {
		log.WithError(err).WithFields(log.Fields{
			"package": packageName,
			"key":     provenanceKey,
		}).Warn("Failed to move provenance bundle to final location")
		s.cleanupTempFiles(tmpProvenancePath)
		return false
	}

	log.WithFields(log.Fields{
		"package": packageName,
		"key":     provenanceKey,
		"bytes":   bytesDownloaded,
	}).Debug("Successfully downloaded provenance bundle")
	return true
}
