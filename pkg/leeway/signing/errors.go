package signing

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

// SigningError represents a categorized error during the signing process
type SigningError struct {
	Type     SigningErrorType `json:"type"`
	Artifact string           `json:"artifact"`
	Message  string           `json:"message"`
	Cause    error            `json:"-"`
}

// SigningErrorType categorizes different types of signing errors
type SigningErrorType string

const (
	ErrorTypeNetwork    SigningErrorType = "network"
	ErrorTypeSigstore   SigningErrorType = "sigstore"
	ErrorTypePermission SigningErrorType = "permission"
	ErrorTypeValidation SigningErrorType = "validation"
	ErrorTypeFileSystem SigningErrorType = "filesystem"
)

// Error implements the error interface
func (e *SigningError) Error() string {
	return fmt.Sprintf("[%s] %s: %s", e.Type, e.Artifact, e.Message)
}

// Unwrap returns the underlying cause for error wrapping
func (e *SigningError) Unwrap() error {
	return e.Cause
}

// NewSigningError creates a new categorized signing error
func NewSigningError(errorType SigningErrorType, artifact, message string, cause error) *SigningError {
	return &SigningError{
		Type:     errorType,
		Artifact: artifact,
		Message:  message,
		Cause:    cause,
	}
}

// IsRetryable determines if an error type should be retried
func (e *SigningError) IsRetryable() bool {
	return isRetryableSigningError(e)
}

func isRetryableSigningError(e *SigningError) bool {
	switch e.Type {
	case ErrorTypeNetwork:
		return true
	case ErrorTypeSigstore:
		message := e.Message
		if e.Cause != nil {
			message += ": " + e.Cause.Error()
		}
		if isDeterministicErrorMessage(message) {
			return false
		}
		return IsTransientError(e.Cause) || isTransientErrorMessage(e.Message)
	case ErrorTypePermission, ErrorTypeValidation, ErrorTypeFileSystem:
		return false
	default:
		return false
	}
}

// RetryOptions configures bounded exponential retry behavior.
type RetryOptions struct {
	MaxAttempts    int
	InitialBackoff time.Duration
	MaxBackoff     time.Duration
	JitterFraction float64
	Sleep          func(context.Context, time.Duration) error
	IsRetryable    func(error) bool
}

// DefaultRetryOptions returns conservative defaults for transient signing failures.
func DefaultRetryOptions() RetryOptions {
	return RetryOptions{
		MaxAttempts:    3,
		InitialBackoff: time.Second,
		MaxBackoff:     10 * time.Second,
		JitterFraction: 0.2,
		Sleep:          sleepWithContext,
		IsRetryable:    IsRetryableError,
	}
}

// WithRetry executes an operation with exponential backoff retry logic
func WithRetry(maxAttempts int, operation func() error) error {
	opts := DefaultRetryOptions()
	opts.MaxAttempts = maxAttempts
	return WithRetryOptions(context.Background(), opts, operation)
}

// WithRetryOptions executes an operation with bounded exponential backoff and jitter.
func WithRetryOptions(ctx context.Context, opts RetryOptions, operation func() error) error {
	var lastErr error
	opts = normalizeRetryOptions(opts)
	backoff := opts.InitialBackoff

	for attempt := 1; attempt <= opts.MaxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}

		if err := operation(); err != nil {
			lastErr = err

			if !opts.IsRetryable(err) {
				var signingErr *SigningError
				if errors.As(err, &signingErr) {
					log.WithFields(log.Fields{
						"error_type": signingErr.Type,
						"artifact":   signingErr.Artifact,
					}).Debug("Non-retryable error encountered")
				}
				return err
			}

			if attempt < opts.MaxAttempts {
				delay := applyJitter(backoff, opts.JitterFraction)
				log.WithFields(log.Fields{
					"attempt":      attempt,
					"max_attempts": opts.MaxAttempts,
					"backoff":      delay,
				}).WithError(err).Warn("Operation failed, retrying")

				if sleepErr := opts.Sleep(ctx, delay); sleepErr != nil {
					return sleepErr
				}
				backoff *= 2 // Exponential backoff
				if backoff > opts.MaxBackoff {
					backoff = opts.MaxBackoff
				}
				continue
			}
		} else {
			return nil // Success
		}
	}

	return fmt.Errorf("operation failed after %d attempts: %w", opts.MaxAttempts, lastErr)
}

// CategorizeError attempts to categorize a generic error into a SigningError
func CategorizeError(artifact string, err error) *SigningError {
	var signingErr *SigningError
	if errors.As(err, &signingErr) {
		return signingErr
	}

	// Try to categorize based on error message patterns
	errMsg := err.Error()

	// Network-related errors
	if containsAny(errMsg, []string{"connection", "timeout", "network", "dial", "dns"}) {
		return &SigningError{
			Type:     ErrorTypeNetwork,
			Artifact: artifact,
			Message:  errMsg,
			Cause:    err,
		}
	}

	// Permission-related errors
	if containsAny(errMsg, []string{"permission", "access denied", "forbidden", "unauthorized"}) {
		return &SigningError{
			Type:     ErrorTypePermission,
			Artifact: artifact,
			Message:  errMsg,
			Cause:    err,
		}
	}

	// File system errors
	if containsAny(errMsg, []string{"no such file", "not found", "is a directory", "read-only"}) {
		return &SigningError{
			Type:     ErrorTypeFileSystem,
			Artifact: artifact,
			Message:  errMsg,
			Cause:    err,
		}
	}

	// Default to network error for unknown errors (most likely to be retryable)
	return &SigningError{
		Type:     ErrorTypeNetwork,
		Artifact: artifact,
		Message:  errMsg,
		Cause:    err,
	}
}

func normalizeRetryOptions(opts RetryOptions) RetryOptions {
	defaults := DefaultRetryOptions()
	if opts.MaxAttempts <= 0 {
		opts.MaxAttempts = defaults.MaxAttempts
	}
	if opts.InitialBackoff <= 0 {
		opts.InitialBackoff = defaults.InitialBackoff
	}
	if opts.MaxBackoff <= 0 {
		opts.MaxBackoff = defaults.MaxBackoff
	}
	if opts.MaxBackoff < opts.InitialBackoff {
		opts.MaxBackoff = opts.InitialBackoff
	}
	if opts.JitterFraction < 0 {
		opts.JitterFraction = 0
	}
	if opts.JitterFraction > 1 {
		opts.JitterFraction = 1
	}
	if opts.Sleep == nil {
		opts.Sleep = defaults.Sleep
	}
	if opts.IsRetryable == nil {
		opts.IsRetryable = defaults.IsRetryable
	}
	return opts
}

func sleepWithContext(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}

	timer := time.NewTimer(d)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func applyJitter(d time.Duration, fraction float64) time.Duration {
	if d <= 0 || fraction <= 0 {
		return d
	}

	delta := int64(float64(d) * fraction)
	if delta <= 0 {
		return d
	}

	return d - time.Duration(delta) + time.Duration(rand.Int63n(2*delta+1))
}

// IsRetryableError returns true for transient transport failures that are safe to retry.
func IsRetryableError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) {
		return false
	}

	var signingErr *SigningError
	if errors.As(err, &signingErr) {
		return isRetryableSigningError(signingErr)
	}

	if IsTransientError(err) {
		return true
	}

	msg := err.Error()
	if isDeterministicErrorMessage(msg) {
		return false
	}
	return isTransientErrorMessage(msg)
}

// IsTransientError identifies transport-level errors that can succeed on retry.
func IsTransientError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}

	return isTransientErrorMessage(err.Error())
}

func isTransientErrorMessage(msg string) bool {
	return containsAny(msg, []string{
		"INTERNAL_ERROR",
		"stream error",
		"http2",
		"timeout",
		"timed out",
		"temporary",
		"connection reset",
		"connection refused",
		"connection closed",
		"broken pipe",
		"network",
		"dial tcp",
		"dns",
		"no such host",
		"i/o timeout",
		"EOF",
		"unexpected EOF",
		"server misbehaving",
		"too many requests",
		"rate limit",
		"status: 429",
		"status: 500",
		"status: 502",
		"status: 503",
		"status: 504",
		"bad gateway",
		"service unavailable",
		"gateway timeout",
	})
}

func isDeterministicErrorMessage(msg string) bool {
	return containsAny(msg, []string{
		"createLogEntryConflict",
		"equivalent entry already exists",
		"rekor conflict cannot be verified",
		"failed to fetch conflicting Rekor entry",
		"conflicting Rekor entry",
		"does not match signed payload",
		"checksum calculation failed",
		"incomplete GitHub context",
		"invalid GitHub context",
		"malformed",
		"invalid JWT",
		"failed to decode JWT",
		"sub claim not found",
		"job_workflow_ref not found",
		"ACTIONS_ID_TOKEN_REQUEST_TOKEN not found",
		"ACTIONS_ID_TOKEN_REQUEST_URL not found",
		"not running in GitHub Actions",
		"permission denied",
		"access denied",
		"forbidden",
		"unauthorized",
		"no such file",
		"not found",
		"is a directory",
		"read-only",
		"failed to marshal statement",
		"failed to marshal signed bundle",
	})
}

// containsAny checks if a string contains any of the given substrings (case-insensitive)
func containsAny(s string, substrings []string) bool {
	s = strings.ToLower(s)
	for _, substr := range substrings {
		if strings.Contains(s, strings.ToLower(substr)) {
			return true
		}
	}
	return false
}
