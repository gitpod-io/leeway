package signing

import (
	"fmt"
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
	switch e.Type {
	case ErrorTypeNetwork, ErrorTypeSigstore:
		return true
	case ErrorTypePermission, ErrorTypeValidation, ErrorTypeFileSystem:
		return false
	default:
		return false
	}
}

// WithRetry executes an operation with exponential backoff retry logic
func WithRetry(maxAttempts int, operation func() error) error {
	var lastErr error
	backoff := time.Second

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if err := operation(); err != nil {
			lastErr = err

			// Check if this is a retryable error
			if signingErr, ok := err.(*SigningError); ok && !signingErr.IsRetryable() {
				log.WithFields(log.Fields{
					"error_type": signingErr.Type,
					"artifact":   signingErr.Artifact,
				}).Debug("Non-retryable error encountered")
				return err
			}

			if attempt < maxAttempts {
				log.WithFields(log.Fields{
					"attempt":      attempt,
					"max_attempts": maxAttempts,
					"backoff":      backoff,
				}).WithError(err).Warn("Operation failed, retrying")

				time.Sleep(backoff)
				backoff *= 2 // Exponential backoff
				if backoff > 30*time.Second {
					backoff = 30 * time.Second // Cap at 30 seconds
				}
				continue
			}
		} else {
			return nil // Success
		}
	}

	return fmt.Errorf("operation failed after %d attempts: %w", maxAttempts, lastErr)
}

// CategorizeError attempts to categorize a generic error into a SigningError
func CategorizeError(artifact string, err error) *SigningError {
	if signingErr, ok := err.(*SigningError); ok {
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
