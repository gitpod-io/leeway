package signing

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func noSleepRetryOptions(maxAttempts int) RetryOptions {
	opts := DefaultRetryOptions()
	opts.MaxAttempts = maxAttempts
	opts.InitialBackoff = time.Nanosecond
	opts.MaxBackoff = time.Nanosecond
	opts.JitterFraction = 0
	opts.Sleep = func(context.Context, time.Duration) error { return nil }
	return opts
}

func TestRetryClassification(t *testing.T) {
	tests := []struct {
		name      string
		err       error
		retryable bool
	}{
		{
			name:      "HTTP/2 internal error is transient",
			err:       fmt.Errorf("stream error: stream ID 7; INTERNAL_ERROR; received from peer"),
			retryable: true,
		},
		{
			name:      "deadline exceeded is transient",
			err:       context.DeadlineExceeded,
			retryable: true,
		},
		{
			name:      "network signing error is transient",
			err:       NewSigningError(ErrorTypeNetwork, "artifact.tar.gz", "connection timeout", fmt.Errorf("timeout")),
			retryable: true,
		},
		{
			name:      "validation error is deterministic",
			err:       NewSigningError(ErrorTypeValidation, "artifact.tar.gz", "incomplete GitHub context", nil),
			retryable: false,
		},
		{
			name:      "filesystem error is deterministic",
			err:       NewSigningError(ErrorTypeFileSystem, "artifact.tar.gz", "no such file", nil),
			retryable: false,
		},
		{
			name:      "Rekor conflict is not retried blindly",
			err:       fmt.Errorf("[POST /api/v1/log/entries][409] createLogEntryConflict an equivalent entry already exists"),
			retryable: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.retryable, IsRetryableError(tt.err))
		})
	}
}

func TestWithRetryOptions_RetriesTransientErrorsOnly(t *testing.T) {
	t.Run("transient error is retried and succeeds", func(t *testing.T) {
		attempts := 0
		err := WithRetryOptions(context.Background(), noSleepRetryOptions(3), func() error {
			attempts++
			if attempts == 1 {
				return NewSigningError(ErrorTypeSigstore, "artifact.tar.gz", "stream error: INTERNAL_ERROR", fmt.Errorf("stream error: INTERNAL_ERROR"))
			}
			return nil
		})

		require.NoError(t, err)
		assert.Equal(t, 2, attempts)
	})

	t.Run("deterministic error is not retried", func(t *testing.T) {
		attempts := 0
		err := WithRetryOptions(context.Background(), noSleepRetryOptions(3), func() error {
			attempts++
			return NewSigningError(ErrorTypeValidation, "artifact.tar.gz", "malformed GitHub context", nil)
		})

		require.Error(t, err)
		assert.Equal(t, 1, attempts)
	})
}

func TestWithRetryOptions_Exhaustion(t *testing.T) {
	attempts := 0
	err := WithRetryOptions(context.Background(), noSleepRetryOptions(2), func() error {
		attempts++
		return fmt.Errorf("stream error: stream ID 3; INTERNAL_ERROR; received from peer")
	})

	require.Error(t, err)
	assert.Equal(t, 2, attempts)
	assert.Contains(t, err.Error(), "operation failed after 2 attempts")
}
