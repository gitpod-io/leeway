package remote

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetEnvInt(t *testing.T) {
	tests := []struct {
		name       string
		envVar     string
		envValue   string
		defaultVal int
		expected   int
	}{
		{
			name:       "returns default when env var not set",
			envVar:     "TEST_UNSET_VAR",
			envValue:   "",
			defaultVal: 30,
			expected:   30,
		},
		{
			name:       "returns parsed value when env var is valid integer",
			envVar:     "TEST_VALID_INT",
			envValue:   "50",
			defaultVal: 30,
			expected:   50,
		},
		{
			name:       "returns default when env var is invalid integer",
			envVar:     "TEST_INVALID_INT",
			envValue:   "not-a-number",
			defaultVal: 30,
			expected:   30,
		},
		{
			name:       "returns default when env var is zero",
			envVar:     "TEST_ZERO_INT",
			envValue:   "0",
			defaultVal: 30,
			expected:   30,
		},
		{
			name:       "returns default when env var is negative",
			envVar:     "TEST_NEGATIVE_INT",
			envValue:   "-10",
			defaultVal: 30,
			expected:   30,
		},
		{
			name:       "returns parsed value for large numbers",
			envVar:     "TEST_LARGE_INT",
			envValue:   "1000",
			defaultVal: 100,
			expected:   1000,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clean up env var before and after test
			os.Unsetenv(tt.envVar)
			defer os.Unsetenv(tt.envVar)

			if tt.envValue != "" {
				os.Setenv(tt.envVar, tt.envValue)
			}

			result := getEnvInt(tt.envVar, tt.defaultVal)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestS3CacheEnvVarTuning(t *testing.T) {
	// Save original env vars
	origWorkerCount := os.Getenv(envvarS3WorkerCount)
	origDownloadWorkers := os.Getenv(envvarS3DownloadWorkers)
	origRateLimit := os.Getenv(envvarS3RateLimit)
	origBurstLimit := os.Getenv(envvarS3BurstLimit)

	// Restore after test
	defer func() {
		if origWorkerCount != "" {
			os.Setenv(envvarS3WorkerCount, origWorkerCount)
		} else {
			os.Unsetenv(envvarS3WorkerCount)
		}
		if origDownloadWorkers != "" {
			os.Setenv(envvarS3DownloadWorkers, origDownloadWorkers)
		} else {
			os.Unsetenv(envvarS3DownloadWorkers)
		}
		if origRateLimit != "" {
			os.Setenv(envvarS3RateLimit, origRateLimit)
		} else {
			os.Unsetenv(envvarS3RateLimit)
		}
		if origBurstLimit != "" {
			os.Setenv(envvarS3BurstLimit, origBurstLimit)
		} else {
			os.Unsetenv(envvarS3BurstLimit)
		}
	}()

	t.Run("uses defaults when env vars not set", func(t *testing.T) {
		os.Unsetenv(envvarS3WorkerCount)
		os.Unsetenv(envvarS3DownloadWorkers)
		os.Unsetenv(envvarS3RateLimit)
		os.Unsetenv(envvarS3BurstLimit)

		workerCount := getEnvInt(envvarS3WorkerCount, defaultWorkerCount)
		downloadWorkers := getEnvInt(envvarS3DownloadWorkers, defaultDownloadWorkerCount)
		rateLimit := getEnvInt(envvarS3RateLimit, defaultRateLimit)
		burstLimit := getEnvInt(envvarS3BurstLimit, defaultBurstLimit)

		assert.Equal(t, defaultWorkerCount, workerCount)
		assert.Equal(t, defaultDownloadWorkerCount, downloadWorkers)
		assert.Equal(t, defaultRateLimit, rateLimit)
		assert.Equal(t, defaultBurstLimit, burstLimit)
	})

	t.Run("uses custom values when env vars set", func(t *testing.T) {
		os.Setenv(envvarS3WorkerCount, "20")
		os.Setenv(envvarS3DownloadWorkers, "50")
		os.Setenv(envvarS3RateLimit, "300")
		os.Setenv(envvarS3BurstLimit, "500")

		workerCount := getEnvInt(envvarS3WorkerCount, defaultWorkerCount)
		downloadWorkers := getEnvInt(envvarS3DownloadWorkers, defaultDownloadWorkerCount)
		rateLimit := getEnvInt(envvarS3RateLimit, defaultRateLimit)
		burstLimit := getEnvInt(envvarS3BurstLimit, defaultBurstLimit)

		assert.Equal(t, 20, workerCount)
		assert.Equal(t, 50, downloadWorkers)
		assert.Equal(t, 300, rateLimit)
		assert.Equal(t, 500, burstLimit)
	})
}
