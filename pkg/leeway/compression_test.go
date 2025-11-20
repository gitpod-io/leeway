package leeway

import (
	"os"
	"strings"
	"testing"
)

func TestWithMtime(t *testing.T) {
	tests := []struct {
		name      string
		mtime     int64
		wantMtime int64
	}{
		{
			name:      "positive timestamp",
			mtime:     1234567890,
			wantMtime: 1234567890,
		},
		{
			name:      "zero timestamp",
			mtime:     0,
			wantMtime: 0,
		},
		{
			name:      "recent timestamp",
			mtime:     1700000000,
			wantMtime: 1700000000,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := &TarOptions{}
			WithMtime(tt.mtime)(opts)

			if opts.Mtime != tt.wantMtime {
				t.Errorf("WithMtime() set Mtime = %d, want %d", opts.Mtime, tt.wantMtime)
			}
		})
	}
}

func TestBuildTarCommand_WithMtime(t *testing.T) {
	tests := []struct {
		name          string
		mtime         int64
		wantMtimeFlag bool
		wantFlag      string
	}{
		{
			name:          "with mtime set",
			mtime:         1234567890,
			wantMtimeFlag: true,
			wantFlag:      "--mtime=@1234567890",
		},
		{
			name:          "with zero mtime (not set)",
			mtime:         0,
			wantMtimeFlag: false,
			wantFlag:      "",
		},
		{
			name:          "with recent mtime",
			mtime:         1700000000,
			wantMtimeFlag: true,
			wantFlag:      "--mtime=@1700000000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cmd []string
			if tt.mtime != 0 {
				cmd = BuildTarCommand(
					WithOutputFile("test.tar.gz"),
					WithMtime(tt.mtime),
				)
			} else {
				cmd = BuildTarCommand(
					WithOutputFile("test.tar.gz"),
				)
			}

			// Check if --mtime flag is present
			hasMtimeFlag := false
			for _, arg := range cmd {
				if strings.HasPrefix(arg, "--mtime=") {
					hasMtimeFlag = true
					if tt.wantMtimeFlag && arg != tt.wantFlag {
						t.Errorf("BuildTarCommand() mtime flag = %s, want %s", arg, tt.wantFlag)
					}
					break
				}
			}

			if tt.wantMtimeFlag && !hasMtimeFlag {
				t.Errorf("BuildTarCommand() missing --mtime flag, want %s", tt.wantFlag)
			}
			if !tt.wantMtimeFlag && hasMtimeFlag {
				t.Error("BuildTarCommand() has --mtime flag, want none")
			}
		})
	}
}

func TestBuildTarCommand_MtimePosition(t *testing.T) {
	// Test that --mtime flag appears before -cf flag
	cmd := BuildTarCommand(
		WithOutputFile("test.tar.gz"),
		WithMtime(1234567890),
	)

	mtimeIdx := -1
	cfIdx := -1

	for i, arg := range cmd {
		if strings.HasPrefix(arg, "--mtime=") {
			mtimeIdx = i
		}
		if arg == "-cf" {
			cfIdx = i
		}
	}

	if mtimeIdx == -1 {
		t.Error("BuildTarCommand() missing --mtime flag")
	}
	if cfIdx == -1 {
		t.Error("BuildTarCommand() missing -cf flag")
	}
	if mtimeIdx >= cfIdx {
		t.Errorf("BuildTarCommand() --mtime flag at index %d should appear before -cf at index %d", mtimeIdx, cfIdx)
	}
}

func TestBuildTarCommand_MtimeWithOtherOptions(t *testing.T) {
	// Test that mtime works correctly with other options
	cmd := BuildTarCommand(
		WithOutputFile("test.tar.gz"),
		WithSourcePaths("file1.txt", "file2.txt"),
		WithWorkingDir("/tmp"),
		WithCompression(true),
		WithMtime(1234567890),
	)

	// Verify command contains expected elements
	cmdStr := strings.Join(cmd, " ")

	expectedElements := []string{
		"tar",
		"--mtime=@1234567890",
		"-cf",
		"test.tar.gz",
		"-C",
		"/tmp",
		"file1.txt",
		"file2.txt",
	}

	for _, elem := range expectedElements {
		if !strings.Contains(cmdStr, elem) {
			t.Errorf("BuildTarCommand() missing expected element: %s\nFull command: %s", elem, cmdStr)
		}
	}
}

func TestIsTestEnvironment(t *testing.T) {
	// This test itself should be detected as a test environment
	if !isTestEnvironment() {
		t.Error("isTestEnvironment() should return true when running in test binary")
	}

	// Test with explicit environment variable
	originalEnv := os.Getenv("LEEWAY_TEST_MODE")
	defer func() {
		if originalEnv != "" {
			os.Setenv("LEEWAY_TEST_MODE", originalEnv)
		} else {
			os.Unsetenv("LEEWAY_TEST_MODE")
		}
	}()

	os.Setenv("LEEWAY_TEST_MODE", "true")
	if !isTestEnvironment() {
		t.Error("isTestEnvironment() should return true when LEEWAY_TEST_MODE=true")
	}

	os.Setenv("LEEWAY_TEST_MODE", "false")
	// Should still be true because we're in a test binary
	if !isTestEnvironment() {
		t.Error("isTestEnvironment() should return true when running in test binary (even if LEEWAY_TEST_MODE=false)")
	}
}
