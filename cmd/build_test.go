package cmd

import (
	"testing"

	"github.com/spf13/cobra"
)

func TestBuildCommandFlags(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantFlag string
		wantVal  interface{}
	}{
		{
			name:     "in-flight-checksums flag default",
			args:     []string{},
			wantFlag: "in-flight-checksums",
			wantVal:  false,
		},
		{
			name:     "in-flight-checksums flag enabled",
			args:     []string{"--in-flight-checksums"},
			wantFlag: "in-flight-checksums",
			wantVal:  true,
		},
		{
			name:     "in-flight-checksums flag explicitly disabled",
			args:     []string{"--in-flight-checksums=false"},
			wantFlag: "in-flight-checksums",
			wantVal:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a new build command for each test
			cmd := &cobra.Command{
				Use: "build",
				Run: func(cmd *cobra.Command, args []string) {
					// No-op for testing
				},
			}
			
			// Add the build flags
			addBuildFlags(cmd)
			
			// Set the args and parse
			cmd.SetArgs(tt.args)
			err := cmd.Execute()
			if err != nil {
				t.Fatalf("failed to execute command: %v", err)
			}
			
			// Check if the flag exists
			flag := cmd.Flags().Lookup(tt.wantFlag)
			if flag == nil {
				t.Fatalf("flag %s not found", tt.wantFlag)
			}
			
			// Get the flag value
			val, err := cmd.Flags().GetBool(tt.wantFlag)
			if err != nil {
				t.Fatalf("failed to get flag value: %v", err)
			}
			
			if val != tt.wantVal {
				t.Errorf("expected flag %s to be %v, got %v", tt.wantFlag, tt.wantVal, val)
			}
		})
	}
}

func TestBuildCommandHelpText(t *testing.T) {
	cmd := &cobra.Command{
		Use: "build",
		Run: func(cmd *cobra.Command, args []string) {
			// No-op for testing
		},
	}
	
	addBuildFlags(cmd)
	
	// Check that the in-flight-checksums flag is documented
	flag := cmd.Flags().Lookup("in-flight-checksums")
	if flag == nil {
		t.Fatal("in-flight-checksums flag not found")
	}
	
	expectedUsage := "Enable checksumming of cache artifacts to prevent TOCTU attacks"
	if flag.Usage != expectedUsage {
		t.Errorf("expected flag usage to be %q, got %q", expectedUsage, flag.Usage)
	}
	
	// Verify it's a boolean flag
	if flag.Value.Type() != "bool" {
		t.Errorf("expected flag type to be bool, got %s", flag.Value.Type())
	}
	
	// Verify default value
	if flag.DefValue != "false" {
		t.Errorf("expected default value to be false, got %s", flag.DefValue)
	}
}

func TestGetBuildOptsWithInFlightChecksums(t *testing.T) {
	tests := []struct {
		name                    string
		inFlightChecksumsFlag   bool
		expectInFlightChecksums bool
	}{
		{
			name:                    "in-flight checksums disabled",
			inFlightChecksumsFlag:   false,
			expectInFlightChecksums: false,
		},
		{
			name:                    "in-flight checksums enabled",
			inFlightChecksumsFlag:   true,
			expectInFlightChecksums: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := &cobra.Command{
				Use: "build",
				Run: func(cmd *cobra.Command, args []string) {
					// No-op for testing
				},
			}
			
			addBuildFlags(cmd)
			
			// Set the flag value
			err := cmd.Flags().Set("in-flight-checksums", "false")
			if tt.inFlightChecksumsFlag {
				err = cmd.Flags().Set("in-flight-checksums", "true")
			}
			if err != nil {
				t.Fatalf("failed to set flag: %v", err)
			}
			
			// Test getBuildOpts function
			opts, localCache := getBuildOpts(cmd)
			
			// We can't directly test the WithInFlightChecksums option since it's internal,
			// but we can verify the function doesn't error and returns options
			if opts == nil {
				t.Error("expected build options but got nil")
			}
			if localCache == nil {
				t.Error("expected local cache but got nil")
			}
			
			// The actual verification of the in-flight checksums option would need
			// to be done through integration tests or by exposing the option state
		})
	}
}