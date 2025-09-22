package slsa

import (
	"context"
	"fmt"
	"strings"
)

// MockVerifier implements VerifierInterface for testing
type MockVerifier struct {
	// VerifyFunc allows customizing verification behavior in tests
	VerifyFunc func(ctx context.Context, artifactPath, attestationPath string) error
	
	// CallLog tracks verification calls for test assertions
	CallLog []VerifyCall
	
	// DefaultResult controls the default verification result when VerifyFunc is nil
	DefaultResult error
}

// VerifyCall represents a single verification call for testing
type VerifyCall struct {
	ArtifactPath    string
	AttestationPath string
	Context         context.Context
}

// NewMockVerifier creates a new mock verifier for testing
func NewMockVerifier() *MockVerifier {
	return &MockVerifier{
		CallLog: make([]VerifyCall, 0),
	}
}

// VerifyArtifact implements the VerifierInterface
func (m *MockVerifier) VerifyArtifact(ctx context.Context, artifactPath, attestationPath string) error {
	// Record the call for test assertions
	m.CallLog = append(m.CallLog, VerifyCall{
		ArtifactPath:    artifactPath,
		AttestationPath: attestationPath,
		Context:         ctx,
	})
	
	// Use custom verification function if provided
	if m.VerifyFunc != nil {
		return m.VerifyFunc(ctx, artifactPath, attestationPath)
	}
	
	// Return default result
	return m.DefaultResult
}

// Reset clears the call log and resets the mock state
func (m *MockVerifier) Reset() {
	m.CallLog = make([]VerifyCall, 0)
	m.VerifyFunc = nil
	m.DefaultResult = nil
}

// SetVerifyResult sets a simple success/failure result for all verifications
func (m *MockVerifier) SetVerifyResult(err error) {
	m.DefaultResult = err
}

// SetVerifyFunc sets a custom verification function
func (m *MockVerifier) SetVerifyFunc(fn func(ctx context.Context, artifactPath, attestationPath string) error) {
	m.VerifyFunc = fn
}

// GetCallCount returns the number of verification calls made
func (m *MockVerifier) GetCallCount() int {
	return len(m.CallLog)
}

// GetLastCall returns the most recent verification call, or nil if no calls were made
func (m *MockVerifier) GetLastCall() *VerifyCall {
	if len(m.CallLog) == 0 {
		return nil
	}
	return &m.CallLog[len(m.CallLog)-1]
}

// WasCalledWith checks if the verifier was called with specific paths
func (m *MockVerifier) WasCalledWith(artifactPath, attestationPath string) bool {
	for _, call := range m.CallLog {
		if call.ArtifactPath == artifactPath && call.AttestationPath == attestationPath {
			return true
		}
	}
	return false
}

// SimulateVerificationFailure creates a verification function that fails for specific artifacts
func SimulateVerificationFailure(failingArtifacts ...string) func(ctx context.Context, artifactPath, attestationPath string) error {
	return func(ctx context.Context, artifactPath, attestationPath string) error {
		for _, failing := range failingArtifacts {
			if strings.Contains(artifactPath, failing) {
				return fmt.Errorf("mock verification failed for artifact: %s", artifactPath)
			}
		}
		return nil
	}
}

// SimulateContextCancellation creates a verification function that respects context cancellation
func SimulateContextCancellation() func(ctx context.Context, artifactPath, attestationPath string) error {
	return func(ctx context.Context, artifactPath, attestationPath string) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			return nil
		}
	}
}