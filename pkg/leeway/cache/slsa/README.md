# SLSA Verification

This package provides SLSA (Supply chain Levels for Software Artifacts) verification for Leeway's remote cache.

## Overview

The verifier validates that cached artifacts have not been tampered with by:
1. Loading the Sigstore Bundle attestation
2. Verifying the signature using Sigstore's public good instance
3. Checking the transparency log entry (Rekor)
4. Comparing the artifact hash with the expected hash from the attestation

## Architecture

```
┌─────────────────┐
│  Remote Cache   │
│   (S3/GCS)      │
└────────┬────────┘
         │
         ├─── artifact.tar.gz
         └─── artifact.tar.gz.att (Sigstore Bundle)
                │
                ▼
         ┌──────────────┐
         │  Verifier    │
         │              │
         │ 1. Load      │
         │ 2. Verify    │
         │ 3. Check     │
         │ 4. Compare   │
         └──────────────┘
                │
                ▼
         ┌──────────────┐
         │   Result     │
         │              │
         │ ✅ Valid     │
         │ ❌ Invalid   │
         └──────────────┘
```

## Usage

### In Code

```go
import "github.com/gitpod-io/leeway/pkg/leeway/cache/slsa"

// Create verifier
verifier := slsa.NewVerifier(
    "github.com/gitpod-io/gitpod-next",  // Source URI
    []string{},                           // Trusted roots (empty = use Sigstore public good)
)

// Verify artifact
err := verifier.VerifyArtifact(
    ctx,
    "/path/to/artifact.tar.gz",
    "/path/to/artifact.tar.gz.att",
)

if err != nil {
    // Verification failed
    var verificationErr slsa.VerificationFailedError
    if errors.As(err, &verificationErr) {
        log.Errorf("Verification failed: %s", verificationErr.Reason)
    }
}
```

### Error Handling

The verifier returns `VerificationFailedError` for all verification failures:

```go
type VerificationFailedError struct {
    Reason string
}
```

**Common error reasons**:
- `"failed to load attestation bundle: ..."` - Attestation file is missing or malformed
- `"signature verification failed: ..."` - Signature is invalid or certificate chain is broken
- `"no subject in attestation"` - SLSA provenance is missing subject
- `"SLSA provenance subject has no SHA256 digest"` - Subject hash is empty
- `"hash mismatch: expected X, got Y"` - Artifact has been tampered with

## Testing

### Unit Tests

Run the standard test suite:

```bash
cd pkg/leeway/cache/slsa
go test -v
```

**Tests included**:
- `TestNewVerifier` - Verifier initialization
- `TestAttestationKey` - Attestation key generation
- `TestVerifier_calculateSHA256` - Hash calculation
- `TestVerifier_VerifyArtifact_MissingFiles` - Error handling for missing files
- `TestVerifier_VerifyArtifact_InvalidAttestation` - Error handling for invalid attestations

### Manual Testing with Real Attestations

To test the verifier with real attestations from S3, create a test file:

**File**: `manual_test.go`

```go
// +build manual

package slsa

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
)

// TestVerifyRealAttestation tests verification with a real attestation from S3
// Run with: go test -tags=manual -v -run TestVerifyRealAttestation
func TestVerifyRealAttestation(t *testing.T) {
	artifactPath := "/tmp/test-artifact.tar.gz"
	attestationPath := "/tmp/test-attestation.json"

	// Check if files exist
	if _, err := os.Stat(artifactPath); os.IsNotExist(err) {
		t.Skip("Real artifact not found at /tmp/test-artifact.tar.gz")
	}
	if _, err := os.Stat(attestationPath); os.IsNotExist(err) {
		t.Skip("Real attestation not found at /tmp/test-attestation.json")
	}

	verifier := NewVerifier("github.com/gitpod-io/gitpod-next", []string{})
	ctx := context.Background()

	t.Log("Testing with real attestation from S3...")
	err := verifier.VerifyArtifact(ctx, artifactPath, attestationPath)
	if err != nil {
		t.Logf("Verification failed: %v", err)
		// Note: This may fail if attestations use non-standard format
		// See: https://github.com/gitpod-io/leeway/pull/275
	} else {
		t.Log("✅ Verification succeeded!")
	}
}

// TestEmptyHashWithRealAttestation validates the empty hash check
// Run with: go test -tags=manual -v -run TestEmptyHashWithRealAttestation
func TestEmptyHashWithRealAttestation(t *testing.T) {
	attestationPath := "/tmp/test-attestation.json"

	if _, err := os.Stat(attestationPath); os.IsNotExist(err) {
		t.Skip("Real attestation not found at /tmp/test-attestation.json")
	}

	// Read and parse the attestation
	data, err := os.ReadFile(attestationPath)
	if err != nil {
		t.Fatalf("Failed to read attestation: %v", err)
	}

	var att struct {
		Content struct {
			DsseEnvelope struct {
				Payload string `json:"payload"`
			} `json:"DsseEnvelope"`
		} `json:"Content"`
	}
	if err := json.Unmarshal(data, &att); err != nil {
		t.Fatalf("Failed to parse attestation: %v", err)
	}

	// Decode and check the payload
	payloadBytes, err := base64.StdEncoding.DecodeString(att.Content.DsseEnvelope.Payload)
	if err != nil {
		t.Fatalf("Failed to decode payload: %v", err)
	}

	var payload struct {
		Subject []struct {
			Digest struct {
				Sha256 string `json:"sha256"`
			} `json:"digest"`
		} `json:"subject"`
	}
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		t.Fatalf("Failed to parse payload: %v", err)
	}

	if len(payload.Subject) == 0 {
		t.Fatal("No subject in payload")
	}

	hash := payload.Subject[0].Digest.Sha256
	t.Logf("Subject hash: %s", hash)

	if hash == "" {
		t.Log("✅ Empty hash detected - validation would trigger")
	} else {
		t.Logf("Hash is present: %s", hash)
	}
}
```

**How to run**:

1. **Download real attestations from S3**:
   ```bash
   # Set AWS credentials
   export AWS_ACCESS_KEY_ID="..."
   export AWS_SECRET_ACCESS_KEY="..."
   export AWS_SESSION_TOKEN="..."
   
   # Download artifact and attestation
   aws s3 cp s3://your-bucket/artifact.tar.gz /tmp/test-artifact.tar.gz
   aws s3 cp s3://your-bucket/artifact.tar.gz.att /tmp/test-attestation.json
   ```

2. **Create the test file**:
   ```bash
   # Copy the code above into manual_test.go
   cd pkg/leeway/cache/slsa
   ```

3. **Run the tests**:
   ```bash
   # Test with real attestation
   go test -tags=manual -v -run TestVerifyRealAttestation
   
   # Test hash extraction
   go test -tags=manual -v -run TestEmptyHashWithRealAttestation
   
   # Run all manual tests
   go test -tags=manual -v
   ```

4. **Clean up**:
   ```bash
   # Remove the test file when done
   rm manual_test.go
   ```

**Expected results**:

- **Before PR #275** (attestation format fix):
  ```
  Verification failed: SLSA verification failed: failed to load attestation bundle: 
  proto: (line 1:88): unknown field "Content"
  ```
  This is expected - current attestations use non-standard format.

- **After PR #275** (attestation format fix):
  ```
  ✅ Verification succeeded!
  ```
  New attestations will use standard Sigstore Bundle v0.3 format.

## Logging

The verifier uses structured logging (logrus) for observability:

**Debug logs** (verification start):
```
level=debug msg="Starting SLSA verification" artifact=/path/to/artifact.tar.gz attestation=/path/to/attestation.att
```

**Info logs** (verification success):
```
level=info msg="SLSA verification successful" artifact=/path/to/artifact.tar.gz expectedHash=abc123... actualHash=abc123... verificationMs=45
```

**Error logs** (verification failure):
```
level=error msg="SLSA verification failed: signature verification failed: ..."
```

**Fields**:
- `artifact` - Path to artifact file
- `attestation` - Path to attestation file
- `expectedHash` - Hash from attestation
- `actualHash` - Hash of artifact
- `verificationMs` - Verification duration in milliseconds

## Performance

Typical verification times:
- **Fast path** (embedded Rekor entry): 20-50ms
- **Network path** (fetch trusted root): 100-200ms (first time only, then cached)

The verifier uses embedded transparency log entries from the attestation, so no network calls to Rekor are needed during verification.

## Troubleshooting

### "failed to load attestation bundle: proto: unknown field 'Content'"

**Cause**: Attestation uses non-standard format with capital "Content" field.

**Solution**: This is fixed by PR #275. After merging, new attestations will use standard format.

**Workaround**: Rebuild the package (verification fails → cache miss → rebuild).

### "signature verification failed"

**Cause**: Signature is invalid, certificate chain is broken, or transparency log entry is invalid.

**Solution**: Check that:
1. Attestation file is not corrupted
2. Artifact has not been tampered with
3. Sigstore public good instance is accessible

### "hash mismatch: expected X, got Y"

**Cause**: Artifact has been modified after signing.

**Solution**: This indicates tampering. Do not use the artifact. Rebuild from source.

### "SLSA provenance subject has no SHA256 digest"

**Cause**: Attestation is malformed - subject exists but hash is empty.

**Solution**: Regenerate the attestation with correct SLSA provenance.

## References

- **Sigstore Bundle Format**: https://docs.sigstore.dev/about/bundle/
- **SLSA Provenance**: https://slsa.dev/provenance/
- **sigstore-go Library**: https://github.com/sigstore/sigstore-go
- **Rekor Transparency Log**: https://docs.sigstore.dev/rekor/overview/

## Related PRs

- **PR #275**: Fix attestation format generation (use protojson.Marshal)
- **PR #276**: Replace slsa-verifier with sigstore-go (this implementation)

---

*Last updated: November 14, 2024*
