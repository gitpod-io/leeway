package signing

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/go-openapi/strfmt"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testRekorUUID = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

type fakeRecoveringRekorClient struct {
	createErr error
	getResp   *entries.GetLogEntryByUUIDOK
	getErr    error

	createCalls int
	getCalls    int
}

func (f *fakeRecoveringRekorClient) CreateLogEntry(params *entries.CreateLogEntryParams, opts ...entries.ClientOption) (*entries.CreateLogEntryCreated, error) {
	f.createCalls++
	return nil, f.createErr
}

func (f *fakeRecoveringRekorClient) GetLogEntryByUUID(params *entries.GetLogEntryByUUIDParams, opts ...entries.ClientOption) (*entries.GetLogEntryByUUIDOK, error) {
	f.getCalls++
	if f.getErr != nil {
		return nil, f.getErr
	}
	return f.getResp, nil
}

func testDSSEBundle(t *testing.T) (*protobundle.Bundle, []byte, []byte) {
	t.Helper()

	ctx := context.Background()
	keypair, err := sign.NewEphemeralKeypair(nil)
	require.NoError(t, err)

	content := &sign.DSSEData{
		Data:        []byte(`{"_type":"https://in-toto.io/Statement/v0.1","subject":[]}`),
		PayloadType: "application/vnd.in-toto+json",
	}
	signature, digest, err := keypair.SignData(ctx, content.PreAuthEncoding())
	require.NoError(t, err)

	bundle := &protobundle.Bundle{
		MediaType:            "application/vnd.dev.sigstore.bundle.v0.3+json",
		VerificationMaterial: &protobundle.VerificationMaterial{},
	}
	content.Bundle(bundle, signature, digest, keypair.GetHashAlgorithm())

	publicKeyPEM, err := keypair.GetPublicKeyPem()
	require.NoError(t, err)

	_, expectedCanonicalBody, err := createDSSEProposedEntry(ctx, []byte(publicKeyPEM), bundle)
	require.NoError(t, err)

	return bundle, []byte(publicKeyPEM), expectedCanonicalBody
}

func rekorLogEntry(canonicalBody []byte) models.LogEntryAnon {
	integratedTime := int64(123)
	logID := strings.Repeat("a", 64)
	logIndex := int64(1)
	rootHash := strings.Repeat("b", 64)
	treeSize := int64(1)
	checkpoint := "checkpoint"

	return models.LogEntryAnon{
		Body:           base64.StdEncoding.EncodeToString(canonicalBody),
		IntegratedTime: &integratedTime,
		LogID:          &logID,
		LogIndex:       &logIndex,
		Verification: &models.LogEntryAnonVerification{
			InclusionProof: &models.InclusionProof{
				Checkpoint: &checkpoint,
				Hashes:     []string{},
				LogIndex:   &logIndex,
				RootHash:   &rootHash,
				TreeSize:   &treeSize,
			},
			SignedEntryTimestamp: strfmt.Base64("signed-entry-timestamp"),
		},
	}
}

func rekorConflict(uuid string) *entries.CreateLogEntryConflict {
	location := strfmt.URI("https://rekor.example.test/api/v1/log/entries/" + uuid)
	return &entries.CreateLogEntryConflict{
		Location: location,
		Payload: &models.Error{
			Code:    409,
			Message: fmt.Sprintf("an equivalent entry already exists in the transparency log with UUID %s", uuid),
		},
	}
}

func TestRecoveringRekor_ConflictWithMatchingExistingEntrySucceeds(t *testing.T) {
	bundle, publicKeyPEM, expectedCanonicalBody := testDSSEBundle(t)
	client := &fakeRecoveringRekorClient{
		createErr: rekorConflict(testRekorUUID),
		getResp: &entries.GetLogEntryByUUIDOK{
			Payload: models.LogEntry{
				testRekorUUID: rekorLogEntry(expectedCanonicalBody),
			},
		},
	}
	rekor := newRecoveringRekorV1(recoveringRekorOptions{
		Client:       client,
		RetryOptions: noSleepRetryOptions(1),
	})

	err := rekor.GetTransparencyLogEntry(context.Background(), publicKeyPEM, bundle)

	require.NoError(t, err)
	assert.Equal(t, 1, client.createCalls)
	assert.Equal(t, 1, client.getCalls)
	require.Len(t, bundle.VerificationMaterial.TlogEntries, 1)
	assert.Equal(t, expectedCanonicalBody, bundle.VerificationMaterial.TlogEntries[0].CanonicalizedBody)
}

func TestRecoveringRekor_ConflictWithMismatchedExistingEntryFailsClosed(t *testing.T) {
	bundle, publicKeyPEM, expectedCanonicalBody := testDSSEBundle(t)
	_, _, mismatchedCanonicalBody := testDSSEBundle(t)
	require.NotEqual(t, string(expectedCanonicalBody), string(mismatchedCanonicalBody))

	client := &fakeRecoveringRekorClient{
		createErr: rekorConflict(testRekorUUID),
		getResp: &entries.GetLogEntryByUUIDOK{
			Payload: models.LogEntry{
				testRekorUUID: rekorLogEntry(mismatchedCanonicalBody),
			},
		},
	}
	rekor := newRecoveringRekorV1(recoveringRekorOptions{
		Client:       client,
		RetryOptions: noSleepRetryOptions(1),
	})

	err := rekor.GetTransparencyLogEntry(context.Background(), publicKeyPEM, bundle)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not match signed payload")
	assert.Empty(t, bundle.VerificationMaterial.TlogEntries)
}

func TestRecoveringRekor_ConflictFetchFailureFailsClosed(t *testing.T) {
	bundle, publicKeyPEM, _ := testDSSEBundle(t)
	client := &fakeRecoveringRekorClient{
		createErr: rekorConflict(testRekorUUID),
		getErr:    fmt.Errorf("fetch failed"),
	}
	rekor := newRecoveringRekorV1(recoveringRekorOptions{
		Client:       client,
		RetryOptions: noSleepRetryOptions(1),
	})

	err := rekor.GetTransparencyLogEntry(context.Background(), publicKeyPEM, bundle)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to fetch conflicting Rekor entry")
	assert.Empty(t, bundle.VerificationMaterial.TlogEntries)
}

func TestRecoveringRekor_ConflictWithoutProofFailsClosed(t *testing.T) {
	bundle, publicKeyPEM, _ := testDSSEBundle(t)
	client := &fakeRecoveringRekorClient{
		createErr: &entries.CreateLogEntryConflict{
			Payload: &models.Error{
				Code:    409,
				Message: "an equivalent entry already exists in the transparency log",
			},
		},
	}
	rekor := newRecoveringRekorV1(recoveringRekorOptions{
		Client:       client,
		RetryOptions: noSleepRetryOptions(1),
	})

	err := rekor.GetTransparencyLogEntry(context.Background(), publicKeyPEM, bundle)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "did not include an entry UUID")
	assert.Equal(t, 0, client.getCalls)
	assert.Empty(t, bundle.VerificationMaterial.TlogEntries)
}

func TestVerifyRekorConflictEntry_RequiresCanonicalPayloadMatch(t *testing.T) {
	_, _, expectedCanonicalBody := testDSSEBundle(t)
	_, _, mismatchedCanonicalBody := testDSSEBundle(t)
	require.NotEqual(t, string(expectedCanonicalBody), string(mismatchedCanonicalBody))

	_, err := verifyRekorConflictEntry(context.Background(), testRekorUUID, rekorLogEntry(expectedCanonicalBody), expectedCanonicalBody)
	require.NoError(t, err)

	_, err = verifyRekorConflictEntry(context.Background(), testRekorUUID, rekorLogEntry(mismatchedCanonicalBody), expectedCanonicalBody)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not match signed payload")
}
