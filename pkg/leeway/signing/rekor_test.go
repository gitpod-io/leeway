package signing

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/go-openapi/strfmt"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/types"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/sigstore/sigstore-go/pkg/testing/ca"
	"github.com/sigstore/sigstore-go/pkg/tlog"
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

type verifiedConflictRekorClient struct {
	t        *testing.T
	sigstore *ca.VirtualSigstore

	proposedEntry models.ProposedEntry
	createCalls   int
	getCalls      int
}

func (v *verifiedConflictRekorClient) CreateLogEntry(params *entries.CreateLogEntryParams, opts ...entries.ClientOption) (*entries.CreateLogEntryCreated, error) {
	v.createCalls++
	v.proposedEntry = params.ProposedEntry
	return nil, rekorConflict(testRekorUUID)
}

func (v *verifiedConflictRekorClient) GetLogEntryByUUID(params *entries.GetLogEntryByUUIDParams, opts ...entries.ClientOption) (*entries.GetLogEntryByUUIDOK, error) {
	v.getCalls++
	require.Equal(v.t, testRekorUUID, params.EntryUUID)
	require.NotNil(v.t, v.proposedEntry)

	entryImpl, err := types.UnmarshalEntry(v.proposedEntry)
	require.NoError(v.t, err)
	canonicalBody, err := types.CanonicalizeEntry(params.Context, entryImpl)
	require.NoError(v.t, err)

	return &entries.GetLogEntryByUUIDOK{
		Payload: models.LogEntry{
			testRekorUUID: verifiedRekorLogEntry(v.t, v.sigstore, canonicalBody),
		},
	}, nil
}

type staticCertificateProvider struct {
	cert *x509.Certificate
}

func (s staticCertificateProvider) GetCertificate(context.Context, sign.Keypair, *sign.CertificateProviderOptions) ([]byte, error) {
	return s.cert.Raw, nil
}

type certificateKeypair struct {
	privateKey crypto.Signer
	hint       []byte
}

func newCertificateKeypair(t *testing.T, privateKey crypto.PrivateKey) *certificateKeypair {
	t.Helper()

	signer, ok := privateKey.(crypto.Signer)
	require.True(t, ok)

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(signer.Public())
	require.NoError(t, err)
	hint := sha256.Sum256(publicKeyBytes)

	return &certificateKeypair{
		privateKey: signer,
		hint:       []byte(base64.StdEncoding.EncodeToString(hint[:])),
	}
}

func (c *certificateKeypair) GetHashAlgorithm() protocommon.HashAlgorithm {
	return protocommon.HashAlgorithm_SHA2_256
}

func (c *certificateKeypair) GetSigningAlgorithm() protocommon.PublicKeyDetails {
	return protocommon.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256
}

func (c *certificateKeypair) GetHint() []byte {
	return c.hint
}

func (c *certificateKeypair) GetKeyAlgorithm() string {
	return "ECDSA"
}

func (c *certificateKeypair) GetPublicKey() crypto.PublicKey {
	return c.privateKey.Public()
}

func (c *certificateKeypair) GetPublicKeyPem() (string, error) {
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(c.privateKey.Public())
	if err != nil {
		return "", err
	}
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})
	return string(publicKeyPEM), nil
}

func (c *certificateKeypair) SignData(_ context.Context, data []byte) ([]byte, []byte, error) {
	digest := sha256.Sum256(data)
	signature, err := c.privateKey.Sign(rand.Reader, digest[:], crypto.SHA256)
	return signature, digest[:], err
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

func verifiedRekorLogEntry(t *testing.T, sigstore *ca.VirtualSigstore, canonicalBody []byte) models.LogEntryAnon {
	t.Helper()

	integratedTime := time.Now().Add(time.Minute).Unix()
	body := base64.StdEncoding.EncodeToString(canonicalBody)

	logID, err := sigstore.RekorLogID()
	require.NoError(t, err)
	inclusionProof, err := sigstore.GetInclusionProof(canonicalBody)
	require.NoError(t, err)
	logIndex := *inclusionProof.LogIndex

	set, err := sigstore.RekorSignPayload(tlog.RekorPayload{
		Body:           body,
		IntegratedTime: integratedTime,
		LogIndex:       logIndex,
		LogID:          logID,
	})
	require.NoError(t, err)

	return models.LogEntryAnon{
		Body:           body,
		IntegratedTime: &integratedTime,
		LogID:          &logID,
		LogIndex:       &logIndex,
		Verification: &models.LogEntryAnonVerification{
			InclusionProof:       inclusionProof,
			SignedEntryTimestamp: strfmt.Base64(set),
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

func TestRecoveringRekor_ConflictRecoveryProducesVerifiableBundle(t *testing.T) {
	ctx := context.Background()
	virtualSigstore, err := ca.NewVirtualSigstore()
	require.NoError(t, err)
	cert, privateKey, err := virtualSigstore.GenerateLeafCert("identity@example.test", "issuer")
	require.NoError(t, err)

	client := &verifiedConflictRekorClient{
		t:        t,
		sigstore: virtualSigstore,
	}
	rekor := newRecoveringRekorV1(recoveringRekorOptions{
		Client:       client,
		RetryOptions: noSleepRetryOptions(1),
	})

	bundle, err := sign.Bundle(
		&sign.DSSEData{
			Data:        []byte(`{"_type":"https://in-toto.io/Statement/v0.1","subject":[]}`),
			PayloadType: "application/vnd.in-toto+json",
		},
		newCertificateKeypair(t, privateKey),
		sign.BundleOptions{
			CertificateProvider: staticCertificateProvider{cert: cert},
			Context:             ctx,
			TransparencyLogs:    []sign.Transparency{rekor},
			TrustedRoot:         virtualSigstore,
		},
	)

	require.NoError(t, err)
	assert.Equal(t, 1, client.createCalls)
	assert.Equal(t, 1, client.getCalls)
	require.Len(t, bundle.VerificationMaterial.TlogEntries, 1)
	assert.NotNil(t, bundle.VerificationMaterial.TlogEntries[0].InclusionProof)
	assert.NotNil(t, bundle.VerificationMaterial.TlogEntries[0].InclusionPromise)
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
