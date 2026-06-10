package signing

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/go-openapi/runtime"
	"github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protorekor "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	rekorclient "github.com/sigstore/rekor/pkg/client"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/tle"
	"github.com/sigstore/rekor/pkg/types"
	rekordsse "github.com/sigstore/rekor/pkg/types/dsse"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/sigstore/sigstore-go/pkg/util"

	_ "github.com/sigstore/rekor/pkg/types/dsse/v0.0.1"
)

type recoveringRekorClient interface {
	CreateLogEntry(params *entries.CreateLogEntryParams, opts ...entries.ClientOption) (*entries.CreateLogEntryCreated, error)
	GetLogEntryByUUID(params *entries.GetLogEntryByUUIDParams, opts ...entries.ClientOption) (*entries.GetLogEntryByUUIDOK, error)
}

type recoveringRekorOptions struct {
	BaseURL      string
	Timeout      time.Duration
	Retries      uint
	Client       recoveringRekorClient
	RetryOptions RetryOptions
}

type recoveringRekor struct {
	options recoveringRekorOptions
}

func newRecoveringRekorV1(opts recoveringRekorOptions) sign.Transparency {
	if opts.RetryOptions.MaxAttempts == 0 {
		opts.RetryOptions = DefaultRetryOptions()
	}
	return &recoveringRekor{options: opts}
}

func (r *recoveringRekor) GetTransparencyLogEntry(ctx context.Context, keyOrCertPEM []byte, b *v1.Bundle) error {
	proposedEntry, expectedCanonicalBody, err := createDSSEProposedEntry(ctx, keyOrCertPEM, b)
	if err != nil {
		return err
	}

	params := entries.NewCreateLogEntryParams()
	if r.options.Timeout >= 0 {
		timeout := r.options.Timeout
		if timeout == 0 {
			timeout = 30 * time.Second
		}
		params.SetTimeout(timeout)
	}
	params.SetProposedEntry(proposedEntry)
	params.SetContext(ctx)

	if err := r.ensureClient(); err != nil {
		return err
	}

	resp, err := r.options.Client.CreateLogEntry(params)
	if err != nil {
		tlogEntry, recoverErr := r.recoverExistingEntry(ctx, err, expectedCanonicalBody)
		if recoverErr != nil {
			return recoverErr
		}
		appendTlogEntry(b, tlogEntry)
		return nil
	}

	entry, ok := resp.Payload[resp.ETag]
	if !ok {
		return fmt.Errorf("created Rekor entry response missing ETag %q", resp.ETag)
	}

	tlogEntry, err := tle.GenerateTransparencyLogEntry(entry)
	if err != nil {
		return err
	}
	appendTlogEntry(b, tlogEntry)
	return nil
}

func (r *recoveringRekor) ensureClient() error {
	if r.options.Client != nil {
		return nil
	}

	client, err := rekorclient.GetRekorClient(
		r.options.BaseURL,
		rekorclient.WithUserAgent(util.ConstructUserAgent()),
		rekorclient.WithRetryCount(r.options.Retries),
	)
	if err != nil {
		return err
	}
	r.options.Client = client.Entries
	return nil
}

func (r *recoveringRekor) recoverExistingEntry(ctx context.Context, createErr error, expectedCanonicalBody []byte) (*protorekor.TransparencyLogEntry, error) {
	var conflict *entries.CreateLogEntryConflict
	if !errors.As(createErr, &conflict) {
		return nil, createErr
	}

	uuid, err := extractRekorConflictUUID(conflict)
	if err != nil {
		return nil, fmt.Errorf("rekor conflict cannot be verified: %w", err)
	}

	var existingEntry models.LogEntryAnon
	fetchErr := WithRetryOptions(ctx, r.options.RetryOptions, func() error {
		params := entries.NewGetLogEntryByUUIDParams()
		if r.options.Timeout >= 0 {
			timeout := r.options.Timeout
			if timeout == 0 {
				timeout = 30 * time.Second
			}
			params.SetTimeout(timeout)
		}
		params.SetContext(ctx)
		params.SetEntryUUID(uuid)

		resp, err := r.options.Client.GetLogEntryByUUID(params)
		if err != nil {
			return err
		}

		entry, err := selectFetchedRekorEntry(resp.Payload, uuid)
		if err != nil {
			return err
		}
		existingEntry = entry
		return nil
	})
	if fetchErr != nil {
		return nil, fmt.Errorf("failed to fetch conflicting Rekor entry %s: %w", uuid, fetchErr)
	}

	return verifyRekorConflictEntry(ctx, uuid, existingEntry, expectedCanonicalBody)
}

func createDSSEProposedEntry(ctx context.Context, keyOrCertPEM []byte, b *v1.Bundle) (models.ProposedEntry, []byte, error) {
	dsseEnvelope := b.GetDsseEnvelope()
	if dsseEnvelope == nil {
		return nil, nil, fmt.Errorf("unable to find DSSE envelope in bundle")
	}

	artifactBytes, err := json.Marshal(dsseEnvelope)
	if err != nil {
		return nil, nil, err
	}

	dsseType := rekordsse.New()
	proposedEntry, err := dsseType.CreateProposedEntry(ctx, "", types.ArtifactProperties{
		PublicKeyBytes: [][]byte{keyOrCertPEM},
		ArtifactBytes:  artifactBytes,
	})
	if err != nil {
		return nil, nil, err
	}

	entryImpl, err := types.UnmarshalEntry(proposedEntry)
	if err != nil {
		return nil, nil, err
	}
	expectedCanonicalBody, err := types.CanonicalizeEntry(ctx, entryImpl)
	if err != nil {
		return nil, nil, err
	}

	return proposedEntry, expectedCanonicalBody, nil
}

func verifyRekorConflictEntry(ctx context.Context, uuid string, entry models.LogEntryAnon, expectedCanonicalBody []byte) (*protorekor.TransparencyLogEntry, error) {
	tlogEntry, err := tle.GenerateTransparencyLogEntry(entry)
	if err != nil {
		return nil, fmt.Errorf("failed to decode conflicting Rekor entry %s: %w", uuid, err)
	}

	if !bytes.Equal(tlogEntry.CanonicalizedBody, expectedCanonicalBody) {
		return nil, fmt.Errorf("conflicting Rekor entry %s does not match signed payload", uuid)
	}

	proposedEntry, err := models.UnmarshalProposedEntry(bytes.NewReader(tlogEntry.CanonicalizedBody), runtime.JSONConsumer())
	if err != nil {
		return nil, fmt.Errorf("failed to parse canonical Rekor body for %s: %w", uuid, err)
	}
	entryImpl, err := types.UnmarshalEntry(proposedEntry)
	if err != nil {
		return nil, fmt.Errorf("failed to verify canonical Rekor body for %s: %w", uuid, err)
	}
	actualCanonicalBody, err := types.CanonicalizeEntry(ctx, entryImpl)
	if err != nil {
		return nil, fmt.Errorf("failed to canonicalize Rekor body for %s: %w", uuid, err)
	}
	if !bytes.Equal(actualCanonicalBody, expectedCanonicalBody) {
		return nil, fmt.Errorf("conflicting Rekor entry %s canonicalizes to different signed payload", uuid)
	}

	return tlogEntry, nil
}

func appendTlogEntry(b *v1.Bundle, tlogEntry *protorekor.TransparencyLogEntry) {
	if b.VerificationMaterial.TlogEntries == nil {
		b.VerificationMaterial.TlogEntries = []*protorekor.TransparencyLogEntry{}
	}
	b.VerificationMaterial.TlogEntries = append(b.VerificationMaterial.TlogEntries, tlogEntry)
}

func selectFetchedRekorEntry(payload models.LogEntry, uuid string) (models.LogEntryAnon, error) {
	if len(payload) == 0 {
		return models.LogEntryAnon{}, fmt.Errorf("rekor entry %s response was empty", uuid)
	}

	if entry, ok := payload[uuid]; ok {
		return entry, nil
	}
	if len(payload) == 1 {
		for _, entry := range payload {
			return entry, nil
		}
	}

	return models.LogEntryAnon{}, fmt.Errorf("rekor entry %s response did not contain matching UUID", uuid)
}

var rekorUUIDPattern = regexp.MustCompile(`(?i)\b[0-9a-f]{64}(?:[0-9a-f]{16})?\b`)

func extractRekorConflictUUID(conflict *entries.CreateLogEntryConflict) (string, error) {
	if conflict == nil {
		return "", fmt.Errorf("missing Rekor conflict response")
	}

	location := strings.TrimSpace(string(conflict.Location))
	if location != "" {
		if uuid := extractUUIDFromLocation(location); uuid != "" {
			return uuid, nil
		}
	}

	if conflict.Payload != nil {
		if uuid := rekorUUIDPattern.FindString(conflict.Payload.Message); uuid != "" {
			return uuid, nil
		}
	}

	return "", fmt.Errorf("rekor conflict response did not include an entry UUID")
}

func extractUUIDFromLocation(location string) string {
	parsed, err := url.Parse(location)
	if err != nil {
		return ""
	}

	candidate := path.Base(parsed.Path)
	if rekorUUIDPattern.MatchString(candidate) {
		return candidate
	}

	if parsed.Fragment != "" && rekorUUIDPattern.MatchString(parsed.Fragment) {
		return parsed.Fragment
	}

	return ""
}
