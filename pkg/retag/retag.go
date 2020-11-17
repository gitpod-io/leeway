package retag

import (
	"context"
	"io"

	"github.com/containerd/containerd/remotes"
)

// CopyManifest downloads the manifest/manifest list of a reference and pushes it to a new reference
func CopyManifest(ctx context.Context, resolver remotes.Resolver, old, new string) error {
	_, desc, err := resolver.Resolve(ctx, old)
	if err != nil {
		return err
	}

	fetcher, err := resolver.Fetcher(ctx, old)
	if err != nil {
		return err
	}
	mfin, err := fetcher.Fetch(ctx, desc)
	if err != nil {
		return err
	}
	defer mfin.Close()

	pusher, err := resolver.Pusher(ctx, new)
	if err != nil {
		return err
	}
	mfout, err := pusher.Push(ctx, desc)
	if err != nil {
		return err
	}
	defer mfout.Close()

	n, err := io.Copy(mfout, mfin)
	if err != nil {
		return err
	}

	err = mfout.Commit(ctx, n, desc.Digest)
	if err != nil {
		return err
	}

	return nil
}
