// Package gcp holds the adapters onto Google Cloud. Everything with a decision in it lives elsewhere,
// so these stay thin enough to be read rather than unit tested, and are proven against the real services.
package gcp

import (
	"context"
	"errors"
	"fmt"
	"io"

	"cloud.google.com/go/storage"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/iterator"

	"github.com/sindredg/ai-k8s/internal/ledger"
)

// Bucket is a ledger.Store on Cloud Storage.
type Bucket struct {
	handle *storage.BucketHandle
}

// NewBucket opens the verdict ledger. The worker holds object create and read on this bucket and nothing wider.
func NewBucket(ctx context.Context, name string) (*Bucket, func() error, error) {
	client, err := storage.NewClient(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("open cloud storage: %w", err)
	}
	return &Bucket{handle: client.Bucket(name)}, client.Close, nil
}

// Create writes an object only if it does not exist. DoesNotExist is the ifGenerationMatch=0
// precondition, which is what makes the ledger append-only and two workers on one message safe.
func (b *Bucket) Create(ctx context.Context, name string, body []byte) error {
	w := b.handle.Object(name).If(storage.Conditions{DoesNotExist: true}).NewWriter(ctx)
	w.ContentType = "application/json"

	if _, err := w.Write(body); err != nil {
		_ = w.Close()
		return fmt.Errorf("write %s: %w", name, err)
	}
	if err := w.Close(); err != nil {
		if isPreconditionFailed(err) {
			return ledger.ErrExists
		}
		return fmt.Errorf("close %s: %w", name, err)
	}
	return nil
}

// Read returns one object, or ledger.ErrNotFound.
func (b *Bucket) Read(ctx context.Context, name string) ([]byte, error) {
	r, err := b.handle.Object(name).NewReader(ctx)
	if errors.Is(err, storage.ErrObjectNotExist) {
		return nil, ledger.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", name, err)
	}
	defer r.Close()

	body, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", name, err)
	}
	return body, nil
}

// List returns the object names under a prefix.
func (b *Bucket) List(ctx context.Context, prefix string) ([]string, error) {
	it := b.handle.Objects(ctx, &storage.Query{Prefix: prefix})
	var names []string
	for {
		attrs, err := it.Next()
		if errors.Is(err, iterator.Done) {
			return names, nil
		}
		if err != nil {
			return nil, fmt.Errorf("list %s: %w", prefix, err)
		}
		names = append(names, attrs.Name)
	}
}

// isPreconditionFailed reports the 412 the create-only precondition returns on a redelivery.
func isPreconditionFailed(err error) bool {
	var apiErr *googleapi.Error
	return errors.As(err, &apiErr) && apiErr.Code == 412
}
