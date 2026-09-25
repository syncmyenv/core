// Package storage abstracts where encrypted blobs live remotely
// (folder, S3/R2, SyncMyEnv server, WebDAV...).
//
// Implementations only ever see ciphertext and opaque IDs — never paths,
// project names or plaintext.
package storage

import (
	"context"
	"errors"
	"io"
)

// ErrNotFound is returned when a blob does not exist.
var ErrNotFound = errors.New("storage: blob not found")

// Backend is a content-addressed store for encrypted blobs.
type Backend interface {
	Put(ctx context.Context, id string, r io.Reader) error
	Get(ctx context.Context, id string) (io.ReadCloser, error)
	Delete(ctx context.Context, id string) error
	List(ctx context.Context, prefix string) ([]string, error)
}
