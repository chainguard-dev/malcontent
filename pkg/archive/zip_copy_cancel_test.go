// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"testing"

	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/malcontent/pkg/file"
	zip "github.com/klauspost/compress/zip"
)

// zipCountdownCtx answers Err with nil for the first live calls and with
// context.Canceled afterward, so a test chooses which cancellation check
// observes the cancellation.
type zipCountdownCtx struct {
	context.Context
	live  int
	calls int
}

func (c *zipCountdownCtx) Err() error {
	c.calls++
	if c.calls > c.live {
		return context.Canceled
	}
	return nil
}

// TestZipExtractFileCancellationPolling checks that copying an entry checks
// for cancellation before every read, so a cancellation stops writing before
// the next read whatever size the previous read returned. Reads of a stored
// entry fill the buffer until the final partial read, so the stopping points
// are exact; reads of a deflated entry vary in size.
func TestZipExtractFileCancellationPolling(t *testing.T) {
	t.Parallel()

	chunk := int(file.ZipBuffer)
	// live counts the Err calls that report no cancellation: the first is made
	// before the entry is opened, then one before each read. The output file
	// must hold a prefix of the entry between minLen and maxLen bytes long.
	tests := []struct {
		name    string
		method  uint16
		size    int
		live    int
		wantErr error
		noFile  bool
		minLen  int
		maxLen  int
	}{
		{name: "live context copies a stored entry spanning several buffers", method: zip.Store, size: 2*chunk + 3, live: math.MaxInt, minLen: 2*chunk + 3, maxLen: 2*chunk + 3},
		{name: "live context copies a deflated entry spanning several buffers", method: zip.Deflate, size: 3*chunk + 5, live: math.MaxInt, minLen: 3*chunk + 5, maxLen: 3*chunk + 5},
		{name: "cancellation before the entry starts creates no file", method: zip.Store, size: 2 * chunk, live: 0, wantErr: context.Canceled, noFile: true},
		{name: "cancellation before the first read leaves an empty file", method: zip.Store, size: 2 * chunk, live: 1, wantErr: context.Canceled},
		{name: "cancellation after one full read stops before the second", method: zip.Store, size: 3 * chunk, live: 2, wantErr: context.Canceled, minLen: chunk, maxLen: chunk},
		{name: "cancellation after two full reads stops before the third", method: zip.Store, size: 3*chunk + 7, live: 3, wantErr: context.Canceled, minLen: 2 * chunk, maxLen: 2 * chunk},
		{name: "cancellation after a partial read is reported before the next read", method: zip.Store, size: chunk + 100, live: 3, wantErr: context.Canceled, minLen: chunk + 100, maxLen: chunk + 100},
		{name: "cancellation after one deflated read stops before the second", method: zip.Deflate, size: 3 * chunk, live: 2, wantErr: context.Canceled, minLen: 1, maxLen: chunk},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			content := make([]byte, tt.size)
			for i := range content {
				content[i] = byte(i % 251)
			}
			src := filepath.Join(t.TempDir(), "entry.zip")
			zipSpecWrite(t, src, tt.method, []zipSpecEntry{{name: "data.bin", body: string(content)}})

			rc, err := zip.OpenReader(src)
			if err != nil {
				t.Fatalf("OpenReader: %v", err)
			}
			defer rc.Close()

			root, err := openRoot(filepath.Join(t.TempDir(), "out"))
			if err != nil {
				t.Fatalf("openRoot: %v", err)
			}
			defer root.Close()

			ctx := &zipCountdownCtx{Context: t.Context(), live: tt.live}
			err = extractFile(ctx, rc.File[0], root, clog.FromContext(t.Context()), &file.ArchiveCounter{}, nil)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("extractFile error: got = %v, want = %v", err, tt.wantErr)
			}

			got, err := os.ReadFile(filepath.Join(root.Name(), "data.bin"))
			if tt.noFile {
				if !errors.Is(err, fs.ErrNotExist) {
					t.Errorf("output file: got err = %v, want = %v", err, fs.ErrNotExist)
				}
				return
			}
			if err != nil {
				t.Fatalf("read output: %v", err)
			}
			if len(got) < tt.minLen || len(got) > tt.maxLen {
				t.Errorf("output length: got = %d, want = between %d and %d", len(got), tt.minLen, tt.maxLen)
			}
			if !bytes.HasPrefix(content, got) {
				t.Errorf("output: got = %d bytes that differ from the entry, want = a prefix of the entry", len(got))
			}
		})
	}
}
