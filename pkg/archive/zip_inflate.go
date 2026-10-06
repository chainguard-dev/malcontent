// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"bufio"
	"errors"
	"io"
	"sync"

	"github.com/klauspost/compress/flate"
)

// errZipEntryClosed is returned by a read from a zip entry after Close.
var errZipEntryClosed = errors.New("read from a closed zip entry")

// zipInflater is a deflate decoder and the buffered reader it consumes, kept
// together so that both are reused across zip entries.
type zipInflater struct {
	br *bufio.Reader
	fr io.ReadCloser
}

// zipInflaters holds idle *zipInflater values.
var zipInflaters sync.Pool

// newZipInflater is the decompressor ExtractZip registers for deflated
// entries. It runs the same decoder as klauspost/compress/zip's default, which
// reads each entry through a new 4 KiB bufio.Reader and so issues a pread(2)
// per 4 KiB of compressed data; this one reads inputBufferSize bytes at a
// time through a reader it reuses along with the decoder state.
func newZipInflater(r io.Reader) io.ReadCloser {
	if zi, ok := zipInflaters.Get().(*zipInflater); ok {
		zi.br.Reset(r)
		if rs, ok := zi.fr.(flate.Resetter); ok && rs.Reset(zi.br, nil) == nil {
			return &zipEntryReader{zi: zi}
		}
	}
	br := bufio.NewReaderSize(r, inputBufferSize)
	return &zipEntryReader{zi: &zipInflater{br: br, fr: flate.NewReader(br)}}
}

// zipEntryReader decodes one entry. Close returns its inflater to the pool
// once, after which the entry no longer reaches it.
type zipEntryReader struct {
	mu sync.Mutex
	zi *zipInflater
}

func (r *zipEntryReader) Read(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.zi == nil {
		return 0, errZipEntryClosed
	}
	return r.zi.fr.Read(p)
}

func (r *zipEntryReader) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.zi == nil {
		return nil
	}
	err := r.zi.fr.Close()
	// Drop the entry's reader so the pool does not keep the archive alive.
	r.zi.br.Reset(nil)
	zipInflaters.Put(r.zi)
	r.zi = nil
	return err
}
