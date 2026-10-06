// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package file

import (
	"errors"
	"io"
	"math/bits"
	"os"
	"slices"
	"sync"
)

// mapThreshold is the size, in bytes, above which ReadContents memory-maps a
// file. yara-x's Scanner.ScanFile (v1.21.0, Scanner::load_file) maps exactly
// the files larger than 32,000,000 bytes and reads smaller ones, so mapping
// the same files keeps the exposure to a file truncated while mapped, which
// faults on access, what it was. Smaller files are read into pooled buffers.
const mapThreshold int64 = 32_000_000

// errNotMappable reports a file that mapFile leaves to the read path: one that
// is not regular, is empty, or is too large to address, or any file on a
// platform without memory mapping.
var errNotMappable = errors.New("file cannot be memory-mapped")

// maxPoolShift bounds pooled read buffers at 1<<maxPoolShift bytes (32 MiB),
// enough for every file at or below mapThreshold plus the byte read past it.
// Larger reads, which happen only when a file grows after stat or cannot be
// mapped, allocate directly.
const maxPoolShift = 25

// bufferPools holds read buffers by size class: bufferPools[k] holds buffers
// of exactly 1<<k bytes. Buffers of larger classes are not pooled.
var bufferPools [maxPoolShift + 1]sync.Pool

// Contents is a read-only view of a regular file's bytes.
//
// A Contents is not safe for concurrent use with its Close method.
type Contents struct {
	data   []byte
	pooled *[]byte // pool buffer backing data, returned by Close
	mapped bool    // data is a memory mapping, released by Close
}

// ReadContents returns the full contents of f, a regular file opened for
// reading whose Stat size is size (> 0). f may be closed as soon as it
// returns.
//
// Files larger than 32,000,000 bytes are memory-mapped whole, at their length
// when mapped, where the platform supports it. Smaller files, and files that
// cannot be mapped, are read from f's current offset (so f should be freshly
// opened) until EOF, up to MaxBytes, which picks up growth since size was
// taken.
func ReadContents(f *os.File, size int64) (*Contents, error) {
	return loadContents(f, size, mapThreshold)
}

// loadContents is ReadContents with the mapping threshold as a parameter:
// files whose size is above mapAbove are mapped where possible.
func loadContents(f *os.File, size, mapAbove int64) (*Contents, error) {
	if size > mapAbove {
		if data, err := mapFile(f); err == nil {
			return &Contents{data: data, mapped: true}, nil
		}
		// Some platforms, filesystems, and file types do not support
		// mapping; reading them returns the same bytes.
	}
	return readPooled(f, size, MaxBytes)
}

// readPooled reads up to limit bytes of r, expecting size bytes, into a
// pooled buffer.
func readPooled(r io.Reader, size, limit int64) (*Contents, error) {
	size, want := readLengths(size, limit)
	bp := getBuffer(want)
	data, grew, err := fill(r, (*bp)[:want], size)
	if err == nil && !grew {
		return &Contents{data: data, pooled: bp}, nil
	}
	if err == nil {
		data, err = readRest(r, data, limit)
	}
	putBuffer(bp)
	if err != nil {
		return nil, err
	}
	return &Contents{data: data}, nil
}

// Bytes returns the contents. The slice is valid until Close and must not be
// modified.
func (c *Contents) Bytes() []byte {
	if c == nil {
		return nil
	}
	// A full slice expression keeps appends by the caller out of a pooled
	// buffer's spare capacity.
	return slices.Clip(c.data)
}

// Close releases the contents. It is safe to call on nil and more than once.
func (c *Contents) Close() error {
	if c == nil {
		return nil
	}
	data, pooled, mapped := c.data, c.pooled, c.mapped
	*c = Contents{}
	if mapped {
		return unmapFile(data)
	}
	putBuffer(pooled)
	return nil
}

// poolClass returns the size class of an n-byte buffer: the smallest k for
// which 1<<k >= n.
func poolClass(n int64) int {
	return bits.Len64(uint64(max(n, 1) - 1))
}

// getBuffer returns a buffer of at least n bytes: a pooled power-of-two buffer
// when n fits a pooled size class, otherwise a new buffer of exactly n bytes.
func getBuffer(n int64) *[]byte {
	k := poolClass(n)
	if k >= len(bufferPools) {
		b := make([]byte, n)
		return &b
	}
	if bp, ok := bufferPools[k].Get().(*[]byte); ok {
		return bp
	}
	b := make([]byte, 1<<k)
	return &b
}

// putBuffer returns a buffer from getBuffer to its pool. Buffers too large to
// pool, and nil, are dropped.
func putBuffer(bp *[]byte) {
	if bp == nil {
		return
	}
	if k := poolClass(int64(cap(*bp))); k < len(bufferPools) {
		bufferPools[k].Put(bp)
	}
}
