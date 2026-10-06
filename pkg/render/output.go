// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package render

import (
	"bytes"
	"fmt"
	"io"
	"sync"
)

// maxPooledBuffer caps the capacity of a buffer returned to bufferPool, so one
// unusually large report does not keep its memory for the rest of the run.
const maxPooledBuffer = 1 << 20

var bufferPool = sync.Pool{New: func() any { return new(bytes.Buffer) }}

// getBuffer returns an empty buffer from bufferPool.
func getBuffer() *bytes.Buffer {
	if b, ok := bufferPool.Get().(*bytes.Buffer); ok {
		return b
	}
	return new(bytes.Buffer)
}

// putBuffer empties b and returns it to bufferPool.
func putBuffer(b *bytes.Buffer) {
	if b.Cap() > maxPooledBuffer {
		return
	}
	b.Reset()
	bufferPool.Put(b)
}

// blockWriter writes each rendered block to w with a single Write while
// holding a lock. Scan workers call File concurrently, so this keeps the
// output of one file from interleaving with another's.
type blockWriter struct {
	mu sync.Mutex
	w  io.Writer
}

// write writes p to w as one block. An empty p writes nothing.
func (bw *blockWriter) write(p []byte) error {
	if len(p) == 0 {
		return nil
	}
	bw.mu.Lock()
	defer bw.mu.Unlock()
	_, err := bw.w.Write(p)
	return err
}

// flush writes the contents of b as one block and empties b for the next one.
func (bw *blockWriter) flush(b *bytes.Buffer) error {
	err := bw.write(b.Bytes())
	b.Reset()
	return err
}

// scanning writes the line the terminal renderers print before scanning path.
// Like the Scanning method that calls it, it has no way to report a write error.
func (bw *blockWriter) scanning(path string) {
	_ = bw.write(fmt.Appendf(nil, "🔎 Scanning %q\n", path))
}
