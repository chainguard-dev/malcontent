// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"bufio"
	"io"
	"sync"

	"github.com/chainguard-dev/malcontent/pkg/file"
	gzip "github.com/klauspost/pgzip"
)

// inputBufferSize is the read size for compressed archive input.
const inputBufferSize = int(file.ExtractBuffer)

// bufferInput returns r buffered for a decompressor. Reading r directly,
// ulikunitz/xz issues a read(2) per byte of input, klauspost/compress/zstd one
// per frame and block header as well as per block, and compress/flate and
// klauspost/pgzip one per 4 KiB. The returned reader also implements
// io.ByteReader, which compress/flate and pgzip then consume directly instead
// of adding a 4 KiB buffer of their own. It reads ahead of the decompressor,
// so nothing else may read from r afterward.
func bufferInput(r io.Reader) *bufio.Reader {
	return bufio.NewReaderSize(r, inputBufferSize)
}

// Each gzip stream decodes ahead of the reader into gzipBlocks buffers of
// gzipBlockSize bytes. pgzip's default of four 1 MiB blocks per stream costs
// 4 MiB even for a small file, and smaller blocks still keep decoding ahead.
const (
	gzipBlockSize = 256 << 10
	gzipBlocks    = 4
)

// newGzipReader returns a pgzip reader of r, buffered by bufferInput.
func newGzipReader(r io.Reader) (*gzip.Reader, error) {
	return gzip.NewReaderN(bufferInput(r), gzipBlockSize, gzipBlocks)
}

// readAheadReaderAt serves ReadAt calls from a window of the underlying reader
// that it refills a window at a time. go-debian decompresses .deb members
// straight from an io.SectionReader over the file, so without it the xz
// decoder issues a pread(2) for every byte of compressed data.
type readAheadReaderAt struct {
	r   io.ReaderAt
	mu  sync.Mutex
	buf []byte // window storage
	off int64  // offset in r of buf[0]
	n   int    // window length: the leading bytes of buf that hold r's data
}

var _ io.ReaderAt = (*readAheadReaderAt)(nil)

// newReadAheadReaderAt returns r read through a window of inputBufferSize
// bytes. The window is allocated rather than pooled, because a decoder
// goroutine that go-debian never stops may still read through it after
// extraction returns.
func newReadAheadReaderAt(r io.ReaderAt) *readAheadReaderAt {
	return &readAheadReaderAt{r: r, buf: make([]byte, inputBufferSize)}
}

// ReadAt implements io.ReaderAt. A read the window cannot serve refills it at
// off, unless the read is at least as large as the window and so gains nothing
// from it.
func (ra *readAheadReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if len(p) == 0 {
		// Nothing to buffer; r still decides whether off is valid.
		return ra.r.ReadAt(p, off)
	}
	ra.mu.Lock()
	defer ra.mu.Unlock()

	total := 0
	for len(p) > 0 {
		if off >= ra.off && off < ra.off+int64(ra.n) {
			n := copy(p, ra.buf[off-ra.off:ra.n])
			total += n
			p = p[n:]
			off += int64(n)
			continue
		}
		if len(p) >= len(ra.buf) {
			n, err := ra.r.ReadAt(p, off)
			return total + n, err
		}
		n, err := ra.r.ReadAt(ra.buf, off)
		ra.off, ra.n = off, n
		// A short fill keeps the bytes it got. Reading past them asks r again,
		// so r's reason for stopping is reported once nothing is left.
		if n == 0 {
			return total, err
		}
	}
	return total, nil
}
