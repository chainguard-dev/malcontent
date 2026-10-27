// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	bzip2 "github.com/cosnicolaou/pbzip2"
	gzip "github.com/klauspost/pgzip"

	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"
	"github.com/ulikunitz/xz/lzma"
)

// maxDecoderWindow bounds the history a decoder may keep, which the xz and
// zstd decoders allocate in full as soon as a stream's header declares it,
// whatever the stream then holds. xz -9, the largest xz preset, uses a 64 MiB
// dictionary, and zstd --ultra -22 a 128 MiB window, the largest the
// reference zstd decoder accepts without being told otherwise; 128 MiB admits
// both, while a header of a few bytes declaring a 4 GiB dictionary is
// refused.
const maxDecoderWindow = 128 << 20

// ErrDecoderWindow reports a compressed stream whose header declares more
// decoder history than maxDecoderWindow.
var ErrDecoderWindow = errors.New("declared decoder window exceeds the limit")

// zstdOptions are the options of every zstd decoder: the window cap, and low
// memory mode, which keeps the decoder from allocating ahead of the data.
func zstdOptions() []zstd.DOption {
	return []zstd.DOption{zstd.WithDecoderMaxWindow(maxDecoderWindow), zstd.WithDecoderLowmem(true)}
}

// newZstdReader returns a zstd decoder of r with zstdOptions.
func newZstdReader(r io.Reader) (*zstd.Decoder, error) {
	return zstd.NewReader(r, zstdOptions()...)
}

// bzip2Reader decodes one bzip2 stream with pbzip2, which decodes blocks in
// parallel on goroutines that block on an internal pipe until every
// decompressed byte has been read. Close cancels them and reads once more,
// which makes the reader close that pipe and wait for them, so returning early
// leaves none blocked. pbzip2 buffers its input itself, a whole bzip2 block at
// a time.
//
// recoverExtractor cannot reach those goroutines, but the three panics in
// pbzip2 v1.0.6's internal/bzip2/bzip2.go guard invariants no input reaches:
// newMTFDecoderWithRange gets a Huffman tree count checked to be 2 to 6 at
// line 373; newMTFDecoder gets at most 256 symbols, read from a 16x16 bitmap;
// and newHuffmanTree gets numSymbols+2 lengths, with numSymbols from 1 to 256
// because line 366 rejects 0, so 3 to 258.
type bzip2Reader struct {
	r      io.Reader
	cancel context.CancelFunc
}

// newBzip2Reader returns a bzip2 decoder of r, which the caller closes.
func newBzip2Reader(ctx context.Context, r io.Reader) *bzip2Reader {
	ctx, cancel := context.WithCancel(ctx)
	return &bzip2Reader{r: bzip2.NewReader(ctx, r), cancel: cancel}
}

func (b *bzip2Reader) Read(p []byte) (int, error) {
	return b.r.Read(p)
}

// Close stops the decoder's goroutines and waits for them.
func (b *bzip2Reader) Close() error {
	b.cancel()
	_, _ = b.r.Read(nil)
	return nil
}

var xzMagic = []byte{0xfd, '7', 'z', 'X', 'Z', 0x00}

// newXZReader returns an xz decoder of the stream in r, of size bytes, after
// checkXZ has walked it. r is read once to check it and again to decode it.
func newXZReader(r io.ReaderAt, size int64) (io.Reader, error) {
	if err := checkXZ(r, size); err != nil {
		return nil, err
	}
	return xz.NewReader(bufferInput(io.NewSectionReader(r, 0, size)))
}

// newLZMAReader returns a decoder of the classic .lzma stream in r after
// checking the dictionary its header declares.
func newLZMAReader(r io.Reader) (io.Reader, error) {
	br := bufferInput(r)
	hdr, err := br.Peek(13)
	if err != nil {
		return nil, fmt.Errorf("lzma header: %w", err)
	}
	if err := checkLZMADict(binary.LittleEndian.Uint32(hdr[1:5])); err != nil {
		return nil, err
	}
	return lzma.NewReader(br)
}

func checkLZMADict(dictCap uint32) error {
	if dictCap > maxDecoderWindow {
		return fmt.Errorf("%w: lzma dictionary of %d bytes", ErrDecoderWindow, dictCap)
	}
	return nil
}

// gzipMembers reads every member of a gzip stream in turn, recording the
// extra and comment fields of each member's header in a sidecar.
type gzipMembers struct {
	gr *gzip.Reader
	br *bufio.Reader
	sc *sidecar
	n  int
}

// newGzipMembers returns a reader of the decompressed members of the gzip
// stream in r.
func newGzipMembers(r io.Reader, sc *sidecar) (*gzipMembers, error) {
	br := bufferInput(r)
	gr, err := gzip.NewReaderN(br, gzipBlockSize, gzipBlocks)
	if err != nil {
		return nil, err
	}
	// One member at a time, so that each member's header is seen. The
	// decompressor reads br a byte at a time, so it stops where the member
	// ends.
	gr.Multistream(false)
	m := &gzipMembers{gr: gr, br: br, sc: sc}
	m.record()
	return m, nil
}

func (m *gzipMembers) record() {
	m.n++
	label := "gzip"
	if m.n > 1 {
		label = fmt.Sprintf("gzip member %d", m.n)
	}
	m.sc.add(label+" extra", m.gr.Extra)
	m.sc.add(label+" comment", []byte(m.gr.Comment))
}

func (m *gzipMembers) Read(p []byte) (int, error) {
	for {
		n, err := m.gr.Read(p)
		if !errors.Is(err, io.EOF) {
			return n, err
		}
		if n > 0 {
			// The next call finds the end of the member again.
			return n, nil
		}
		if err := m.gr.Reset(m.br); err != nil {
			return 0, err
		}
		m.record()
	}
}

func (m *gzipMembers) Close() error {
	return m.gr.Close()
}
