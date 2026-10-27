// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/ulikunitz/xz/lzma"
)

// The walkers in this file read the structure of a compressed stream, its
// frame, block, and chunk headers, without decoding it. Each stops quietly at
// anything it cannot walk: the decoder parses the same bytes in the same
// order, so it rejects them before reaching anything beyond them.

// checkXZ walks the .xz container in r, of size bytes, block by block and
// reports ErrDecoderWindow when an LZMA2 filter declares a dictionary larger
// than maxDecoderWindow, which ulikunitz/xz would allocate in full whatever a
// caller configures.
func checkXZ(r io.ReaderAt, size int64) error {
	br := newHeaderReader(r, size)
	for {
		hdr, ok := br.take(12)
		if !ok || !bytes.Equal(hdr[:6], xzMagic) {
			return nil
		}
		ok, err := walkXZBlocks(br, xzCheckSize(hdr[7]&0x0f))
		if err != nil || !ok {
			return err
		}
		// The stream footer, then any stream padding: zero bytes in groups
		// of four.
		if !br.skip(12) {
			return nil
		}
		for {
			b, ok := br.peek(4)
			if !ok || !bytes.Equal(b, []byte{0, 0, 0, 0}) {
				break
			}
			br.skip(4)
		}
	}
}

// xzCheckSize returns the size of the check field of each block in a stream
// whose header names check type t.
func xzCheckSize(t byte) int {
	if t == 0 {
		return 0
	}
	return 4 << ((t - 1) / 3)
}

// walkXZBlocks walks the blocks of one stream and its index, reporting
// whether it reached the stream footer.
func walkXZBlocks(br *headerReader, checkSize int) (bool, error) {
	for {
		size, ok := br.byte()
		if !ok {
			return false, nil
		}
		if size == 0 {
			return skipXZIndex(br), nil
		}
		rest, ok := br.take((int(size)+1)*4 - 1)
		if !ok {
			return false, nil
		}
		h := append([]byte{size}, rest...)
		ok, err := checkXZBlockHeader(h)
		if err != nil || !ok {
			return false, err
		}
		n, ok := walkLZMA2(br)
		if !ok {
			return false, nil
		}
		unpadded := int64(len(h)) + n
		if !br.skip(int((4-unpadded%4)%4) + checkSize) {
			return false, nil
		}
	}
}

// checkXZBlockHeader examines the filter flags of block header h, reporting
// whether they could be read and ErrDecoderWindow for an oversized LZMA2
// dictionary.
func checkXZBlockHeader(h []byte) (bool, error) {
	flags := h[1]
	fields := h[2 : len(h)-4] // the header ends with its CRC32
	next := func() (uint64, bool) {
		v, n := binary.Uvarint(fields)
		if n <= 0 {
			return 0, false
		}
		fields = fields[n:]
		return v, true
	}
	// The optional compressed and uncompressed sizes precede the filters.
	for _, present := range []bool{flags&0x40 != 0, flags&0x80 != 0} {
		if !present {
			continue
		}
		if _, ok := next(); !ok {
			return false, nil
		}
	}
	for range int(flags&3) + 1 {
		id, ok := next()
		if !ok {
			return false, nil
		}
		propsSize, ok := next()
		if !ok || propsSize > uint64(len(fields)) {
			return false, nil
		}
		props := fields[:propsSize]
		fields = fields[propsSize:]
		if id != 0x21 || len(props) != 1 {
			continue
		}
		dictCap, err := lzma.DecodeDictCap(props[0])
		if err != nil {
			return false, nil //nolint:nilerr // the decoder rejects the same byte
		}
		if dictCap > maxDecoderWindow {
			return false, fmt.Errorf("%w: xz dictionary of %d bytes", ErrDecoderWindow, dictCap)
		}
	}
	return true, nil
}

// walkLZMA2 skips the LZMA2 chunks of one block, returning how many bytes
// they take and whether it reached their end marker.
func walkLZMA2(br *headerReader) (int64, bool) {
	var n int64
	for {
		c, ok := br.byte()
		if !ok {
			return n, false
		}
		n++
		var hdr []byte
		switch {
		case c == 0:
			return n, true
		case c == 1 || c == 2:
			// An uncompressed chunk: its size less one.
			hdr, ok = br.take(2)
		case c >= 0xc0:
			// An LZMA chunk with properties: unpacked and packed sizes less
			// one, then the properties.
			hdr, ok = br.take(5)
		case c >= 0x80:
			hdr, ok = br.take(4)
		default:
			return n, false
		}
		if !ok {
			return n, false
		}
		n += int64(len(hdr))
		// The size of the data that follows, less one: the uncompressed
		// size of an uncompressed chunk, the packed size of an LZMA chunk.
		sizeAt := 0
		if c >= 0x80 {
			sizeAt = 2
		}
		size := int(binary.BigEndian.Uint16(hdr[sizeAt:])) + 1
		if !br.skip(size) {
			return n, false
		}
		n += int64(size)
	}
}

// skipXZIndex skips a stream's index, whose indicator byte was read,
// reporting whether it could.
func skipXZIndex(br *headerReader) bool {
	length := 1
	readVarint := func() (uint64, bool) {
		var v uint64
		for i := range 9 {
			b, ok := br.byte()
			if !ok {
				return 0, false
			}
			length++
			v |= uint64(b&0x7f) << (7 * i)
			if b&0x80 == 0 {
				return v, true
			}
		}
		return 0, false
	}
	count, ok := readVarint()
	if !ok {
		return false
	}
	for range count {
		if _, ok := readVarint(); !ok {
			return false
		}
		if _, ok := readVarint(); !ok {
			return false
		}
	}
	return br.skip((4-length%4)%4 + 4)
}

// zstdSkippableFrames records in sc the content of every skippable frame in
// the zstd stream in r, of size bytes, which the decoder skips.
func zstdSkippableFrames(r io.ReaderAt, size int64, sc *sidecar) {
	br := newHeaderReader(r, size)
	for {
		hdr, ok := br.take(4)
		if !ok {
			return
		}
		switch magic := binary.LittleEndian.Uint32(hdr); {
		case magic&0xfffffff0 == 0x184d2a50:
			length, ok := br.take(4)
			if !ok {
				return
			}
			n := int(binary.LittleEndian.Uint32(length))
			if n > maxSidecarBytes {
				sc.overflow = true
				if !br.skip(n) {
					return
				}
				continue
			}
			data, ok := br.take(n)
			if !ok {
				return
			}
			sc.add("zstd skippable frame", data)
		case magic == 0xfd2fb528:
			if !skipZstdFrame(br) {
				return
			}
		default:
			return
		}
	}
}

// skipZstdFrame skips the rest of a zstd frame whose magic number was read,
// reporting whether it could.
func skipZstdFrame(br *headerReader) bool {
	fhd, ok := br.byte()
	if !ok {
		return false
	}
	single := fhd&0x20 != 0
	skip := []int{0, 1, 2, 4}[fhd&3] + []int{0, 2, 4, 8}[fhd>>6]
	if !single {
		skip++ // window descriptor
	} else if fhd>>6 == 0 {
		skip++ // a single segment frame always holds its content size
	}
	if !br.skip(skip) {
		return false
	}
	for {
		bh, ok := br.take(3)
		if !ok {
			return false
		}
		v := uint32(bh[0]) | uint32(bh[1])<<8 | uint32(bh[2])<<16
		n := int(v >> 3)
		switch (v >> 1) & 3 {
		case 1: // RLE: one byte repeated
			n = 1
		case 3:
			return false
		}
		if !br.skip(n) {
			return false
		}
		if v&1 != 0 {
			break
		}
	}
	return fhd&0x04 == 0 || br.skip(4)
}

// headerReaderWindow is how much of a stream a headerReader reads at once.
const headerReaderWindow = 4 << 10

// headerReader reads the headers of a compressed stream in r, of size bytes,
// through a small window, and skips the data between them without reading
// it, so that walking a stream's structure costs a read per header rather
// than a read of the whole stream.
type headerReader struct {
	r      io.ReaderAt
	size   int64
	off    int64  // the offset of the next byte
	buf    []byte // the window
	bufOff int64  // the offset of buf[0]
}

func newHeaderReader(r io.ReaderAt, size int64) *headerReader {
	return &headerReader{r: r, size: size}
}

// peek returns the next n bytes without consuming them, reporting false when
// the stream holds fewer.
func (h *headerReader) peek(n int) ([]byte, bool) {
	if n < 0 || h.off+int64(n) > h.size {
		return nil, false
	}
	if h.off < h.bufOff || h.off+int64(n) > h.bufOff+int64(len(h.buf)) {
		want := int(min(int64(max(n, headerReaderWindow)), h.size-h.off))
		if cap(h.buf) < want {
			h.buf = make([]byte, want)
		}
		got, _ := h.r.ReadAt(h.buf[:want], h.off)
		h.buf, h.bufOff = h.buf[:got], h.off
		if got < n {
			return nil, false
		}
	}
	i := h.off - h.bufOff
	return h.buf[i : i+int64(n)], true
}

// take returns and consumes the next n bytes. The bytes are valid until the
// next call.
func (h *headerReader) take(n int) ([]byte, bool) {
	b, ok := h.peek(n)
	if ok {
		h.off += int64(n)
	}
	return b, ok
}

func (h *headerReader) byte() (byte, bool) {
	b, ok := h.take(1)
	if !ok {
		return 0, false
	}
	return b[0], true
}

// skip consumes the next n bytes without reading them.
func (h *headerReader) skip(n int) bool {
	if n < 0 || h.off+int64(n) > h.size {
		h.off = h.size
		return false
	}
	h.off += int64(n)
	return true
}
