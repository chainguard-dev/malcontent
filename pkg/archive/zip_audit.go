// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"bufio"
	"bytes"
	"cmp"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"math"
	"slices"

	"github.com/klauspost/compress/flate"
)

const (
	// zipEOCDLen is the fixed size of the end-of-central-directory record.
	zipEOCDLen = 22
	// zipMaxCommentLen is the largest archive comment the format can express.
	zipMaxCommentLen = 65535
	// zipLocalHeaderLen is the fixed size of a local file header.
	zipLocalHeaderLen = 30
	// zipCentralHeaderLen is the fixed size of a central directory header.
	zipCentralHeaderLen = 46
	// zip64Sentinel marks a field whose real value lives in the zip64 record.
	zip64Sentinel = 0xFFFFFFFF
	// zipDataDescriptorMax is the longest data descriptor: a signature, a
	// CRC-32, and two 64-bit sizes.
	zipDataDescriptorMax = 24
)

var (
	zipEOCDSignature        = []byte("PK\x05\x06")
	zip64LocatorSignature   = []byte("PK\x06\x07")
	zip64EndSignature       = []byte("PK\x06\x06")
	zipCentralSignature     = []byte("PK\x01\x02")
	zipDescriptorSignature  = []byte("PK\x07\x08")
	errNotZip               = errors.New("no zip end-of-central-directory record")
	errZipDirectoryMismatch = errors.New("central directory does not match its end record")
)

// zipLayout is where the parts of a zip archive lie, located the way zip
// readers locate them: from the end-of-central-directory record.
type zipLayout struct {
	// base is what offsets in the archive's records are relative to, which
	// is past any data prepended to the archive when its writer did not
	// account for it.
	base int64
	// cdStart and cdEnd bound the central directory.
	cdStart, cdEnd int64
	// zip64Start is where the zip64 end record begins, or -1.
	zip64Start int64
	// eocdStart is where the end record begins; recordEnd is where it and
	// the archive comment end.
	eocdStart, recordEnd int64
	records              []zipRecord
}

// zipRecord is what the central directory says about one entry.
type zipRecord struct {
	name       string
	flags      uint16
	crc        uint32
	compressed uint64
	local      int64 // the offset of the entry's local header in the file
}

// readZipLayout locates the parts of the zip archive in r, of size bytes, as
// archive/zip locates them, and reads its central directory.
func readZipLayout(r io.ReaderAt, size int64) (*zipLayout, error) {
	if size < zipEOCDLen {
		return nil, errNotZip
	}
	tailLen := min(int64(zipEOCDLen+zipMaxCommentLen), size)
	tail := make([]byte, tailLen)
	if _, err := r.ReadAt(tail, size-tailLen); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	idx := findZipEOCD(tail)
	if idx < 0 {
		return nil, errNotZip
	}
	end := tail[idx:]
	l := &zipLayout{zip64Start: -1, eocdStart: size - tailLen + int64(idx)}
	l.recordEnd = l.eocdStart + zipEOCDLen + int64(binary.LittleEndian.Uint16(end[20:]))
	records := uint64(binary.LittleEndian.Uint16(end[10:]))
	cdSize := uint64(binary.LittleEndian.Uint32(end[12:]))
	cdOffset := uint64(binary.LittleEndian.Uint32(end[16:]))

	dirEnd := l.eocdStart
	if records == 0xffff || cdSize == zip64Sentinel || cdOffset == zip64Sentinel {
		if p, z64, ok := readZip64End(r, l.eocdStart); ok {
			records, cdSize, cdOffset = z64[0], z64[1], z64[2]
			dirEnd, l.zip64Start = p, p
		}
	}
	dirSize, dirOffset := clampInt64(cdSize), clampInt64(cdOffset)
	if dirSize > size || dirOffset > size {
		return nil, errZipDirectoryMismatch
	}
	l.base = dirEnd - dirSize - dirOffset
	if o := l.base + dirOffset; o < 0 || o >= size {
		return nil, errZipDirectoryMismatch
	}
	// As archive/zip does, an end record that implies data was prepended
	// gives way to a central directory found where it says, unmoved.
	if l.base > 0 && hasSignature(r, dirOffset, zipCentralSignature) {
		l.base = 0
	}
	l.cdStart = l.base + dirOffset
	l.cdEnd = l.cdStart + dirSize
	if cdSize == 0 {
		return l, nil
	}
	if !hasSignature(r, l.cdStart, zipCentralSignature) {
		return nil, errZipDirectoryMismatch
	}
	cd := make([]byte, cdSize)
	if _, err := r.ReadAt(cd, l.cdStart); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	l.records = parseZipCentral(cd, l.base, records)
	return l, nil
}

// readZip64End reads the zip64 end record a locator just before eocdStart
// names, returning where it begins and its entry count, central directory
// size, and central directory offset.
func readZip64End(r io.ReaderAt, eocdStart int64) (int64, [3]uint64, bool) {
	var vals [3]uint64
	if eocdStart < 20 {
		return 0, vals, false
	}
	loc := make([]byte, 20)
	if _, err := r.ReadAt(loc, eocdStart-20); err != nil || !bytes.Equal(loc[:4], zip64LocatorSignature) {
		return 0, vals, false
	}
	p := clampInt64(binary.LittleEndian.Uint64(loc[8:]))
	if p > eocdStart {
		return 0, vals, false
	}
	rec := make([]byte, 56)
	if _, err := r.ReadAt(rec, p); err != nil || !bytes.Equal(rec[:4], zip64EndSignature) {
		return 0, vals, false
	}
	vals = [3]uint64{binary.LittleEndian.Uint64(rec[32:]), binary.LittleEndian.Uint64(rec[40:]), binary.LittleEndian.Uint64(rec[48:])}
	return p, vals, true
}

// parseZipCentral reads up to count records from the central directory cd,
// stopping at the first that does not parse.
func parseZipCentral(cd []byte, base int64, count uint64) []zipRecord {
	var out []zipRecord
	for p := 0; uint64(len(out)) < count && p+zipCentralHeaderLen <= len(cd); {
		rec := cd[p:]
		if !bytes.HasPrefix(rec, zipCentralSignature) {
			break
		}
		nameLen := int(binary.LittleEndian.Uint16(rec[28:]))
		extraLen := int(binary.LittleEndian.Uint16(rec[30:]))
		commentLen := int(binary.LittleEndian.Uint16(rec[32:]))
		recLen := zipCentralHeaderLen + nameLen + extraLen + commentLen
		if p+recLen > len(cd) {
			break
		}
		r := zipRecord{
			name:       string(rec[zipCentralHeaderLen : zipCentralHeaderLen+nameLen]),
			flags:      binary.LittleEndian.Uint16(rec[8:]),
			crc:        binary.LittleEndian.Uint32(rec[16:]),
			compressed: uint64(binary.LittleEndian.Uint32(rec[20:])),
		}
		uncompressed := uint64(binary.LittleEndian.Uint32(rec[24:]))
		local := uint64(binary.LittleEndian.Uint32(rec[42:]))
		// The zip64 extra field holds, in order, the values whose fields
		// hold the sentinel.
		extra := rec[zipCentralHeaderLen+nameLen : zipCentralHeaderLen+nameLen+extraLen]
		for len(extra) >= 4 {
			id, n := binary.LittleEndian.Uint16(extra), int(binary.LittleEndian.Uint16(extra[2:]))
			if 4+n > len(extra) {
				break
			}
			if id == 0x0001 {
				field := extra[4 : 4+n]
				for _, v := range []*uint64{&uncompressed, &r.compressed, &local} {
					if *v == zip64Sentinel && len(field) >= 8 {
						*v = binary.LittleEndian.Uint64(field)
						field = field[8:]
					}
				}
			}
			extra = extra[4+n:]
		}
		r.local = base + clampInt64(local)
		out = append(out, r)
		p += recLen
	}
	return out
}

// clampInt64 returns u as an int64, or the largest int64 when u exceeds it,
// so that sizes and offsets an archive declares compare safely with real
// ones.
func clampInt64(u uint64) int64 {
	return int64(min(u, math.MaxInt64)) // #nosec G115 -- clamped to MaxInt64 first
}

func hasSignature(r io.ReaderAt, off int64, sig []byte) bool {
	got := make([]byte, len(sig))
	_, err := r.ReadAt(got, off)
	return err == nil && bytes.Equal(got, sig)
}

// findZipEOCD locates the end-of-central-directory record the way zip readers
// do: the last signature whose declared comment length fits in the tail.
func findZipEOCD(tail []byte) int {
	for i := len(tail) - zipEOCDLen; i >= 0; i-- {
		if !bytes.Equal(tail[i:i+4], zipEOCDSignature) {
			continue
		}
		commentLen := int(binary.LittleEndian.Uint16(tail[i+20:]))
		if i+zipEOCDLen+commentLen <= len(tail) {
			return i
		}
	}
	return -1
}

// zipSpan is a region of an archive, [start, end).
type zipSpan struct {
	start, end int64
}

// auditRegions accounts for every byte of the archive, of size bytes: the
// entries the central directory lists, from each local header to the end of
// its data, the central directory, the zip64 records, and the end record with
// its comment. A local entry the central directory omits, which streaming
// readers extract, is extracted too when it is stored or deflated. Any byte
// still unaccounted for, such as data prepended to the archive or appended
// after it, is reported as ErrUnaccountedBytes, so that the archive is
// retained and scanned as it is.
func (x *zipExtraction) auditRegions(size int64) error {
	l, err := readZipLayout(x.src, size)
	if err != nil {
		// The zip reader opened the archive, so its end record is there;
		// what this walk cannot read is left to the extraction.
		return nil //nolint:nilerr // best effort
	}
	if l.recordEnd != size {
		return fmt.Errorf("%w: %d bytes follow the end-of-central-directory record", ErrUnaccountedBytes, size-l.recordEnd)
	}

	spans := []zipSpan{{start: l.cdStart, end: l.cdEnd}, {start: l.eocdStart, end: l.recordEnd}}
	if l.zip64Start >= 0 {
		spans = append(spans, zipSpan{start: l.zip64Start, end: l.eocdStart})
	}
	src := newReadAheadReaderAt(x.src)
	slices.SortFunc(l.records, func(a, b zipRecord) int { return cmp.Compare(a.local, b.local) })
	for _, r := range l.records {
		dataStart, ok := zipDataStart(src, r.local)
		if !ok {
			continue
		}
		dataEnd := dataStart + clampInt64(r.compressed)
		if r.flags&0x8 != 0 {
			dataEnd += zipDescriptorLen(src, dataEnd, r)
		}
		spans = append(spans, zipSpan{start: r.local, end: dataEnd})
	}

	var unaccounted int64
	for _, gap := range zipGaps(spans, size) {
		unaccounted += x.recoverLocalEntries(src, gap[0], gap[1])
	}
	if unaccounted > 0 {
		return fmt.Errorf("%w: %d bytes lie outside every entry", ErrUnaccountedBytes, unaccounted)
	}
	return nil
}

// zipDataStart returns where the data of the entry whose local header is at
// off begins.
func zipDataStart(r io.ReaderAt, off int64) (int64, bool) {
	hdr := make([]byte, zipLocalHeaderLen)
	if _, err := r.ReadAt(hdr, off); err != nil || !bytes.Equal(hdr[:4], zipLocalMagic) {
		return 0, false
	}
	n := int64(binary.LittleEndian.Uint16(hdr[26:])) + int64(binary.LittleEndian.Uint16(hdr[28:]))
	return off + zipLocalHeaderLen + n, true
}

// zipDescriptorLen returns the length of the data descriptor at pos that
// matches the CRC-32 and compressed size the central directory gives r, in
// any of the forms writers use: with or without a signature, with 32-bit or
// 64-bit sizes. It returns 0 when none matches.
func zipDescriptorLen(src io.ReaderAt, pos int64, r zipRecord) int64 {
	b := make([]byte, zipDataDescriptorMax)
	n, _ := src.ReadAt(b, pos)
	b = b[:n]
	for _, sig := range []int{4, 0} {
		if sig == 4 && !bytes.HasPrefix(b, zipDescriptorSignature) {
			continue
		}
		for _, wide := range []bool{false, true} {
			fields := b[sig:]
			need := 12
			if wide {
				need = 20
			}
			if len(fields) < need || binary.LittleEndian.Uint32(fields) != r.crc {
				continue
			}
			size := uint64(binary.LittleEndian.Uint32(fields[4:]))
			if wide {
				size = binary.LittleEndian.Uint64(fields[4:])
			}
			if size == r.compressed {
				return int64(sig + need)
			}
		}
	}
	return 0
}

// zipGaps returns the regions of [0, size) no span covers.
func zipGaps(spans []zipSpan, size int64) [][2]int64 {
	slices.SortFunc(spans, func(a, b zipSpan) int { return cmp.Compare(a.start, b.start) })
	var gaps [][2]int64
	var pos int64
	for _, s := range spans {
		if s.start > pos {
			gaps = append(gaps, [2]int64{pos, s.start})
		}
		pos = max(pos, s.end)
	}
	if pos < size {
		gaps = append(gaps, [2]int64{pos, size})
	}
	return gaps
}

// recoverLocalEntries extracts the stored or deflated local entries that
// begin the region [start, end) one after another, and returns how many bytes
// of the region they leave unaccounted for.
func (x *zipExtraction) recoverLocalEntries(r io.ReaderAt, start, end int64) int64 {
	pos := start
	for pos < end {
		next, ok := x.recoverLocalEntry(r, pos, end)
		if !ok {
			break
		}
		pos = next
	}
	return end - pos
}

// recoverLocalEntry extracts the local entry at pos, which must end by end,
// returning where it ends, data descriptor included.
func (x *zipExtraction) recoverLocalEntry(r io.ReaderAt, pos, end int64) (int64, bool) {
	hdr := make([]byte, zipLocalHeaderLen)
	if _, err := r.ReadAt(hdr, pos); err != nil || !bytes.Equal(hdr[:4], zipLocalMagic) {
		return 0, false
	}
	flags := binary.LittleEndian.Uint16(hdr[6:])
	method := binary.LittleEndian.Uint16(hdr[8:])
	compressed := int64(binary.LittleEndian.Uint32(hdr[18:]))
	nameLen := int64(binary.LittleEndian.Uint16(hdr[26:]))
	extraLen := int64(binary.LittleEndian.Uint16(hdr[28:]))
	dataStart := pos + zipLocalHeaderLen + nameLen + extraLen
	if dataStart > end || compressed == zip64Sentinel {
		return 0, false
	}
	nameBuf := make([]byte, nameLen)
	if _, err := r.ReadAt(nameBuf, pos+zipLocalHeaderLen); err != nil {
		return 0, false
	}
	known := flags&0x8 == 0 || compressed > 0
	data := io.NewSectionReader(r, dataStart, end-dataStart)

	var content io.Reader
	var consumed func() int64
	switch {
	case method == 0 && known && dataStart+compressed <= end:
		content = io.LimitReader(data, compressed)
		consumed = func() int64 { return compressed }
	case method == 8:
		counted := &countingByteReader{r: bufio.NewReaderSize(data, inputBufferSize)}
		limit := end - dataStart
		if known {
			limit = min(limit, compressed)
		}
		counted.limit = limit
		content = flate.NewReader(counted)
		consumed = func() int64 { return counted.n }
	default:
		return 0, false
	}

	clean, _ := fileEntryName(string(nameBuf))
	x.logger.Warnf("extracting local zip entry %q, which the central directory omits", string(nameBuf))
	out, _, err := x.paths.createFile(clean)
	if err != nil {
		return 0, false
	}
	defer out.Close()
	buf := extractPool.Get()
	defer extractPool.Put(buf)
	if err := x.budget.Entry(); err != nil {
		return 0, false
	}
	sum := crc32.NewIEEE()
	if err := copyCounted(x.ctx, out, io.TeeReader(content, sum), x.budget, buf, clean); err != nil {
		return 0, false
	}
	next := dataStart + consumed()
	if flags&0x8 != 0 {
		next += zipDescriptorLen(r, next, zipRecord{crc: sum.Sum32(), compressed: uint64(max(consumed(), 0))})
	}
	return next, next <= end
}

// countingByteReader counts the bytes a decompressor consumes, up to limit,
// reading them one at a time, as compress/flate does from an io.ByteReader.
type countingByteReader struct {
	r     *bufio.Reader
	n     int64
	limit int64
}

func (c *countingByteReader) ReadByte() (byte, error) {
	if c.n >= c.limit {
		return 0, io.EOF
	}
	b, err := c.r.ReadByte()
	if err == nil {
		c.n++
	}
	return b, err
}

func (c *countingByteReader) Read(p []byte) (int, error) {
	if c.n >= c.limit {
		return 0, io.EOF
	}
	p = p[:min(int64(len(p)), c.limit-c.n)]
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}
