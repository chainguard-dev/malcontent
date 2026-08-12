// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"archive/tar"
	"errors"
	"io"
	"math"
)

const tarBlockSize = 512

// ErrUnaccountedBytes reports that an archive held bytes which never reached the
// extraction directory. Callers treat it as an extraction failure so that the
// archive is retained and scanned as an opaque file, because a payload hidden in
// those bytes would otherwise be deleted along with the archive.
var ErrUnaccountedBytes = errors.New("archive contains bytes that were not extracted")

// maxTrailerAudit bounds how many bytes past the end-of-archive marker are
// examined. It is a var so tests can shrink it.
var maxTrailerAudit int64 = 32 << 20

// auditState tracks which region of the tar byte stream the auditor is in.
type auditState int

const (
	auditHeader auditState = iota
	auditData
	auditPadding
	// auditTrailer is everything after the end-of-archive marker, which must be
	// zero padding to the writer's blocking factor and nothing else.
	auditTrailer
	// auditDisabled stops accounting after a construct the block walk cannot
	// model, so that an unusual archive is not reported as an attack.
	auditDisabled
)

// tarAuditor accounts for every byte of a tar stream by walking it as 512-byte
// blocks in parallel with the extraction loop.
//
// archive/tar surfaces entry content but silently discards two regions: the
// padding between an entry's content and its next block boundary, and anything
// following the end-of-archive marker. Both are viable hiding places for a
// payload, so the auditor verifies they contain only zero bytes.
//
// It is fed via io.TeeReader from the same stream the tar reader consumes, so it
// costs no extra I/O. Write never returns an error, because a TeeReader write
// error surfaces as a read error and would abort an extraction that should be
// allowed to finish; violations accumulate in a sticky field instead.
type tarAuditor struct {
	state      auditState
	blk        [tarBlockSize]byte
	buffered   int
	dataLeft   int64
	padLeft    int64
	zeroBlocks int
	violation  error
}

var _ io.Writer = (*tarAuditor)(nil)

func newTarAuditor() *tarAuditor {
	return &tarAuditor{}
}

// err returns the first accounting violation observed, or nil.
func (a *tarAuditor) err() error {
	return a.violation
}

func (a *tarAuditor) fail(reason string) {
	if a.violation == nil {
		a.violation = errors.New(reason)
	}
}

func (a *tarAuditor) Write(p []byte) (int, error) {
	total := len(p)
	for len(p) > 0 {
		if a.state == auditDisabled || a.violation != nil {
			return total, nil //nolint:nilerr // a violation is reported via err(), never through Write
		}

		switch a.state {
		case auditHeader:
			n := min(tarBlockSize-a.buffered, len(p))
			copy(a.blk[a.buffered:], p[:n])
			a.buffered += n
			p = p[n:]
			if a.buffered == tarBlockSize {
				a.buffered = 0
				a.consumeHeader()
			}

		case auditData:
			n := min(a.dataLeft, int64(len(p)))
			a.dataLeft -= n
			p = p[n:]
			if a.dataLeft == 0 {
				a.state = auditPadding
				if a.padLeft == 0 {
					a.state = auditHeader
				}
			}

		case auditPadding:
			n := min(a.padLeft, int64(len(p)))
			for _, b := range p[:n] {
				if b != 0 {
					// Content between an entry's declared end and its block
					// boundary is never returned by archive/tar.
					a.fail("non-zero bytes in tar entry block padding")
					return total, nil
				}
			}
			a.padLeft -= n
			p = p[n:]
			if a.padLeft == 0 {
				a.state = auditHeader
			}

		case auditTrailer:
			for _, b := range p {
				if b != 0 {
					a.fail("non-zero bytes after tar end-of-archive marker")
					return total, nil
				}
			}
			p = nil

		case auditDisabled:
			return total, nil
		}
	}
	return total, nil
}

// consumeHeader interprets a complete header block and sets up the byte counts
// for the entry that follows it.
func (a *tarAuditor) consumeHeader() {
	if isZeroBlock(a.blk[:]) {
		a.zeroBlocks++
		// Two consecutive zero blocks mark end-of-archive; archive/tar stops
		// reading there and returns io.EOF.
		if a.zeroBlocks >= 2 {
			a.state = auditTrailer
		}
		return
	}
	a.zeroBlocks = 0

	typeflag := a.blk[156]

	// Old GNU sparse entries describe their stored bytes with a sparse map, and
	// continuation blocks for long maps, which this walk does not parse. Report
	// them rather than stopping: silently trusting the rest of the archive would
	// let a single sparse entry switch off padding accounting for every entry
	// that follows it.
	if typeflag == tar.TypeGNUSparse {
		a.fail("GNU sparse entry layout cannot be accounted for")
		return
	}

	size, ok := parseTarSize(a.blk[124:136])
	if !ok {
		// archive/tar rejects the same field, so extraction fails on its own and
		// the archive is retained without the auditor having to say so.
		a.state = auditDisabled
		return
	}

	// Header-only entries carry no data blocks regardless of their size field.
	if size == 0 || isTarHeaderOnlyType(typeflag) {
		a.state = auditHeader
		return
	}

	a.dataLeft = size
	a.padLeft = (tarBlockSize - (size % tarBlockSize)) % tarBlockSize
	a.state = auditData
}

// isTarHeaderOnlyType mirrors the archive/tar internal predicate for entries
// whose content is described entirely by their header.
func isTarHeaderOnlyType(flag byte) bool {
	switch flag {
	case tar.TypeLink, tar.TypeSymlink, tar.TypeChar, tar.TypeBlock, tar.TypeDir, tar.TypeFifo:
		return true
	default:
		return false
	}
}

func isZeroBlock(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// parseTarSize decodes a tar numeric size field, handling both NUL/space padded
// octal and the GNU base-256 encoding used for large values. It reports false
// for anything it cannot decode, which disables accounting rather than treating
// an unfamiliar archive as an attack.
func parseTarSize(b []byte) (int64, bool) {
	if len(b) == 0 {
		return 0, false
	}

	// GNU base-256: the high bit of the first byte is set.
	if b[0]&0x80 != 0 {
		// 0xff would indicate a negative value, which is meaningless for a size.
		if b[0] != 0x80 {
			return 0, false
		}
		var n int64
		for _, c := range b[1:] {
			if n > math.MaxInt64>>8 {
				return 0, false
			}
			n = n<<8 | int64(c)
		}
		if n < 0 {
			return 0, false
		}
		return n, true
	}

	var n int64
	var seenDigit bool
	for _, c := range b {
		if c == 0 || c == ' ' {
			if seenDigit {
				break
			}
			continue
		}
		if c < '0' || c > '7' {
			return 0, false
		}
		if n > math.MaxInt64>>3 {
			return 0, false
		}
		n = n<<3 | int64(c-'0')
		seenDigit = true
	}
	return n, true
}
