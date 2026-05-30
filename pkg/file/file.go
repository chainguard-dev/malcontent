// Copyright 2025 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package file

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"math"
	"os"
	"sync"
	"sync/atomic"
)

// common values used across malcontent for extracting and reading files.
const (
	DefaultPoolBuffer      int64   = 4 * 1024   // 4KB
	ExtractBuffer          int64   = 64 * 1024  // 64KB
	MaxPoolBuffer          int64   = 128 * 1024 // 128KB
	MaxBytes               int64   = 1 << 32    // 4096MB
	ReadBuffer             int64   = 64 * 1024  // 64KB
	ZipBuffer              int64   = 2 * 1024   // 2KB
	DefaultMaxArchiveBytes int64   = 16 << 30   // 16GiB total uncompressed across all entries
	DefaultMaxArchiveRatio float64 = 100        // uncompressed/input expansion ceiling
)

// ErrArchiveBytesCap is returned by ArchiveCounter.Add once the running total
// of uncompressed bytes would exceed ArchiveCounter.MaxBytes (seeded from
// DefaultMaxArchiveBytes when the caller supplies no override). Extractors wrap
// this sentinel and abort the in-flight extraction.
var ErrArchiveBytesCap = errors.New("archive total uncompressed bytes exceeded")

// ErrArchiveRatioCap is returned by ArchiveCounter.Add once the running total
// of uncompressed bytes exceeds InputBytes * MaxRatio.
var ErrArchiveRatioCap = errors.New("archive expansion ratio exceeded")

// ratioOverflowOnce guards a single warning emission when MaxRatio*InputBytes
// would overflow the int64 byte domain. Operators see the unbounded condition
// once per process rather than per archive entry.
var ratioOverflowOnce sync.Once

// ArchiveCounter accumulates uncompressed bytes written by an extractor and
// enforces a byte cap and an expansion-ratio cap. A zero value disables a
// cap; a nil receiver disables accounting entirely so callers may opt out.
//
// Total is updated with atomic semantics so concurrent extractor goroutines
// (e.g., the zip errgroup fan-out) may share a single counter without locks.
type ArchiveCounter struct {
	Total      atomic.Int64
	MaxBytes   int64   // 0 = unlimited
	MaxRatio   float64 // <= 0 = unlimited; ratio measured against InputBytes
	InputBytes int64   // size of the outer archive blob; 0 disables ratio check
}

// Add records additional uncompressed bytes against the counter. A nil
// receiver is a documented no-op so call sites can pass a nil counter to opt
// out without nil-checking. The byte-cap and ratio-cap guards are evaluated
// after the atomic increment; this preserves a single source of truth for
// Total under concurrent writers.
func (c *ArchiveCounter) Add(n int) error {
	if c == nil {
		return nil
	}
	total := c.Total.Add(int64(n))
	if c.MaxBytes > 0 && total > c.MaxBytes {
		return ErrArchiveBytesCap
	}
	// Skip the ratio cap when MaxRatio * InputBytes exceeds the int64 byte
	// domain; this can happen with pathologically large inputs or
	// operator-supplied caps. "Would overflow" is treated as "ratio cap
	// inactive" and logged once so operators can see the unbounded condition.
	// The bytes cap above still applies. InputBytes > 0 is already gated so the
	// threshold is well defined.
	if c.MaxRatio > 0 && c.InputBytes > 0 {
		threshold := c.MaxRatio * float64(c.InputBytes)
		if threshold > math.MaxInt64 {
			ratioOverflowOnce.Do(func() {
				slog.Default().Warn(
					"archive ratio cap disabled — MaxRatio*InputBytes overflows int64",
					"input_bytes", c.InputBytes,
					"max_ratio", c.MaxRatio,
				)
			})
		} else if float64(total) > threshold {
			return ErrArchiveRatioCap
		}
	}
	return nil
}

// Size-class thresholds for the read dispatch. Files at or below
// smallFileMaxBytes use a single-shot read; files at or below
// mediumFileMaxBytes use a buffered copy backed by the caller's buffer;
// anything larger streams through the same buffer up to MaxBytes.
const (
	smallFileMaxBytes  int64 = 64 * 1024        // 64 KiB
	mediumFileMaxBytes int64 = 16 * 1024 * 1024 // 16 MiB
)

// sizeClassEnum tags the read strategy chosen for a given input size.
type sizeClassEnum uint8

const (
	sizeClassSmall sizeClassEnum = iota
	sizeClassMedium
	sizeClassLarge
)

// sizeClass maps a byte count to a read-strategy bucket. Values at or below
// smallFileMaxBytes are small; values at or below mediumFileMaxBytes are
// medium; everything else is large. Negative or oversized values fall
// through to large so the caller still receives a bounded, streaming read.
func sizeClass(n int64) sizeClassEnum {
	switch {
	case n <= smallFileMaxBytes:
		return sizeClassSmall
	case n <= mediumFileMaxBytes:
		return sizeClassMedium
	default:
		return sizeClassLarge
	}
}

// readSmallFile pulls the entire payload through a bytes.Buffer pre-grown to
// the stat-reported size, capped at smallFileMaxBytes. The size is a capacity
// hint only: io.Copy from the capped LimitReader supplies the actual content,
// so a file that grew or shrank between stat and read is read defensively —
// the hint never truncates the result nor zero-pads it. A correct hint avoids
// the incremental regrowth a default-sized buffer would incur.
func readSmallFile(f *os.File, sizeHint int64) ([]byte, error) {
	var b bytes.Buffer
	if sizeHint > 0 {
		if sizeHint > smallFileMaxBytes {
			sizeHint = smallFileMaxBytes
		}
		b.Grow(int(sizeHint))
	}
	if _, err := io.Copy(&b, io.LimitReader(f, smallFileMaxBytes)); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// readBuffered streams the input through the caller-supplied buffer up to
// the supplied byte limit. Returned bytes are the buffer's contents at the
// time of completion; the caller owns the slice.
func readBuffered(f *os.File, buf []byte, limit int64) ([]byte, error) {
	b := &bytes.Buffer{}
	if _, err := io.CopyBuffer(b, io.LimitReader(f, limit), buf); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// GetContents takes a file, reads its contents, and returns them as a slice of bytes.
func GetContents(f *os.File, buf []byte) ([]byte, error) {
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return readBuffered(f, buf, MaxBytes)
	}
	switch sizeClass(info.Size()) {
	case sizeClassSmall:
		return readSmallFile(f, info.Size())
	case sizeClassMedium:
		return readBuffered(f, buf, mediumFileMaxBytes)
	default:
		return readBuffered(f, buf, MaxBytes)
	}
}
