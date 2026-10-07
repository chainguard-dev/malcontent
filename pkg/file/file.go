// Copyright 2025 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package file

import (
	"errors"
	"io"
	"log/slog"
	"math"
	"os"
	"slices"
	"sync"
	"sync/atomic"
)

// common values used across malcontent for extracting and reading files.
const (
	ExtractBuffer          int64   = 64 * 1024 // 64KB
	MaxBytes               int64   = 1 << 32   // 4096MB
	DefaultMaxArchiveBytes int64   = 32 << 30  // 32GiB total uncompressed across all entries
	DefaultMaxArchiveRatio float64 = 100       // uncompressed/input expansion ceiling
)

// ErrArchiveBytesCap is returned by ArchiveCounter.Add once the running total
// of uncompressed bytes would exceed ArchiveCounter.MaxBytes (seeded from
// DefaultMaxArchiveBytes when the caller supplies no override). Extractors wrap
// this sentinel and abort the in-flight extraction.
var ErrArchiveBytesCap = errors.New("archive total uncompressed bytes exceeded")

// ErrArchiveRatioCap is returned by ArchiveCounter.Add once the running total
// of uncompressed bytes exceeds InputBytes * MaxRatio.
var ErrArchiveRatioCap = errors.New("archive expansion ratio exceeded")

// logWarn emits warnings through the default slog logger. It is a variable so
// tests can record the messages without replacing the process-wide logger.
var logWarn = slog.Warn

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

	// warnOnce guards a single warning emission per counter when
	// MaxRatio*InputBytes would overflow the int64 byte domain.
	warnOnce sync.Once
}

// Remaining returns the number of bytes still available under the byte cap,
// zero once Total reaches it. A nil receiver or a MaxBytes of zero or less
// (unlimited) returns MaxInt64 so callers can unconditionally use
// min(Remaining(), otherLimit) without nil checks.
func (c *ArchiveCounter) Remaining() int64 {
	if c == nil || c.MaxBytes <= 0 {
		return math.MaxInt64
	}
	return max(c.MaxBytes-c.Total.Load(), 0)
}

// Available returns how many more bytes Add accepts before either cap fails
// it: the smaller of Remaining and what the ratio cap leaves. A nil receiver,
// or a counter with no active cap, returns MaxInt64.
func (c *ArchiveCounter) Available() int64 {
	avail := c.Remaining()
	if c == nil || c.MaxRatio <= 0 || c.InputBytes <= 0 {
		return avail
	}
	// Add fails once the total exceeds the threshold, so a total up to the
	// threshold rounded down is accepted.
	threshold := c.MaxRatio * float64(c.InputBytes)
	if threshold >= math.MaxInt64 {
		return avail
	}
	return min(avail, max(int64(threshold)-c.Total.Load(), 0))
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
	// threshold is well defined. math.MaxInt64 converts to 2^63 as a float64,
	// and no int64 total can exceed a threshold of 2^63 or more, so that
	// boundary already leaves the cap inactive.
	if c.MaxRatio > 0 && c.InputBytes > 0 {
		threshold := c.MaxRatio * float64(c.InputBytes)
		if threshold >= math.MaxInt64 {
			c.warnOnce.Do(func() {
				logWarn(
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

// GetContents returns up to MaxBytes of f's contents, read from its current
// offset, in a newly allocated slice of exactly that length. A regular file is
// read into one allocation sized from Stat; a file that is not regular, or
// cannot be stat'd, is read until EOF.
func GetContents(f *os.File) ([]byte, error) {
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return io.ReadAll(io.LimitReader(f, MaxBytes))
	}
	return readUpTo(f, info.Size(), MaxBytes)
}

// readUpTo returns up to limit bytes of r, expecting size bytes, in a single
// allocation unless r holds more than size bytes.
func readUpTo(r io.Reader, size, limit int64) ([]byte, error) {
	size, want := readLengths(size, limit)
	data, grew, err := fill(r, make([]byte, want), size)
	if !grew {
		return data, err
	}
	return readRest(r, data, limit)
}

// readLengths clamps the expected size to [0, limit] and returns it with the
// length of the first read: one byte past size, so that growth since stat
// shows up without another allocation, unless that would pass limit.
func readLengths(size, limit int64) (int64, int64) {
	size = min(max(size, 0), limit)
	return size, min(size+1, limit)
}

// fill reads len(buf) bytes of r into buf, where len(buf) comes from
// readLengths. It returns the bytes read and whether r holds more than size
// bytes, in which case the rest is still unread; a failed read never reports
// more. A short read means the source ended at or before size, as when a file
// shrinks after stat.
func fill(r io.Reader, buf []byte, size int64) ([]byte, bool, error) {
	n, err := io.ReadFull(r, buf)
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return buf[:n], false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return buf, int64(n) > size, nil
}

// readRest returns a new slice holding data followed by the rest of r, up to
// limit bytes in total.
func readRest(r io.Reader, data []byte, limit int64) ([]byte, error) {
	rest, err := io.ReadAll(io.LimitReader(r, limit-int64(len(data))))
	if err != nil {
		return nil, err
	}
	return slices.Concat(data, rest), nil
}
