// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package file

import (
	"fmt"
	"io"
	"math"
	"os"
	"testing"
)

// benchSizes spans small files through sizes past mapThreshold, comparing the
// read and map strategies at each.
var benchSizes = []int{4 << 10, 64 << 10, 512 << 10, 1 << 20, 4 << 20, 64 << 20}

// sizeName formats n bytes as KiB or MiB.
func sizeName(n int) string {
	if n >= 1<<20 {
		return fmt.Sprintf("%dMiB", n>>20)
	}
	return fmt.Sprintf("%dKiB", n>>10)
}

// touchPages reads one byte from every 4 KiB page of b, as a scan would, so
// that a mapping's page faults count against it.
func touchPages(b []byte) byte {
	var s byte
	for i := 0; i < len(b); i += 4096 {
		s ^= b[i]
	}
	return s
}

// BenchmarkReadContents compares reading into a pooled buffer, mapping, and
// ReadContents' own choice, which maps only above mapThreshold.
func BenchmarkReadContents(b *testing.B) {
	strategies := []struct {
		name    string
		mapOnly bool // the strategy needs memory mapping
		read    func(*os.File, int64) (*Contents, error)
	}{
		{"read", false, func(f *os.File, size int64) (*Contents, error) {
			if _, err := f.Seek(0, io.SeekStart); err != nil {
				return nil, err
			}
			return readPooled(f, size, MaxBytes)
		}},
		{"map", true, func(f *os.File, _ int64) (*Contents, error) {
			data, err := mapFile(f)
			if err != nil {
				return nil, err
			}
			return &Contents{data: data, mapped: true}, nil
		}},
		{"auto", false, func(f *os.File, size int64) (*Contents, error) {
			if _, err := f.Seek(0, io.SeekStart); err != nil {
				return nil, err
			}
			return ReadContents(f, size)
		}},
	}
	for _, s := range strategies {
		for _, n := range benchSizes {
			b.Run(s.name+"/"+sizeName(n), func(b *testing.B) {
				if s.mapOnly && !canMap {
					b.Skip("files are not memory-mapped on this platform")
				}
				f := openTemp(b, deterministicBytes(n))
				b.SetBytes(int64(n))
				b.ReportAllocs()
				var sink byte
				for b.Loop() {
					c, err := s.read(f, int64(n))
					if err != nil {
						b.Fatalf("read: %v", err)
					}
					sink ^= touchPages(c.Bytes())
					if err := c.Close(); err != nil {
						b.Fatalf("Close: %v", err)
					}
				}
				_ = sink
			})
		}
	}
}

// BenchmarkPooledBuffer measures taking a read buffer from its pool and
// returning it, the per-file cost of the pooled read path beyond the read.
func BenchmarkPooledBuffer(b *testing.B) {
	for _, n := range []int{4 << 10, 1 << 20, int(mapThreshold) + 1} {
		b.Run(sizeName(n), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				putBuffer(getBuffer(int64(n)))
			}
		})
	}
}

func BenchmarkGetContents(b *testing.B) {
	for _, n := range []int{4 << 10, 64 << 10, 1 << 20, 4 << 20} {
		b.Run(sizeName(n), func(b *testing.B) {
			f := openTemp(b, deterministicBytes(n))
			b.SetBytes(int64(n))
			b.ReportAllocs()
			for b.Loop() {
				if _, err := f.Seek(0, io.SeekStart); err != nil {
					b.Fatalf("Seek: %v", err)
				}
				if _, err := GetContents(f); err != nil {
					b.Fatalf("GetContents: %v", err)
				}
			}
		})
	}
}

// BenchmarkArchiveCounterAdd measures the atomic-increment + cap-check fast
// path under a fresh counter. The cap is set past any total the loop can
// reach, so the check runs on every call without firing.
func BenchmarkArchiveCounterAdd(b *testing.B) {
	c := &ArchiveCounter{MaxBytes: math.MaxInt64}
	b.ReportAllocs()
	for b.Loop() {
		if err := c.Add(1024); err != nil {
			b.Fatalf("Add: %v", err)
		}
	}
}
