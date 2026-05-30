// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package file

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// makeTempFile writes payload to a file under b.TempDir and returns the open
// handle. The caller is responsible for closing the handle.
func makeTempFile(b *testing.B, name string, payload []byte) *os.File {
	b.Helper()
	path := filepath.Join(b.TempDir(), name)
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		b.Fatalf("write fixture: %v", err)
	}
	f, err := os.Open(path) // #nosec G304 -- bench fixture under b.TempDir
	if err != nil {
		b.Fatalf("open fixture: %v", err)
	}
	return f
}

// BenchmarkGetContents exercises the size-class dispatch across small,
// medium, and over-medium inputs.
func BenchmarkGetContents(b *testing.B) {
	sizes := []struct {
		name string
		n    int
	}{
		{"small_4KiB", 4 * 1024},
		{"medium_256KiB", 256 * 1024},
		{"medium_4MiB", 4 * 1024 * 1024},
	}
	for _, sz := range sizes {
		b.Run(sz.name, func(b *testing.B) {
			payload := bytes.Repeat([]byte("x"), sz.n)
			f := makeTempFile(b, "bench.bin", payload)
			defer f.Close()
			buf := make([]byte, ReadBuffer)
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				if _, err := f.Seek(0, 0); err != nil {
					b.Fatalf("seek: %v", err)
				}
				if _, err := GetContents(f, buf); err != nil {
					b.Fatalf("GetContents: %v", err)
				}
			}
		})
	}
}

// BenchmarkReadSmallFile measures the small-file read path across the
// representative sizes the small size-class covers. The size hint passed is
// the true on-disk length, so the pre-grown buffer is sized in one shot.
func BenchmarkReadSmallFile(b *testing.B) {
	sizes := []struct {
		name string
		n    int
	}{
		{"1KiB", 1 * 1024},
		{"8KiB", 8 * 1024},
		{"64KiB", 64 * 1024},
	}
	for _, sz := range sizes {
		b.Run(sz.name, func(b *testing.B) {
			payload := bytes.Repeat([]byte("z"), sz.n)
			f := makeTempFile(b, "bench.bin", payload)
			defer f.Close()
			info, err := f.Stat()
			if err != nil {
				b.Fatalf("stat: %v", err)
			}
			size := info.Size()
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				if _, err := f.Seek(0, 0); err != nil {
					b.Fatalf("seek: %v", err)
				}
				if _, err := readSmallFile(f, size); err != nil {
					b.Fatalf("readSmallFile: %v", err)
				}
			}
		})
	}
}

// BenchmarkArchiveCounterAdd measures the atomic-increment + cap-check fast
// path under a fresh counter.
func BenchmarkArchiveCounterAdd(b *testing.B) {
	c := &ArchiveCounter{MaxBytes: DefaultMaxArchiveBytes}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if err := c.Add(1024); err != nil {
			b.Fatalf("Add: %v", err)
		}
	}
}

// BenchmarkReadBuffered measures buffered streaming reads at the medium size
// class.
func BenchmarkReadBuffered(b *testing.B) {
	payload := bytes.Repeat([]byte("y"), 1*1024*1024)
	f := makeTempFile(b, "bench.bin", payload)
	defer f.Close()
	buf := make([]byte, ReadBuffer)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := f.Seek(0, 0); err != nil {
			b.Fatalf("seek: %v", err)
		}
		if _, err := readBuffered(f, buf, mediumFileMaxBytes); err != nil {
			b.Fatalf("readBuffered: %v", err)
		}
	}
}
