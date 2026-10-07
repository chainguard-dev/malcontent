// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package file

import (
	"bytes"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/iotest"
)

// testMapAbove stands in for mapThreshold so the map path can be exercised
// with small files.
const testMapAbove int64 = 64 << 10

func TestLoadContents(t *testing.T) {
	t.Parallel()
	above := int(testMapAbove)
	tests := []struct {
		name       string
		size       int   // bytes on disk
		statSize   int64 // size passed to loadContents
		wantMapped bool
	}{
		{"small file is read", 4096, 4096, false},
		{"file at the threshold is read", above, int64(above), false},
		{"file one byte past the threshold is mapped", above + 1, int64(above + 1), canMap},
		{"large file is mapped", 4 * above, int64(4 * above), canMap},
		{"small file grown after stat is read in full", 8192, 100, false},
		{"file grown past the threshold after stat is read in full", above + 4096, 4096, false},
		{"large file grown after stat is mapped in full", 4 * above, int64(2 * above), canMap},
		{"small file shrunk after stat is read as it is now", 100, 4096, false},
		{"file shrunk below the threshold after stat is mapped as it is now", 100, int64(2 * above), canMap},
		{"small file emptied after stat is read as empty", 0, 4096, false},
		{"large file emptied after stat is read as empty", 0, int64(2 * above), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			content := deterministicBytes(tt.size)
			f := openTemp(t, content)

			c, err := loadContents(f, tt.statSize, testMapAbove)
			if err != nil {
				t.Fatalf("loadContents() error: got = %v, want = nil", err)
			}
			// The contents must outlive the file they were read from.
			if err := f.Close(); err != nil {
				t.Fatalf("Close file: %v", err)
			}
			got := c.Bytes()
			if !bytes.Equal(got, content) {
				t.Errorf("Bytes(): got = %d bytes, want = the %d bytes on disk", len(got), len(content))
			}
			if cap(got) != len(got) {
				t.Errorf("Bytes() capacity: got = %d, want = %d", cap(got), len(got))
			}
			if c.mapped != tt.wantMapped {
				t.Errorf("mapped: got = %v, want = %v", c.mapped, tt.wantMapped)
			}
			if err := c.Close(); err != nil {
				t.Errorf("Close() error: got = %v, want = nil", err)
			}
			if err := c.Close(); err != nil {
				t.Errorf("second Close() error: got = %v, want = nil", err)
			}
			if got := c.Bytes(); len(got) != 0 {
				t.Errorf("Bytes() after Close: got = %d bytes, want = 0", len(got))
			}
		})
	}
}

// TestReadContents checks that files well below the 32,000,000-byte
// threshold, the size above which yara-x maps files, are read rather than
// mapped.
func TestReadContents(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		size int
	}{
		{"small file", 4096},
		{"file of several MiB", 4 << 20},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			content := deterministicBytes(tt.size)
			c, err := ReadContents(openTemp(t, content), int64(tt.size))
			if err != nil {
				t.Fatalf("ReadContents() error: got = %v, want = nil", err)
			}
			defer c.Close()
			if got := c.Bytes(); !bytes.Equal(got, content) {
				t.Errorf("Bytes(): got = %d bytes, want = the %d bytes on disk", len(got), len(content))
			}
			if c.mapped {
				t.Errorf("mapped: got = true, want = false")
			}
		})
	}
}

func TestReadContentsClosedFile(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		size int64
	}{
		{"read path", 4},
		{"map path", testMapAbove + 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			p := writeTemp(t, deterministicBytes(int(tt.size)))
			f, err := OpenIn(filepath.Dir(p), filepath.Base(p))
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			if err := f.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}

			c, err := loadContents(f, tt.size, testMapAbove)
			if err == nil {
				t.Errorf("loadContents() error on a closed file: got = nil, want = an error")
			}
			if c != nil {
				t.Errorf("loadContents() contents on error: got = non-nil, want = nil")
			}
		})
	}
}

func TestReadContentsNonRegular(t *testing.T) {
	t.Parallel()
	// A pipe cannot be mapped, so even a size past the threshold falls back
	// to reading, which streams the pipe to EOF.
	tests := []struct {
		name string
		size int64
	}{
		{"size below the payload", 5},
		{"size past the threshold", testMapAbove + 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatalf("Pipe: %v", err)
			}
			defer r.Close()

			payload := []byte("non-regular payload")
			go func() {
				_, _ = w.Write(payload)
				_ = w.Close()
			}()

			c, err := loadContents(r, tt.size, testMapAbove)
			if err != nil {
				t.Fatalf("loadContents() error on a pipe: got = %v, want = nil", err)
			}
			defer c.Close()
			if got := c.Bytes(); !bytes.Equal(got, payload) {
				t.Errorf("Bytes() from a pipe: got = %q, want = %q", got, payload)
			}
		})
	}
}

// TestReadPooledLimit drives the read path with a limit small enough to
// reach; ReadContents uses MaxBytes.
func TestReadPooledLimit(t *testing.T) {
	t.Parallel()
	content := deterministicBytes(100)
	tests := []struct {
		name  string
		size  int64
		limit int64
		want  []byte
	}{
		{"content within the limit", 100, 1000, content},
		{"growth within the limit", 10, 1000, content},
		{"content past the limit is not read", 100, 64, content[:64]},
		{"growth past the limit is not read", 10, 64, content[:64]},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c, err := readPooled(bytes.NewReader(content), tt.size, tt.limit)
			if err != nil {
				t.Fatalf("readPooled() error: got = %v, want = nil", err)
			}
			defer c.Close()
			if got := c.Bytes(); !bytes.Equal(got, tt.want) {
				t.Errorf("Bytes(): got = %d bytes, want = %d bytes", len(got), len(tt.want))
			}
		})
	}
}

func TestReadPooledReadErrors(t *testing.T) {
	t.Parallel()
	content := deterministicBytes(100)
	tests := []struct {
		name string
		r    io.Reader
		size int64
	}{
		{"error before any byte", iotest.ErrReader(errRead), 100},
		{"error before the stat size", io.MultiReader(bytes.NewReader(content[:10]), iotest.ErrReader(errRead)), 100},
		{"error while reading growth past the stat size", io.MultiReader(bytes.NewReader(content), iotest.ErrReader(errRead)), 10},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c, err := readPooled(tt.r, tt.size, MaxBytes)
			if !errors.Is(err, errRead) {
				t.Errorf("readPooled() error: got = %v, want = %v", err, errRead)
			}
			if c != nil {
				t.Errorf("readPooled() contents on error: got = non-nil, want = nil")
			}
		})
	}
}

func TestContentsNil(t *testing.T) {
	t.Parallel()
	var c *Contents
	if got := c.Bytes(); got != nil {
		t.Errorf("Bytes() on nil: got = %v, want = nil", got)
	}
	if err := c.Close(); err != nil {
		t.Errorf("Close() on nil: got = %v, want = nil", err)
	}
}

// mappedPaths reports whether this process maps path, from /proc/self/maps.
// It skips the test where that file is unavailable.
func mappedPaths(t *testing.T, path string) bool {
	t.Helper()
	maps, err := ReadFileIn("/proc/self", "maps")
	if err != nil {
		t.Skipf("memory mappings are not listable: %v", err)
	}
	return strings.Contains(string(maps), path)
}

func TestContentsCloseUnmaps(t *testing.T) {
	t.Parallel()
	if !canMap {
		t.Skip("files are not memory-mapped on this platform")
	}
	size := testMapAbove + 1
	p := writeTemp(t, deterministicBytes(int(size)))
	resolved, err := filepath.EvalSymlinks(p)
	if err != nil {
		t.Fatalf("EvalSymlinks(%q): %v", p, err)
	}
	f, err := OpenIn(filepath.Dir(p), filepath.Base(p))
	if err != nil {
		t.Fatalf("Open(%q): %v", p, err)
	}
	c, err := loadContents(f, size, testMapAbove)
	_ = f.Close()
	if err != nil {
		t.Fatalf("loadContents() error: got = %v, want = nil", err)
	}

	if !mappedPaths(t, resolved) {
		t.Errorf("mapping before Close: got = absent, want = present")
	}
	if err := c.Close(); err != nil {
		t.Fatalf("Close() error: got = %v, want = nil", err)
	}
	if mappedPaths(t, resolved) {
		t.Errorf("mapping after Close: got = present, want = absent")
	}
}

func TestMapFile(t *testing.T) {
	t.Parallel()
	if !canMap {
		t.Skip("files are not memory-mapped on this platform")
	}
	tests := []struct {
		name string
		size int
	}{
		{"one-byte file", 1},
		{"file of one page", 4096},
		{"file one byte past a page", 4097},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			content := deterministicBytes(tt.size)
			data, err := mapFile(openTemp(t, content))
			if err != nil {
				t.Fatalf("mapFile() error: got = %v, want = nil", err)
			}
			if !bytes.Equal(data, content) {
				t.Errorf("mapFile() data: got = %d bytes, want = the %d bytes on disk", len(data), len(content))
			}
			if err := unmapFile(data); err != nil {
				t.Errorf("unmapFile() error: got = %v, want = nil", err)
			}
		})
	}
}

func TestMapFileRejectsUnmappableFiles(t *testing.T) {
	t.Parallel()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("Pipe: %v", err)
	}
	// Cleanup rather than defer: the parallel subtests run after this
	// function returns.
	t.Cleanup(func() {
		_ = r.Close()
		_ = w.Close()
	})

	tests := []struct {
		name string
		f    *os.File
	}{
		{"empty file", openTemp(t, nil)},
		{"pipe", r},
		{"directory", openDir(t, t.TempDir())},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			data, err := mapFile(tt.f)
			if !errors.Is(err, errNotMappable) {
				t.Errorf("mapFile() error: got = %v, want = %v", err, errNotMappable)
			}
			if data != nil {
				t.Errorf("mapFile() data: got = %d bytes, want = nil", len(data))
			}
		})
	}
}

// openDir opens dir for reading. The directory is closed when the test ends.
func openDir(t *testing.T, dir string) *os.File {
	t.Helper()
	f, err := OpenIn(dir, ".")
	if err != nil {
		t.Fatalf("Open(%q): %v", dir, err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

func TestPoolClass(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		n    int64
		want int
	}{
		{"negative", -1, 0},
		{"empty", 0, 0},
		{"one byte", 1, 0},
		{"two bytes", 2, 1},
		{"between classes rounds up", 3, 2},
		{"at a class", 4, 2},
		{"one past a class", 5, 3},
		{"page", 4096, 12},
		{"one past a page", 4097, 13},
		{"largest read-path buffer", mapThreshold + 1, maxPoolShift},
		{"largest pooled size", 1 << maxPoolShift, maxPoolShift},
		{"one past the largest pooled size", 1<<maxPoolShift + 1, maxPoolShift + 1},
		{"largest int64", math.MaxInt64, 63},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := poolClass(tt.n); got != tt.want {
				t.Errorf("poolClass(%d): got = %d, want = %d", tt.n, got, tt.want)
			}
		})
	}
}

func TestGetBuffer(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		n       int64
		wantCap int
	}{
		{"one byte takes the smallest class", 1, 1},
		{"size between classes rounds up", 3000, 4096},
		{"size at a class takes that class", 4096, 4096},
		{"size one past a class takes the next", 64<<10 + 1, 128 << 10},
		// These two allocate 32 MiB each: the largest pooled class is the
		// only one big enough for the largest read-path buffer, and sizes
		// past it are not pooled.
		{"largest read-path buffer takes the largest pooled class", mapThreshold + 1, 1 << maxPoolShift},
		{"size past the largest pooled class is allocated exactly", 1<<maxPoolShift + 1, 1<<maxPoolShift + 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			bp := getBuffer(tt.n)
			if got := cap(*bp); got != tt.wantCap {
				t.Errorf("getBuffer(%d) capacity: got = %d, want = %d", tt.n, got, tt.wantCap)
			}
			if got := len(*bp); got != tt.wantCap {
				t.Errorf("getBuffer(%d) length: got = %d, want = %d", tt.n, got, tt.wantCap)
			}
			putBuffer(bp)
		})
	}
}

// TestReadAllocations checks that reads allocate only their results and that
// read buffers go back to their pools, whether the read succeeds or fails.
// Not parallel: testing.AllocsPerRun counts allocations process-wide.
func TestReadAllocations(t *testing.T) {
	content := deterministicBytes(4096)
	r := bytes.NewReader(content)
	failing := iotest.ErrReader(errRead)
	tests := []struct {
		name      string
		run       func()
		maxAllocs float64
	}{
		{"buffer returned to its pool is reused", func() {
			putBuffer(getBuffer(4096))
		}, 0},
		{"read sized from stat allocates only its result", func() {
			r.Reset(content)
			_, _ = readUpTo(r, 4096, MaxBytes)
		}, 1},
		{"read stopped at the limit allocates only its result", func() {
			r.Reset(content)
			_, _ = readUpTo(r, 1024, 1024)
		}, 1},
		{"pooled read allocates only its Contents", func() {
			r.Reset(content)
			c, _ := readPooled(r, 4096, MaxBytes)
			_ = c.Close()
		}, 1},
		{"failed pooled read returns its buffer to the pool", func() {
			_, _ = readPooled(failing, 4096, MaxBytes)
		}, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := testing.AllocsPerRun(1000, tt.run); got > tt.maxAllocs {
				t.Errorf("allocations per run: got = %v, want = %v or fewer", got, tt.maxAllocs)
			}
		})
	}
}
