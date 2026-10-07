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
	"testing"
	"testing/iotest"
)

// errRead stands in for an I/O error partway through a read.
var errRead = errors.New("read failed")

// deterministicBytes returns n bytes filled with a non-trivial repeating
// pattern so test assertions catch silent truncation or duplication.
func deterministicBytes(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte((i*31 + 7) & 0xff)
	}
	return b
}

// writeTemp writes content to a new file under tb.TempDir and returns its
// path.
func writeTemp(tb testing.TB, content []byte) string {
	tb.Helper()
	dir := tb.TempDir()
	p := filepath.Join(dir, "f")
	if err := WriteFileIn(dir, "f", content, 0o600); err != nil {
		tb.Fatalf("WriteFile(%q): %v", p, err)
	}
	return p
}

// openTemp writes content to a new file and returns it open for reading. The
// file is closed when the test ends.
func openTemp(tb testing.TB, content []byte) *os.File {
	tb.Helper()
	p := writeTemp(tb, content)
	f, err := OpenIn(filepath.Dir(p), filepath.Base(p))
	if err != nil {
		tb.Fatalf("Open(%q): %v", p, err)
	}
	tb.Cleanup(func() { _ = f.Close() })
	return f
}

func TestGetContents(t *testing.T) {
	t.Parallel()
	marked := append([]byte("START"), deterministicBytes(10<<20)...)
	tests := []struct {
		name    string
		content []byte
	}{
		{"empty file", []byte{}},
		{"small file", []byte("hello world")},
		{"1 KiB file", make([]byte, 1024)},
		{"8 KiB file", deterministicBytes(8192)},
		{"64 KiB file", make([]byte, 64<<10)},
		{"file one byte past 64 KiB", deterministicBytes(64<<10 + 1)},
		{"128 KiB file", make([]byte, 128<<10)},
		{"file with null bytes", []byte{0, 1, 2, 0, 3, 4, 0}},
		{"file with unicode content", []byte("Hello 世界 🌍")},
		{"1 MiB file", deterministicBytes(1 << 20)},
		{"10 MiB file with a leading marker", marked},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := GetContents(openTemp(t, tt.content))
			if err != nil {
				t.Fatalf("GetContents() error: got = %v, want = nil", err)
			}
			if len(got) != len(tt.content) {
				t.Errorf("GetContents() length: got = %d, want = %d", len(got), len(tt.content))
			}
			if !bytes.Equal(got, tt.content) {
				t.Errorf("GetContents() content: got = %d bytes differing from the %d written", len(got), len(tt.content))
			}
		})
	}
}

func TestGetContentsSparseFile(t *testing.T) {
	t.Parallel()
	const size = int64(17 << 20)
	p := writeTemp(t, nil)
	dir, name := filepath.Dir(p), filepath.Base(p)
	w, err := OpenFileIn(dir, name, os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("Open(%q) for writing: %v", p, err)
	}
	err = w.Truncate(size)
	_ = w.Close()
	if err != nil {
		t.Fatalf("Truncate(%q): %v", p, err)
	}
	f, err := OpenIn(dir, name)
	if err != nil {
		t.Fatalf("Open(%q): %v", p, err)
	}
	defer f.Close()

	got, err := GetContents(f)
	if err != nil {
		t.Fatalf("GetContents() error: got = %v, want = nil", err)
	}
	if int64(len(got)) != size {
		t.Errorf("GetContents() length: got = %d, want = %d", len(got), size)
	}
}

func TestGetContentsReadsFromTheCurrentOffset(t *testing.T) {
	t.Parallel()
	content := deterministicBytes(4096)
	f := openTemp(t, content)
	if _, err := f.Seek(100, io.SeekStart); err != nil {
		t.Fatalf("Seek: %v", err)
	}

	got, err := GetContents(f)
	if err != nil {
		t.Fatalf("GetContents() error: got = %v, want = nil", err)
	}
	if !bytes.Equal(got, content[100:]) {
		t.Errorf("GetContents() content: got = %d bytes, want = the last %d bytes", len(got), len(content)-100)
	}
}

func TestGetContentsClosedFile(t *testing.T) {
	t.Parallel()
	p := writeTemp(t, []byte("test"))
	f, err := OpenIn(filepath.Dir(p), filepath.Base(p))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if _, err := GetContents(f); err == nil {
		t.Errorf("GetContents() error on a closed file: got = nil, want = an error")
	}
}

func TestGetContentsNonRegular(t *testing.T) {
	t.Parallel()
	// A pipe is not a regular file, so it is read to EOF rather than by its
	// Stat size.
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

	got, err := GetContents(r)
	if err != nil {
		t.Fatalf("GetContents() error on a pipe: got = %v, want = nil", err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("GetContents() on a pipe: got = %q, want = %q", got, payload)
	}
}

// TestReadUpTo drives the sized read behind GetContents with a stat size that
// disagrees with the content, as when a file grows or shrinks between Stat and
// the read, and with a limit small enough to reach.
func TestReadUpTo(t *testing.T) {
	t.Parallel()
	content := deterministicBytes(100)
	tests := []struct {
		name    string
		content []byte
		size    int64
		limit   int64
		want    []byte
	}{
		{"size matches the content", content, 100, 1000, content},
		{"content grew after stat", content, 40, 1000, content},
		{"content grew by one byte after stat", content, 99, 1000, content},
		{"content grew from an empty stat", content, 0, 1000, content},
		{"content shrank after stat", content[:40], 100, 1000, content[:40]},
		{"content emptied after stat", nil, 100, 1000, []byte{}},
		{"negative stat size", content, -1, 1000, content},
		{"content past the limit is not read", content, 100, 64, content[:64]},
		{"growth past the limit is not read", content, 10, 64, content[:64]},
		{"stat size past the limit", content, 1000, 64, content[:64]},
		{"stat size exactly at the limit", content, 64, 64, content[:64]},
		{"content one byte short of the limit", content[:63], 63, 64, content[:63]},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := readUpTo(bytes.NewReader(tt.content), tt.size, tt.limit)
			if err != nil {
				t.Fatalf("readUpTo() error: got = %v, want = nil", err)
			}
			if !bytes.Equal(got, tt.want) {
				t.Errorf("readUpTo() content: got = %d bytes, want = %d bytes", len(got), len(tt.want))
			}
		})
	}
}

func TestReadLengths(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		size      int64
		limit     int64
		wantSize  int64
		wantFirst int64
	}{
		{"size under the limit", 100, 1000, 100, 101},
		{"empty size", 0, 1000, 0, 1},
		{"negative size counts as empty", -1, 1000, 0, 1},
		{"size one under the limit", 63, 64, 63, 64},
		{"size at the limit", 64, 64, 64, 64},
		{"size past the limit", 1000, 64, 64, 64},
		{"largest int64 size", math.MaxInt64, 64, 64, 64},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			gotSize, gotFirst := readLengths(tt.size, tt.limit)
			if gotSize != tt.wantSize {
				t.Errorf("readLengths(%d, %d) size: got = %d, want = %d", tt.size, tt.limit, gotSize, tt.wantSize)
			}
			if gotFirst != tt.wantFirst {
				t.Errorf("readLengths(%d, %d) first read: got = %d, want = %d", tt.size, tt.limit, gotFirst, tt.wantFirst)
			}
		})
	}
}

func TestReadUpToReadErrors(t *testing.T) {
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
			got, err := readUpTo(tt.r, tt.size, MaxBytes)
			if !errors.Is(err, errRead) {
				t.Errorf("readUpTo() error: got = %v, want = %v", err, errRead)
			}
			if got != nil {
				t.Errorf("readUpTo() content on error: got = %d bytes, want = nil", len(got))
			}
		})
	}
}

func TestArchiveCounter_RatioOverflowGuard(t *testing.T) {
	t.Parallel()

	t.Run("non_overflowing_caps_normal_path", func(t *testing.T) {
		t.Parallel()
		c := &ArchiveCounter{MaxRatio: 100, InputBytes: 1000}
		if err := c.Add(500); err != nil {
			t.Fatalf("Add(500) error = %v, want nil", err)
		}
		// 500 + 1_000_000 = 1_000_500 > 1000*100 = 100_000 -> ratio cap fires.
		if err := c.Add(1_000_000); !errors.Is(err, ErrArchiveRatioCap) {
			t.Fatalf("Add(1_000_000) error = %v, want ErrArchiveRatioCap", err)
		}
	})

	t.Run("overflow_disables_ratio_cap", func(t *testing.T) {
		t.Parallel()
		// MaxRatio * InputBytes = (MaxInt64/2) * 3 -> overflows int64.
		c := &ArchiveCounter{MaxRatio: math.MaxInt64 / 2, InputBytes: 3}
		// A large n that would otherwise exceed the wrapped negative product;
		// the guard must short-circuit the ratio check.
		if err := c.Add(1 << 30); err != nil {
			t.Fatalf("Add(1<<30) first call error = %v, want nil (ratio cap disabled on overflow)", err)
		}
		if err := c.Add(1 << 30); errors.Is(err, ErrArchiveRatioCap) {
			t.Fatalf("Add(1<<30) second call returned ErrArchiveRatioCap despite overflow-disable; err=%v", err)
		}
	})

	t.Run("zero_ratio_no_ratio_check", func(t *testing.T) {
		t.Parallel()
		c := &ArchiveCounter{MaxRatio: 0, InputBytes: 1 << 30}
		if err := c.Add(1 << 30); err != nil {
			t.Fatalf("Add(1<<30) error = %v, want nil (MaxRatio=0 disables ratio cap)", err)
		}
	})

	t.Run("bytes_cap_still_enforced", func(t *testing.T) {
		t.Parallel()
		// Even when ratio inputs would overflow, the independent bytes cap fires.
		c := &ArchiveCounter{
			MaxBytes:   100,
			MaxRatio:   math.MaxInt64 / 2,
			InputBytes: 3,
		}
		if err := c.Add(200); !errors.Is(err, ErrArchiveBytesCap) {
			t.Fatalf("Add(200) error = %v, want ErrArchiveBytesCap", err)
		}
	})
}

func TestArchiveCounter_NilAddIsNoOp(t *testing.T) {
	t.Parallel()
	var c *ArchiveCounter
	if err := c.Add(math.MaxInt); err != nil {
		t.Errorf("Add() on a nil counter: got = %v, want = nil", err)
	}
}

func TestArchiveCounter_AddZeroBytes(t *testing.T) {
	t.Parallel()
	c := &ArchiveCounter{MaxBytes: 100, MaxRatio: 10, InputBytes: 50}
	if err := c.Add(0); err != nil {
		t.Fatalf("Add(0) error = %v, want nil", err)
	}
}

func TestConstants(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		got  int64
		want int64
	}{
		{"ExtractBuffer", ExtractBuffer, 64 * 1024},
		{"MaxBytes", MaxBytes, 1 << 32},
		{"DefaultMaxArchiveBytes", DefaultMaxArchiveBytes, 32 << 30},
		{"mapThreshold", mapThreshold, 32_000_000},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if tt.got != tt.want {
				t.Errorf("%s: got = %d, want = %d", tt.name, tt.got, tt.want)
			}
		})
	}
	t.Run("DefaultMaxArchiveRatio", func(t *testing.T) {
		t.Parallel()
		if got, want := DefaultMaxArchiveRatio, 100.0; got != want {
			t.Errorf("DefaultMaxArchiveRatio: got = %v, want = %v", got, want)
		}
	})
}

// TestArchiveCounter_FractionalRatio exercises ArchiveCounter.Add with
// non-integer MaxRatio values. A ratio in (0,1) must enforce rather than
// disable the cap, and a fractional ratio above 1 must fire at its exact
// threshold rather than the truncated integer.
func TestArchiveCounter_FractionalRatio(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		maxRatio   float64
		inputBytes int64
		writes     []int
		wantErr    bool
	}{
		{
			name:       "ratio below one enforces",
			maxRatio:   0.5,
			inputBytes: 1000,
			writes:     []int{500, 1},
			wantErr:    true,
		},
		{
			name:       "ratio below one does not fire at threshold",
			maxRatio:   0.5,
			inputBytes: 1000,
			writes:     []int{500},
			wantErr:    false,
		},
		{
			name:       "fractional ratio fires at 2.5x not 2x",
			maxRatio:   2.5,
			inputBytes: 100,
			writes:     []int{200, 51},
			wantErr:    true,
		},
		{
			name:       "fractional ratio does not fire just below 2.5x",
			maxRatio:   2.5,
			inputBytes: 100,
			writes:     []int{200, 50},
			wantErr:    false,
		},
		{
			name:       "non-positive ratio disables the cap",
			maxRatio:   0,
			inputBytes: 100,
			writes:     []int{1 << 20},
			wantErr:    false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := &ArchiveCounter{MaxRatio: tc.maxRatio, InputBytes: tc.inputBytes}
			var lastErr error
			for _, n := range tc.writes {
				if err := c.Add(n); err != nil {
					lastErr = err
					break
				}
			}
			if tc.wantErr {
				if !errors.Is(lastErr, ErrArchiveRatioCap) {
					t.Fatalf("want ErrArchiveRatioCap, got %v", lastErr)
				}
				return
			}
			if lastErr != nil {
				t.Fatalf("Add() error: got = %v, want = nil", lastErr)
			}
		})
	}
}

// TestArchiveCounter_Remaining verifies Remaining returns correct values.
func TestArchiveCounter_Remaining(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		counter *ArchiveCounter
		preAdd  int
		want    int64
	}{
		{
			name:    "nil counter returns MaxInt64",
			counter: nil,
			want:    math.MaxInt64,
		},
		{
			name:    "zero MaxBytes returns MaxInt64",
			counter: &ArchiveCounter{MaxBytes: 0},
			want:    math.MaxInt64,
		},
		{
			name:    "negative MaxBytes returns MaxInt64",
			counter: &ArchiveCounter{MaxBytes: -1},
			want:    math.MaxInt64,
		},
		{
			name:    "one-byte budget available",
			counter: &ArchiveCounter{MaxBytes: 1},
			want:    1,
		},
		{
			name:    "one-byte budget consumed",
			counter: &ArchiveCounter{MaxBytes: 1},
			preAdd:  1,
			want:    0,
		},
		{
			name:    "full budget available",
			counter: &ArchiveCounter{MaxBytes: 1000},
			want:    1000,
		},
		{
			name:    "partial budget consumed",
			counter: &ArchiveCounter{MaxBytes: 1000},
			preAdd:  600,
			want:    400,
		},
		{
			name:    "budget fully consumed",
			counter: &ArchiveCounter{MaxBytes: 1000},
			preAdd:  1000,
			want:    0,
		},
		{
			name:    "budget overdrawn returns zero",
			counter: &ArchiveCounter{MaxBytes: 100, InputBytes: 1 << 30},
			preAdd:  200,
			want:    0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if tt.preAdd > 0 && tt.counter != nil {
				_ = tt.counter.Add(tt.preAdd)
			}
			if got := tt.counter.Remaining(); got != tt.want {
				t.Errorf("Remaining() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestArchiveCounter_Available(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		counter *ArchiveCounter
		preAdd  int
		want    int64
	}{
		{name: "nil counter accepts any amount", counter: nil, want: math.MaxInt64},
		{name: "counter without caps accepts any amount", counter: &ArchiveCounter{}, want: math.MaxInt64},
		{name: "byte cap alone bounds what is left", counter: &ArchiveCounter{MaxBytes: 1000}, preAdd: 600, want: 400},
		{name: "ratio cap alone bounds what is left", counter: &ArchiveCounter{MaxRatio: 10, InputBytes: 100}, preAdd: 300, want: 700},
		{name: "fractional ratio threshold rounds down", counter: &ArchiveCounter{MaxRatio: 1.5, InputBytes: 3}, want: 4},
		{name: "ratio cap below the byte cap wins", counter: &ArchiveCounter{MaxBytes: 5000, MaxRatio: 10, InputBytes: 100}, want: 1000},
		{name: "byte cap below the ratio cap wins", counter: &ArchiveCounter{MaxBytes: 500, MaxRatio: 10, InputBytes: 100}, want: 500},
		{name: "ratio cap without input size is inactive", counter: &ArchiveCounter{MaxBytes: 500, MaxRatio: 10}, want: 500},
		{name: "ratio cap without a ratio is inactive", counter: &ArchiveCounter{MaxBytes: 500, InputBytes: 100}, want: 500},
		{name: "overdrawn ratio cap leaves nothing", counter: &ArchiveCounter{MaxRatio: 1, InputBytes: 100}, preAdd: 150, want: 0},
		{name: "ratio threshold beyond int64 leaves the byte cap", counter: &ArchiveCounter{MaxBytes: 500, MaxRatio: math.MaxFloat64, InputBytes: 2}, want: 500},
		{name: "ratio threshold of exactly 2^63 is no cap however much was added", counter: &ArchiveCounter{MaxRatio: 1 << 62, InputBytes: 2}, preAdd: 10, want: math.MaxInt64},
		{name: "ratio cap of a one-byte input", counter: &ArchiveCounter{MaxRatio: 10, InputBytes: 1}, want: 10},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if tt.preAdd > 0 {
				_ = tt.counter.Add(tt.preAdd)
			}
			got := tt.counter.Available()
			if got != tt.want {
				t.Fatalf("Available(): got = %d, want = %d", got, tt.want)
			}
			// Exactly what is available can be added; one byte more fails.
			if got == 0 || got == math.MaxInt64 || got > 1<<20 {
				return
			}
			if err := tt.counter.Add(int(got)); err != nil {
				t.Errorf("Add(%d) of what is available: got err = %v, want = nil", got, err)
			}
			if err := tt.counter.Add(1); err == nil {
				t.Error("Add(1) past what is available: got err = nil, want a cap error")
			}
		})
	}
}
