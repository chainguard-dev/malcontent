// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package file

import (
	"bytes"
	"errors"
	"math"
	"os"
	"path/filepath"
	"testing"
)

func TestGetContents(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		content     []byte
		bufSize     int64
		wantErr     bool
		wantLen     int
		wantContent []byte
	}{
		{
			name:        "empty file",
			content:     []byte{},
			bufSize:     DefaultPoolBuffer,
			wantErr:     false,
			wantLen:     0,
			wantContent: []byte{},
		},
		{
			name:        "small file",
			content:     []byte("hello world"),
			bufSize:     DefaultPoolBuffer,
			wantErr:     false,
			wantLen:     11,
			wantContent: []byte("hello world"),
		},
		{
			name:        "file with buffer size 1KB",
			content:     make([]byte, 1024),
			bufSize:     1024,
			wantErr:     false,
			wantLen:     1024,
			wantContent: make([]byte, 1024),
		},
		{
			name:        "file larger than buffer",
			content:     make([]byte, 8192),
			bufSize:     DefaultPoolBuffer,
			wantErr:     false,
			wantLen:     8192,
			wantContent: make([]byte, 8192),
		},
		{
			name:        "file at ReadBuffer size",
			content:     make([]byte, ReadBuffer),
			bufSize:     ReadBuffer,
			wantErr:     false,
			wantLen:     int(ReadBuffer),
			wantContent: make([]byte, ReadBuffer),
		},
		{
			name:        "file with ExtractBuffer size",
			content:     make([]byte, ExtractBuffer),
			bufSize:     ExtractBuffer,
			wantErr:     false,
			wantLen:     int(ExtractBuffer),
			wantContent: make([]byte, ExtractBuffer),
		},
		{
			name:        "file with MaxPoolBuffer size",
			content:     make([]byte, MaxPoolBuffer),
			bufSize:     MaxPoolBuffer,
			wantErr:     false,
			wantLen:     int(MaxPoolBuffer),
			wantContent: make([]byte, MaxPoolBuffer),
		},
		{
			name:        "file with null bytes",
			content:     []byte{0, 1, 2, 0, 3, 4, 0},
			bufSize:     DefaultPoolBuffer,
			wantErr:     false,
			wantLen:     7,
			wantContent: []byte{0, 1, 2, 0, 3, 4, 0},
		},
		{
			name:        "file with unicode content",
			content:     []byte("Hello 世界 🌍"),
			bufSize:     DefaultPoolBuffer,
			wantErr:     false,
			wantLen:     17,
			wantContent: []byte("Hello 世界 🌍"),
		},
		{
			name:        "small buffer still works",
			content:     []byte("test content"),
			bufSize:     4,
			wantErr:     false,
			wantLen:     12,
			wantContent: []byte("test content"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tmpDir := t.TempDir()
			tmpFile := filepath.Join(tmpDir, "testfile")

			if err := os.WriteFile(tmpFile, tt.content, 0o644); err != nil {
				t.Fatalf("failed to create test file: %v", err)
			}

			f, err := os.Open(tmpFile)
			if err != nil {
				t.Fatalf("failed to open test file: %v", err)
			}
			defer f.Close()

			buf := make([]byte, tt.bufSize)

			got, err := GetContents(f, buf)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetContents() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if len(got) != tt.wantLen {
				t.Errorf("GetContents() returned %d bytes, want %d", len(got), tt.wantLen)
			}

			if !bytes.Equal(got, tt.wantContent) {
				t.Errorf("GetContents() content mismatch")
			}
		})
	}
}

func TestGetContentsClosedFile(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "testfile")

	if err := os.WriteFile(tmpFile, []byte("test"), 0o644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	f, err := os.Open(tmpFile)
	if err != nil {
		t.Fatalf("failed to open test file: %v", err)
	}

	f.Close()

	buf := make([]byte, DefaultPoolBuffer)
	_, err = GetContents(f, buf)
	if err == nil {
		t.Error("GetContents() should error on closed file, got nil error")
	}
}

func TestGetContentsMaxBytesLimit(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "largefile")

	f, err := os.Create(tmpFile)
	if err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	testPattern := []byte("START")
	if _, err := f.Write(testPattern); err != nil {
		f.Close()
		t.Fatalf("failed to write to test file: %v", err)
	}

	chunkSize := 1024 * 1024
	chunk := make([]byte, chunkSize)
	for i := range chunk {
		chunk[i] = byte(i % 256)
	}

	for range 10 {
		if _, err := f.Write(chunk); err != nil {
			f.Close()
			t.Fatalf("failed to write chunk: %v", err)
		}
	}

	f.Close()

	f, err = os.Open(tmpFile)
	if err != nil {
		t.Fatalf("failed to open test file: %v", err)
	}
	defer f.Close()

	buf := make([]byte, ExtractBuffer)
	got, err := GetContents(f, buf)
	if err != nil {
		t.Fatalf("GetContents() error = %v", err)
	}

	expectedSize := 5 + (10 * chunkSize)
	if len(got) != expectedSize {
		t.Errorf("GetContents() read %d bytes, want %d", len(got), expectedSize)
	}

	if string(got[:5]) != "START" {
		t.Errorf("GetContents() start pattern = %q, want %q", got[:5], "START")
	}
}

func TestGetContentsNilBuffer(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "testfile")

	if err := os.WriteFile(tmpFile, []byte("test content"), 0o644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	f, err := os.Open(tmpFile)
	if err != nil {
		t.Fatalf("failed to open test file: %v", err)
	}
	defer f.Close()

	got, err := GetContents(f, nil)
	if err != nil {
		t.Fatalf("GetContents() with nil buffer error = %v", err)
	}

	want := []byte("test content")
	if !bytes.Equal(got, want) {
		t.Errorf("GetContents() = %q, want %q", got, want)
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
		{"DefaultPoolBuffer", DefaultPoolBuffer, 4 * 1024},
		{"ExtractBuffer", ExtractBuffer, 64 * 1024},
		{"MaxPoolBuffer", MaxPoolBuffer, 128 * 1024},
		{"MaxBytes", MaxBytes, 1 << 32},
		{"ReadBuffer", ReadBuffer, 64 * 1024},
		{"ZipBuffer", ZipBuffer, 2 * 1024},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if tt.got != tt.want {
				t.Errorf("%s = %d, want %d", tt.name, tt.got, tt.want)
			}
		})
	}
}

// writeTempFile materializes the supplied bytes to disk and returns an open
// read handle. Callers own closing the returned file.
func writeTempFile(t *testing.T, content []byte) *os.File {
	t.Helper()
	tmp := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(tmp, content, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	f, err := os.Open(tmp)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return f
}

// deterministicBytes returns n bytes filled with a non-trivial repeating
// pattern so test assertions catch silent truncation or duplication.
func deterministicBytes(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte((i*31 + 7) & 0xff)
	}
	return b
}

func TestGetContentsSmallFile(t *testing.T) {
	t.Parallel()
	content := deterministicBytes(8 * 1024)
	f := writeTempFile(t, content)
	defer f.Close()

	buf := make([]byte, DefaultPoolBuffer)
	got, err := GetContents(f, buf)
	if err != nil {
		t.Fatalf("GetContents: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Fatalf("content mismatch: got %d bytes, want %d", len(got), len(content))
	}
	cls := sizeClass(int64(len(content)))
	if cls != sizeClassSmall {
		t.Fatalf("sizeClass(%d) = %v, want sizeClassSmall", len(content), cls)
	}
}

func TestGetContentsMediumFile(t *testing.T) {
	t.Parallel()
	content := deterministicBytes(1 << 20) // 1 MiB
	f := writeTempFile(t, content)
	defer f.Close()

	buf := make([]byte, ExtractBuffer)
	got, err := GetContents(f, buf)
	if err != nil {
		t.Fatalf("GetContents: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Fatalf("content mismatch: got %d bytes, want %d", len(got), len(content))
	}
	cls := sizeClass(int64(len(content)))
	if cls != sizeClassMedium {
		t.Fatalf("sizeClass(%d) = %v, want sizeClassMedium", len(content), cls)
	}
}

func TestGetContentsLargeFile(t *testing.T) {
	t.Parallel()
	const size = int64(17 * 1024 * 1024) // 17 MiB, sparse
	tmp := filepath.Join(t.TempDir(), "large")
	wf, err := os.Create(tmp)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := wf.Truncate(size); err != nil {
		wf.Close()
		t.Fatalf("Truncate: %v", err)
	}
	wf.Close()

	f, err := os.Open(tmp)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer f.Close()

	buf := make([]byte, ExtractBuffer)
	got, err := GetContents(f, buf)
	if err != nil {
		t.Fatalf("GetContents: %v", err)
	}
	if int64(len(got)) != size {
		t.Fatalf("len(got) = %d, want %d", len(got), size)
	}
	cls := sizeClass(size)
	if cls != sizeClassLarge {
		t.Fatalf("sizeClass(%d) = %v, want sizeClassLarge", size, cls)
	}
}

func TestGetContentsBoundaryAt64KiB(t *testing.T) {
	t.Parallel()
	// Boundary case: exactly at the small-file ceiling. The classifier uses an
	// inclusive upper bound for small so this file must be classed small.
	content := deterministicBytes(int(smallFileMaxBytes))
	f := writeTempFile(t, content)
	defer f.Close()

	buf := make([]byte, ExtractBuffer)
	got, err := GetContents(f, buf)
	if err != nil {
		t.Fatalf("GetContents: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Fatalf("content mismatch at small boundary")
	}
	if sizeClass(smallFileMaxBytes) != sizeClassSmall {
		t.Fatalf("sizeClass(smallFileMaxBytes) != sizeClassSmall")
	}
	// One byte past the small ceiling must promote to medium.
	if sizeClass(smallFileMaxBytes+1) != sizeClassMedium {
		t.Fatalf("sizeClass(smallFileMaxBytes+1) != sizeClassMedium")
	}
}

func TestGetContentsBoundaryAt16MiB(t *testing.T) {
	t.Parallel()
	// Boundary case at the medium-file ceiling. Use a sparse temp file to
	// avoid materializing 16 MiB of test data in memory.
	tmp := filepath.Join(t.TempDir(), "boundary")
	wf, err := os.Create(tmp)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := wf.Truncate(mediumFileMaxBytes); err != nil {
		wf.Close()
		t.Fatalf("Truncate: %v", err)
	}
	wf.Close()

	f, err := os.Open(tmp)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer f.Close()

	buf := make([]byte, ExtractBuffer)
	got, err := GetContents(f, buf)
	if err != nil {
		t.Fatalf("GetContents: %v", err)
	}
	if int64(len(got)) != mediumFileMaxBytes {
		t.Fatalf("len(got) = %d, want %d", len(got), mediumFileMaxBytes)
	}
	if sizeClass(mediumFileMaxBytes) != sizeClassMedium {
		t.Fatalf("sizeClass(mediumFileMaxBytes) != sizeClassMedium")
	}
	if sizeClass(mediumFileMaxBytes+1) != sizeClassLarge {
		t.Fatalf("sizeClass(mediumFileMaxBytes+1) != sizeClassLarge")
	}
}

func TestGetContentsNonRegular(t *testing.T) {
	t.Parallel()
	// A pipe is non-regular and f.Stat reports a non-regular mode. The
	// dispatch must fall through to the streaming read path and still return
	// the correct bytes.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("Pipe: %v", err)
	}
	defer r.Close()

	payload := []byte("non-regular payload")
	go func() {
		_, _ = w.Write(payload)
		w.Close()
	}()

	buf := make([]byte, DefaultPoolBuffer)
	got, err := GetContents(r, buf)
	if err != nil {
		t.Fatalf("GetContents on pipe: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("got %q, want %q", got, payload)
	}
}

func TestGetContentsEmpty(t *testing.T) {
	t.Parallel()
	f := writeTempFile(t, nil)
	defer f.Close()

	buf := make([]byte, DefaultPoolBuffer)
	got, err := GetContents(f, buf)
	if err != nil {
		t.Fatalf("GetContents: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("len(got) = %d, want 0", len(got))
	}
	if sizeClass(0) != sizeClassSmall {
		t.Fatalf("sizeClass(0) != sizeClassSmall")
	}
}

func TestSizeClassClassification(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		n    int64
		want sizeClassEnum
	}{
		{"zero", 0, sizeClassSmall},
		{"one byte", 1, sizeClassSmall},
		{"small mid-range", 32 * 1024, sizeClassSmall},
		{"small boundary", smallFileMaxBytes, sizeClassSmall},
		{"medium just above small", smallFileMaxBytes + 1, sizeClassMedium},
		{"medium mid-range", 4 * 1024 * 1024, sizeClassMedium},
		{"medium boundary", mediumFileMaxBytes, sizeClassMedium},
		{"large just above medium", mediumFileMaxBytes + 1, sizeClassLarge},
		{"large at MaxBytes", MaxBytes, sizeClassLarge},
		{"large above MaxBytes", MaxBytes + 1, sizeClassLarge},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := sizeClass(tt.n); got != tt.want {
				t.Errorf("sizeClass(%d) = %v, want %v", tt.n, got, tt.want)
			}
		})
	}
}
