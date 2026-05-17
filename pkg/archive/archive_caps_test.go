// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/chainguard-dev/malcontent/pkg/file"
	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	zip "github.com/klauspost/compress/zip"
)

// TestArchiveBytesCap_HitsLimit verifies Add returns ErrArchiveBytesCap when
// the cumulative Total would exceed MaxBytes.
func TestArchiveBytesCap_HitsLimit(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		maxBytes  int64
		writes    []int
		wantIndex int
	}{
		{
			name:      "single write exceeds cap",
			maxBytes:  100,
			writes:    []int{200},
			wantIndex: 0,
		},
		{
			name:      "cumulative writes exceed cap",
			maxBytes:  100,
			writes:    []int{40, 40, 40},
			wantIndex: 2,
		},
		{
			name:      "exact cap boundary writes succeed; next exceeds",
			maxBytes:  100,
			writes:    []int{50, 50, 1},
			wantIndex: 2,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := &file.ArchiveCounter{MaxBytes: tc.maxBytes, InputBytes: 1 << 30}
			firstErrAt := -1
			for i, n := range tc.writes {
				if err := c.Add(n); err != nil {
					if !errors.Is(err, file.ErrArchiveBytesCap) {
						t.Fatalf("write %d: want ErrArchiveBytesCap, got %v", i, err)
					}
					firstErrAt = i
					break
				}
			}
			if firstErrAt != tc.wantIndex {
				t.Fatalf("first error at index %d, want %d", firstErrAt, tc.wantIndex)
			}
		})
	}
}

// TestArchiveRatioCap_HitsLimit verifies Add returns ErrArchiveRatioCap when
// Total exceeds InputBytes * MaxRatio.
func TestArchiveRatioCap_HitsLimit(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		inputBytes int64
		maxRatio   int64
		writes     []int
		wantErr    bool
	}{
		{
			name:       "10x ratio against 100 input fires after 1001 bytes",
			inputBytes: 100,
			maxRatio:   10,
			writes:     []int{500, 501},
			wantErr:    true,
		},
		{
			name:       "ratio cap does not fire below threshold",
			inputBytes: 100,
			maxRatio:   10,
			writes:     []int{500, 500},
			wantErr:    false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := &file.ArchiveCounter{MaxRatio: tc.maxRatio, InputBytes: tc.inputBytes}
			var lastErr error
			for _, n := range tc.writes {
				if err := c.Add(n); err != nil {
					lastErr = err
					break
				}
			}
			if tc.wantErr {
				if lastErr == nil {
					t.Fatalf("expected ErrArchiveRatioCap; got nil")
				}
				if !errors.Is(lastErr, file.ErrArchiveRatioCap) {
					t.Fatalf("want ErrArchiveRatioCap, got %v", lastErr)
				}
				return
			}
			if lastErr != nil {
				t.Fatalf("expected no error, got %v", lastErr)
			}
		})
	}
}

// TestArchive_NoCounter_NoOp verifies that Add on a nil receiver returns nil.
// Callers that pass nil opt out of accounting; the documented no-op preserves
// the additive default contract for library-API consumers.
func TestArchive_NoCounter_NoOp(t *testing.T) {
	t.Parallel()

	var c *file.ArchiveCounter
	if err := c.Add(1 << 20); err != nil {
		t.Fatalf("nil receiver Add returned %v; want nil", err)
	}
	// Multiple calls remain no-op.
	for range 4 {
		if err := c.Add(1 << 20); err != nil {
			t.Fatalf("nil receiver Add returned %v; want nil", err)
		}
	}
}

// TestArchiveCounter_BelowLimits_Succeeds is the positive case: a write under
// both caps returns nil and increments Total.
func TestArchiveCounter_BelowLimits_Succeeds(t *testing.T) {
	t.Parallel()

	c := &file.ArchiveCounter{MaxBytes: 1 << 20, MaxRatio: 100, InputBytes: 1 << 14}
	if err := c.Add(1024); err != nil {
		t.Fatalf("Add returned %v; want nil", err)
	}
	if got := c.Total.Load(); got != 1024 {
		t.Fatalf("Total = %d; want 1024", got)
	}
	if err := c.Add(2048); err != nil {
		t.Fatalf("Add returned %v; want nil", err)
	}
	if got := c.Total.Load(); got != 3072 {
		t.Fatalf("Total = %d; want 3072", got)
	}
}

// TestArchiveCounter_AtomicConcurrency runs N goroutines that each call Add
// and checks Total equals the sum of all writes (no torn reads, no lost
// updates). The race detector verifies the atomic semantics independently.
func TestArchiveCounter_AtomicConcurrency(t *testing.T) {
	t.Parallel()

	const goroutines = 64
	const perG = 1024
	const writeSize = 8

	c := &file.ArchiveCounter{
		MaxBytes:   int64(goroutines) * int64(perG) * int64(writeSize) * 2,
		InputBytes: 1 << 30,
	}

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for range goroutines {
		go func() {
			defer wg.Done()
			for range perG {
				if err := c.Add(writeSize); err != nil {
					t.Errorf("Add returned %v; want nil", err)
					return
				}
			}
		}()
	}
	wg.Wait()

	want := int64(goroutines) * int64(perG) * int64(writeSize)
	if got := c.Total.Load(); got != want {
		t.Fatalf("Total = %d; want %d (lost updates indicate non-atomic Add)", got, want)
	}
}

// TestExtractZip_DefaultBytesCap_Fires proves the package-level default cap is
// applied at the ExtractZip allocation site. The production default
// (file.DefaultMaxArchiveBytes = 16 GiB) is too large to synthesize, so the
// test temporarily shrinks defaultMaxArchiveBytes; the lowest-blast-radius
// override available without touching production callers.
func TestExtractZip_DefaultBytesCap_Fires(t *testing.T) {
	const capBytes = 1024
	const payload = 4096

	original := defaultMaxArchiveBytes
	defaultMaxArchiveBytes = capBytes
	t.Cleanup(func() { defaultMaxArchiveBytes = original })

	tmp := t.TempDir()
	zipPath := filepath.Join(tmp, "oversize.zip")
	zf, err := os.OpenFile(zipPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatalf("create zip: %v", err)
	}

	zw := zip.NewWriter(zf)
	w, err := zw.Create("payload.bin")
	if err != nil {
		_ = zf.Close()
		t.Fatalf("create entry: %v", err)
	}
	if _, err := w.Write(make([]byte, payload)); err != nil {
		_ = zf.Close()
		t.Fatalf("write payload: %v", err)
	}
	if err := zw.Close(); err != nil {
		_ = zf.Close()
		t.Fatalf("close zip writer: %v", err)
	}
	if err := zf.Close(); err != nil {
		t.Fatalf("close zip file: %v", err)
	}

	dst := filepath.Join(tmp, "out")
	err = ExtractZip(context.Background(), dst, zipPath)
	if err == nil {
		t.Fatalf("ExtractZip succeeded; want ErrArchiveBytesCap")
	}
	if !errors.Is(err, file.ErrArchiveBytesCap) {
		t.Fatalf("ExtractZip err = %v; want chain containing ErrArchiveBytesCap", err)
	}
}

// TestResolveArchiveCaps_DefaultsWhenNoConfig verifies that with no Config on
// the context, resolveArchiveCaps returns the package-level defaults.
func TestResolveArchiveCaps_DefaultsWhenNoConfig(t *testing.T) {
	t.Parallel()

	gotBytes, gotRatio := resolveArchiveCaps(context.Background())
	if gotBytes != defaultMaxArchiveBytes {
		t.Fatalf("maxBytes = %d; want %d", gotBytes, defaultMaxArchiveBytes)
	}
	if gotRatio != file.DefaultMaxArchiveRatio {
		t.Fatalf("maxRatio = %v; want %v", gotRatio, file.DefaultMaxArchiveRatio)
	}
}

// TestResolveArchiveCaps_ConfigOverrides covers the precedence rules: a
// non-zero Config field overrides the default; a zero/unset field falls back.
// A nil Config on the context is equivalent to no Config at all.
func TestResolveArchiveCaps_ConfigOverrides(t *testing.T) {
	t.Parallel()

	const customBytes int64 = 4096
	const customRatio float64 = 7.5

	tests := []struct {
		name      string
		cfg       *malcontent.Config
		wantBytes int64
		wantRatio float64
	}{
		{
			name:      "nil_config",
			cfg:       nil,
			wantBytes: defaultMaxArchiveBytes,
			wantRatio: file.DefaultMaxArchiveRatio,
		},
		{
			name:      "zero_values_config",
			cfg:       &malcontent.Config{},
			wantBytes: defaultMaxArchiveBytes,
			wantRatio: file.DefaultMaxArchiveRatio,
		},
		{
			name:      "bytes_override_only",
			cfg:       &malcontent.Config{MaxArchiveBytes: customBytes},
			wantBytes: customBytes,
			wantRatio: file.DefaultMaxArchiveRatio,
		},
		{
			name:      "ratio_override_only",
			cfg:       &malcontent.Config{MaxArchiveRatio: customRatio},
			wantBytes: defaultMaxArchiveBytes,
			wantRatio: customRatio,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := malcontent.ContextWithConfig(context.Background(), tc.cfg)
			gotBytes, gotRatio := resolveArchiveCaps(ctx)
			if gotBytes != tc.wantBytes {
				t.Fatalf("maxBytes = %d; want %d", gotBytes, tc.wantBytes)
			}
			if gotRatio != tc.wantRatio {
				t.Fatalf("maxRatio = %v; want %v", gotRatio, tc.wantRatio)
			}
		})
	}
}
