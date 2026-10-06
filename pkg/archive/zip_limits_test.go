// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/chainguard-dev/malcontent/pkg/file"
	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	zip "github.com/klauspost/compress/zip"
)

func TestExtractZipEarlyExits(t *testing.T) {
	t.Parallel()

	valid := zipSpecBytes(t, zip.Deflate, []zipSpecEntry{{name: "entry.txt", body: "entry"}})

	// wantErr empty means success. No case may create the destination.
	tests := []struct {
		name          string
		data          []byte
		destUnderFile bool
		wantErr       string
	}{
		{name: "empty input is skipped without error", data: []byte{}},
		{name: "one-byte input is rejected as not a zip archive", data: []byte("P"), wantErr: "not a valid zip archive"},
		{name: "destination beneath a regular file is reported as an extraction directory failure", data: valid, destUnderFile: true, wantErr: "failed to create extraction directory"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			src := filepath.Join(t.TempDir(), "input.zip")
			if err := os.WriteFile(src, tt.data, 0o600); err != nil {
				t.Fatalf("write input: %v", err)
			}
			d := filepath.Join(t.TempDir(), "out")
			if tt.destUnderFile {
				blocker := filepath.Join(t.TempDir(), "blocker")
				if err := os.WriteFile(blocker, nil, 0o600); err != nil {
					t.Fatalf("write blocker: %v", err)
				}
				d = filepath.Join(blocker, "out")
			}

			err := ExtractZip(t.Context(), d, src)
			switch {
			case tt.wantErr == "" && err != nil:
				t.Fatalf("ExtractZip error: got = %v, want = nil", err)
			case tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)):
				t.Fatalf("ExtractZip error: got = %v, want = containing %q", err, tt.wantErr)
			}
			if errors.Is(err, ErrExtractorPanic) {
				t.Errorf("ExtractZip error: got = %v, want = an error rather than a recovered panic", err)
			}
			if _, statErr := os.Lstat(d); !errors.Is(statErr, fs.ErrNotExist) && !errors.Is(statErr, syscall.ENOTDIR) {
				t.Errorf("destination: got stat err = %v, want = not created", statErr)
			}
		})
	}
}

// TestExtractZipConfiguredRatioCap checks that a configured expansion ratio
// applies even when it is below one. A stored entry expands to slightly less
// than the archive size, so a ratio of 0.5 trips and a ratio of 2 does not.
func TestExtractZipConfiguredRatioCap(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		ratio   float64
		wantCap bool
	}{
		{name: "ratio below one caps a stored entry", ratio: 0.5, wantCap: true},
		{name: "ratio above the entry's expansion lets it through", ratio: 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			src := filepath.Join(t.TempDir(), "stored.zip")
			zipSpecWrite(t, src, zip.Store, []zipSpecEntry{{name: "data.bin", body: strings.Repeat("z", 4096)}})
			ctx := malcontent.ContextWithConfig(t.Context(), &malcontent.Config{MaxArchiveRatio: tt.ratio})

			err := ExtractZip(ctx, filepath.Join(t.TempDir(), "out"), src)
			if got := errors.Is(err, file.ErrArchiveRatioCap); got != tt.wantCap {
				t.Fatalf("ErrArchiveRatioCap: got = %v (err %v), want = %v", got, err, tt.wantCap)
			}
			if !tt.wantCap && err != nil {
				t.Errorf("ExtractZip error: got = %v, want = nil", err)
			}
		})
	}
}

// TestExtractZipBoundsWorkerGoroutines checks that an archive with many entries
// never has more worker goroutines alive than the concurrency limit, so the
// entry count cannot drive goroutine and stack growth, and that extraction
// leaves the process's GOMAXPROCS setting alone. It changes process-wide
// state, so it must not call t.Parallel.
func TestExtractZipBoundsWorkerGoroutines(t *testing.T) {
	// Size the shared extraction semaphore before lowering GOMAXPROCS, so later
	// tests keep their usual concurrency.
	extractionSemaphore()
	const procs = 2
	prevProcs := runtime.GOMAXPROCS(procs)
	t.Cleanup(func() { runtime.GOMAXPROCS(prevProcs) })

	const count = 256
	entries := make([]zipSpecEntry, count)
	for i := range entries {
		entries[i] = zipSpecEntry{name: fmt.Sprintf("f%03d.txt", i), body: "x"}
	}
	src := filepath.Join(t.TempDir(), "many.zip")
	zipSpecWrite(t, src, zip.Deflate, entries)

	var peak atomic.Int64
	base := runtime.NumGoroutine()
	prevHook := workerPanicHook
	workerPanicHook = func(string) {
		alive := int64(runtime.NumGoroutine() - base)
		for {
			cur := peak.Load()
			if alive <= cur || peak.CompareAndSwap(cur, alive) {
				return
			}
		}
	}
	t.Cleanup(func() { workerPanicHook = prevHook })

	d := filepath.Join(t.TempDir(), "out")
	if err := ExtractZip(t.Context(), d, src); err != nil {
		t.Fatalf("ExtractZip error: got = %v, want = nil", err)
	}

	// The limit is at most procs; the margin absorbs a finishing worker that
	// has released its slot but not yet exited.
	const maxAlive = 16
	if got := peak.Load(); got > maxAlive {
		t.Errorf("goroutines alive during extraction: got = %d, want = at most %d", got, maxAlive)
	}
	if got := runtime.GOMAXPROCS(0); got != procs {
		t.Errorf("GOMAXPROCS after extraction: got = %d, want = %d", got, procs)
	}
	extracted, err := os.ReadDir(d)
	if err != nil {
		t.Fatalf("read destination: %v", err)
	}
	if len(extracted) != count {
		t.Errorf("extracted entries: got = %d, want = %d", len(extracted), count)
	}
}
