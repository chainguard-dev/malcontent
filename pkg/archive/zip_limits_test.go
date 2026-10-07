// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
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
			srcDir := t.TempDir()
			src := filepath.Join(srcDir, "input.zip")
			if err := file.WriteFileIn(srcDir, "input.zip", tt.data, 0o600); err != nil {
				t.Fatalf("write input: %v", err)
			}
			// out is the destination's name in base.
			base, out := t.TempDir(), "out"
			if tt.destUnderFile {
				if err := file.WriteFileIn(base, "blocker", nil, 0o600); err != nil {
					t.Fatalf("write blocker: %v", err)
				}
				out = filepath.Join("blocker", "out")
			}
			d := filepath.Join(base, out)

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
			if _, statErr := file.LstatIn(base, out); !errors.Is(statErr, fs.ErrNotExist) && !errors.Is(statErr, syscall.ENOTDIR) {
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
	extracted, err := fs.ReadDir(openTestRoot(t, d).FS(), ".")
	if err != nil {
		t.Fatalf("read destination: %v", err)
	}
	if len(extracted) != count {
		t.Errorf("extracted entries: got = %d, want = %d", len(extracted), count)
	}
}

// TestExtractZipPartialExtractionIsDeterministic checks which entries an
// extraction that fails leaves behind: every entry that fits within the caps
// and is intact, whatever the order of the archive, and of the entries that
// do not fit, only the smallest, cut short. With one worker, an extraction
// that stopped at its first failure would leave only what preceded it. It
// changes process-wide state, so it must not call t.Parallel.
func TestExtractZipPartialExtractionIsDeterministic(t *testing.T) {
	extractionSemaphore()
	prevProcs := runtime.GOMAXPROCS(1)
	t.Cleanup(func() { runtime.GOMAXPROCS(prevProcs) })

	zeros := func(n int) string { return strings.Repeat("\x00", n) }
	const small, smallBody = "a.txt", "alpha\n"
	tests := []struct {
		name    string
		entries []zipSpecEntry
		corrupt string // an entry whose stored data is altered after writing
		// want maps each entry expected on disk to its full body, or to "" for
		// an entry cut short.
		want    map[string]string
		wantErr error
	}{
		{
			name:    "entries within the ratio cap survive a larger entry before them",
			entries: []zipSpecEntry{{name: "big.bin", body: zeros(1 << 20)}, {name: small, body: smallBody}, {name: "b.txt", body: "beta\n"}},
			want:    map[string]string{"big.bin": "", small: smallBody, "b.txt": "beta\n"},
			wantErr: file.ErrArchiveRatioCap,
		},
		{
			name:    "entries beyond the cap stop at the smallest of them",
			entries: []zipSpecEntry{{name: "huge.bin", body: zeros(2 << 20)}, {name: small, body: smallBody}, {name: "big.bin", body: zeros(1 << 20)}},
			want:    map[string]string{small: smallBody, "big.bin": ""},
			wantErr: file.ErrArchiveRatioCap,
		},
		{
			name:    "a corrupt entry leaves the intact entries after it",
			entries: []zipSpecEntry{{name: "bad.bin", body: "corrupt-me-please"}, {name: small, body: smallBody}, {name: "b.txt", body: "beta\n"}},
			corrupt: "corrupt-me-please",
			// The altered byte is the first of the stored data.
			want:    map[string]string{"bad.bin": "\x9corrupt-me-please", small: smallBody, "b.txt": "beta\n"},
			wantErr: zip.ErrChecksum,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			method := zip.Deflate
			if tt.corrupt != "" {
				// Stored data appears verbatim in the archive.
				method = zip.Store
			}
			data := zipSpecBytes(t, method, tt.entries)
			if tt.corrupt != "" {
				i := bytes.Index(data, []byte(tt.corrupt))
				if i < 0 {
					t.Fatalf("fixture: stored data %q not found", tt.corrupt)
				}
				data[i] ^= 0xff
			}
			srcDir := t.TempDir()
			src := filepath.Join(srcDir, "input.zip")
			if err := file.WriteFileIn(srcDir, "input.zip", data, 0o600); err != nil {
				t.Fatalf("write input: %v", err)
			}
			d := filepath.Join(t.TempDir(), "out")

			err := ExtractZip(t.Context(), d, src)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("ExtractZip error: got = %v, want = %v", err, tt.wantErr)
			}
			r := openTestRoot(t, d)
			dirents, err := fs.ReadDir(r.FS(), ".")
			if err != nil {
				t.Fatalf("read destination: %v", err)
			}
			got := map[string]string{}
			for _, de := range dirents {
				body, err := r.ReadFile(de.Name())
				if err != nil {
					t.Fatalf("read %s: %v", de.Name(), err)
				}
				got[de.Name()] = string(body)
			}
			for _, e := range tt.entries {
				body, ok := got[e.name]
				want, wantOK := tt.want[e.name]
				switch {
				case ok != wantOK:
					t.Errorf("%s on disk: got = %v, want = %v", e.name, ok, wantOK)
				case ok && want != "" && body != want:
					t.Errorf("%s body: got = %q, want = %q", e.name, body, want)
				case ok && want == "" && len(body) >= len(e.body):
					t.Errorf("%s length: got = %d, want = less than %d", e.name, len(body), len(e.body))
				}
			}
		})
	}
}
