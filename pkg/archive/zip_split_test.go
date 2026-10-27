// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/chainguard-dev/clog"
	zip "github.com/klauspost/compress/zip"
)

func TestSplitByCaps(t *testing.T) {
	t.Parallel()
	entry := func(name string, size uint64) zipEntry {
		return zipEntry{zf: &zip.File{Name: name, UncompressedSize64: size}, name: name, path: name}
	}
	entries := []zipEntry{entry("e", 5), entry("a", 1), entry("b", 3), entry("c", 3), entry("z", 0)}
	names := func(files []zipEntry) []string {
		out := make([]string, len(files))
		for i, f := range files {
			out[i] = f.name
		}
		return out
	}
	tests := []struct {
		name     string
		budget   int64
		fit      []string
		wantOver []string
	}{
		// Smallest first, ties in archive order; an entry that exactly
		// fills what is left fits.
		{name: "budget filled exactly", budget: 7, fit: []string{"z", "a", "b", "c"}, wantOver: []string{"e"}},
		{name: "budget for all", budget: 12, fit: []string{"z", "a", "b", "c", "e"}},
		{name: "budget one short", budget: 11, fit: []string{"z", "a", "b", "c"}, wantOver: []string{"e"}},
		{name: "empty budget fits only empty entries", budget: 0, fit: []string{"z"}, wantOver: []string{"a", "b", "c", "e"}},
		{name: "negative budget fits only empty entries", budget: -1, fit: []string{"z"}, wantOver: []string{"a", "b", "c", "e"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fit, over := splitByCaps(entries, tt.budget)
			if got := names(fit); !slices.Equal(got, tt.fit) {
				t.Errorf("fit: got = %q, want = %q", got, tt.fit)
			}
			if got := names(over); !slices.Equal(got, tt.wantOver) && len(got)+len(tt.wantOver) > 0 {
				t.Errorf("over: got = %q, want = %q", got, tt.wantOver)
			}
		})
	}
	if got := names(entries); !slices.Equal(got, []string{"e", "a", "b", "c", "z"}) {
		t.Errorf("entries after splitting: got = %q, want them unchanged", got)
	}
}

func TestExtractEntriesStopsForACanceledContext(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	src := filepath.Join(dir, "a.zip")
	zipSpecWrite(t, src, zip.Deflate, []zipSpecEntry{{name: "x/a.txt", body: "a"}, {name: "x/b.txt", body: "b"}})
	rc, err := zip.OpenReader(src)
	if err != nil {
		t.Fatalf("OpenReader: %v", err)
	}
	defer rc.Close()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	x := &zipExtraction{ctx: ctx, logger: clog.FromContext(t.Context()), paths: testPaths(t, openTestRoot(t, dir)), budget: testBudget(0)}
	entries := make([]zipEntry, len(rc.File))
	for i, zf := range rc.File {
		entries[i] = zipEntry{zf: zf, name: zf.Name, path: zf.Name}
	}
	err = errors.Join(extractEntries(ctx, entries, src, x)...)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("extractEntries: got err = %v, want = %v", err, context.Canceled)
	}
}

func TestExtractZipReportsAnUnreadableArchive(t *testing.T) {
	t.Parallel()
	// A local file header and nothing else: detected as a zip, but with no
	// central directory to read.
	src := writeTemp(t, "broken.zip", []byte("PK\x03\x04\x14\x00\x00\x00\x08\x00truncated"))
	err := ExtractZip(t.Context(), t.TempDir(), src)
	if err == nil || !strings.Contains(err.Error(), "not a valid zip archive") {
		t.Errorf("ExtractZip: got err = %v, want the archive reported as unreadable", err)
	}
}
