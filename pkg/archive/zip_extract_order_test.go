// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/chainguard-dev/malcontent/pkg/file"
	zip "github.com/klauspost/compress/zip"
)

// zipSpecEntry describes one entry of a generated zip archive. Directory
// names end in "/", and a zero mode means a regular file.
type zipSpecEntry struct {
	name string
	body string
	mode fs.FileMode
}

// zipSpecWrite writes entries, in order, to a zip archive at path.
func zipSpecWrite(t *testing.T, path string, method uint16, entries []zipSpecEntry) {
	t.Helper()
	if err := file.WriteFileIn(filepath.Dir(path), filepath.Base(path), zipSpecBytes(t, method, entries), 0o600); err != nil {
		t.Fatalf("write archive: %v", err)
	}
}

// zipSpecBytes returns a zip archive holding entries in order.
func zipSpecBytes(t *testing.T, method uint16, entries []zipSpecEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range entries {
		hdr := &zip.FileHeader{Name: e.name, Method: method}
		if e.mode != 0 {
			hdr.SetMode(e.mode)
		}
		w, err := zw.CreateHeader(hdr)
		if err != nil {
			t.Fatalf("CreateHeader(%q): %v", e.name, err)
		}
		if _, err := io.WriteString(w, e.body); err != nil {
			t.Fatalf("write %q: %v", e.name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return buf.Bytes()
}

// zipSpecTree lists every path beneath dir in sorted order. Directories end
// in "/", symlinks read "name -> target", and regular files appear by name.
func zipSpecTree(t *testing.T, dir string) []string {
	t.Helper()
	r := openTestRoot(t, dir)
	var got []string
	err := fs.WalkDir(r.FS(), ".", func(rel string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		switch {
		case rel == ".":
		case d.Type()&fs.ModeSymlink != 0:
			target, err := r.Readlink(rel)
			if err != nil {
				return err
			}
			got = append(got, rel+" -> "+target)
		case d.IsDir():
			got = append(got, rel+"/")
		default:
			got = append(got, rel)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", dir, err)
	}
	slices.Sort(got)
	return got
}

func TestExtractZipEntryOrderAndSafety(t *testing.T) {
	t.Parallel()

	const symlinkMode = fs.ModeSymlink | 0o777

	tests := []struct {
		name      string
		entries   []zipSpecEntry
		wantErr   string
		wantTree  []string
		wantFiles map[string]string
	}{
		{
			name:     "directory entry climbing out is created beneath the root",
			entries:  []zipSpecEntry{{name: "../escape/"}, {name: "kept/"}},
			wantTree: []string{"escape/", "kept/"},
		},
		{
			name:     "directory entry with a NUL byte is cut at it",
			entries:  []zipSpecEntry{{name: "bad\x00name/"}, {name: "kept/"}},
			wantTree: []string{"bad/", "kept/"},
		},
		{
			name:      "file after a directory entry is extracted",
			entries:   []zipSpecEntry{{name: "kept/"}, {name: "top.txt", body: "top"}},
			wantTree:  []string{"kept/", "top.txt"},
			wantFiles: map[string]string{"top.txt": "top"},
		},
		{
			// Symlink entries are written as files holding their targets, as
			// Python's zipfile writes them.
			name:      "symlink entry is written as a file holding its target",
			entries:   []zipSpecEntry{{name: "link", body: "top.txt", mode: symlinkMode}, {name: "top.txt", body: "top"}},
			wantTree:  []string{"link", "top.txt"},
			wantFiles: map[string]string{"top.txt": "top", "link": "top.txt"},
		},
		{
			name:      "symlink entry climbing above the root is written as a file",
			entries:   []zipSpecEntry{{name: "top.txt", body: "top"}, {name: "link", body: "../../outside", mode: symlinkMode}},
			wantTree:  []string{"link", "top.txt"},
			wantFiles: map[string]string{"link": "../../outside"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			src := filepath.Join(t.TempDir(), "case.zip")
			zipSpecWrite(t, src, zip.Deflate, tt.entries)
			parent := t.TempDir()
			d := filepath.Join(parent, "out")

			err := ExtractZip(t.Context(), d, src)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("ExtractZip error: got = %v, want = containing %q", err, tt.wantErr)
				}
			} else if err != nil {
				t.Fatalf("ExtractZip error: got = %v, want = nil", err)
			}

			pr := openTestRoot(t, parent)
			siblings, err := fs.ReadDir(pr.FS(), ".")
			if err != nil {
				t.Fatalf("read parent: %v", err)
			}
			names := make([]string, 0, len(siblings))
			for _, s := range siblings {
				names = append(names, s.Name())
			}
			if !slices.Equal(names, []string{"out"}) {
				t.Errorf("entries beside the extraction directory: got = %q, want = %q", names, []string{"out"})
			}
			if tt.wantErr != "" {
				return
			}

			if got := zipSpecTree(t, d); !slices.Equal(got, tt.wantTree) {
				t.Errorf("extracted tree: got = %q, want = %q", got, tt.wantTree)
			}
			for name, want := range tt.wantFiles {
				data, err := pr.ReadFile(filepath.Join("out", name))
				if err != nil {
					t.Errorf("read %s: %v", name, err)
					continue
				}
				if string(data) != want {
					t.Errorf("contents of %s: got = %q, want = %q", name, data, want)
				}
			}
		})
	}
}

// TestExtractZipAbsoluteNames extracts entries named by absolute paths with
// and without the case-folding handling, since only one runs by default on
// each platform. Tests that set caseInsensitiveFS must not call t.Parallel.
func TestExtractZipAbsoluteNames(t *testing.T) {
	entries := []zipSpecEntry{
		{name: "/abs/"},
		{name: "/abs/evil.php", body: "evil"},
		{name: "//double.php", body: "double"},
		{name: "/link", body: "top.txt", mode: fs.ModeSymlink | 0o777},
		{name: "kept/"},
		{name: "kept/f.txt", body: "f"},
		{name: "top.txt", body: "top"},
	}
	want := []string{"abs/", "abs/evil.php", "double.php", "kept/", "kept/f.txt", "link", "top.txt"}
	wantFiles := map[string]string{"abs/evil.php": "evil", "double.php": "double", "link": "top.txt"}
	for _, fold := range []bool{false, true} {
		t.Run(fmt.Sprintf("fold=%v", fold), func(t *testing.T) {
			prev := caseInsensitiveFS
			caseInsensitiveFS = fold
			t.Cleanup(func() { caseInsensitiveFS = prev })

			src := filepath.Join(t.TempDir(), "abs.zip")
			zipSpecWrite(t, src, zip.Deflate, entries)
			d := filepath.Join(t.TempDir(), "out")
			if err := ExtractZip(t.Context(), d, src); err != nil {
				t.Fatalf("ExtractZip error: got = %v, want = nil", err)
			}
			if got := zipSpecTree(t, d); !slices.Equal(got, want) {
				t.Errorf("extracted tree: got = %q, want = %q", got, want)
			}
			r := openTestRoot(t, d)
			for name, want := range wantFiles {
				if got, err := r.ReadFile(name); err != nil || string(got) != want {
					t.Errorf("contents of %s: got = (%q, %v), want = (%q, nil)", name, got, err, want)
				}
			}
		})
	}
}

// TestExtractZipAgainKeepsEarlierFiles extracts into a directory that
// already holds the archive's paths, as a retried extraction does: entries
// never replace what is there, but take sibling names.
func TestExtractZipAgainKeepsEarlierFiles(t *testing.T) {
	t.Parallel()

	srcDir := t.TempDir()
	first := filepath.Join(srcDir, "first.zip")
	second := filepath.Join(srcDir, "second.zip")
	zipSpecWrite(t, first, zip.Deflate, []zipSpecEntry{
		{name: "top.txt", body: "original contents"},
		{name: "sub/inner.txt", body: "original inner"},
	})
	zipSpecWrite(t, second, zip.Deflate, []zipSpecEntry{
		{name: "top.txt", body: "new"},
		{name: "sub/inner.txt", body: "newer"},
	})

	d := filepath.Join(t.TempDir(), "out")
	for _, src := range []string{first, second} {
		if err := ExtractZip(t.Context(), d, src); err != nil {
			t.Fatalf("ExtractZip(%s) error: got = %v, want = nil", filepath.Base(src), err)
		}
	}
	wantTree(t, d, map[string]string{
		"sub":             "/",
		"sub/inner.txt":   "original inner",
		"sub/inner_1.txt": "newer",
		"top.txt":         "original contents",
		"top_1.txt":       "new",
	})
}

func TestExtractZipRejectsNonZipContent(t *testing.T) {
	t.Parallel()

	var gz bytes.Buffer
	gw := gzip.NewWriter(&gz)
	if _, err := gw.Write([]byte("not a zip archive\n")); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}

	tests := []struct {
		name string
		data []byte
	}{
		// File detection reports no type at all for this content.
		{name: "content of no recognized type", data: bytes.Repeat([]byte{0x00, 0xff, 0x13, 0x37}, 64)},
		{name: "gzip content", data: gz.Bytes()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			src := filepath.Join(dir, "payload")
			if err := file.WriteFileIn(dir, "payload", tt.data, 0o600); err != nil {
				t.Fatalf("write input: %v", err)
			}
			err := ExtractZip(t.Context(), t.TempDir(), src)
			if err == nil {
				t.Fatal("ExtractZip error: got = nil, want = not a valid zip archive")
			}
			if errors.Is(err, ErrExtractorPanic) {
				t.Fatalf("ExtractZip error: got = %v, want = a validation error rather than a recovered panic", err)
			}
			if !strings.Contains(err.Error(), "not a valid zip archive") {
				t.Errorf("ExtractZip error: got = %v, want = containing %q", err, "not a valid zip archive")
			}
		})
	}
}
