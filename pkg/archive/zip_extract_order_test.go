// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"io/fs"
	"path/filepath"
	"runtime"
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
			name:     "directory entry climbing out is skipped and later directories are created",
			entries:  []zipSpecEntry{{name: "../escape/"}, {name: "kept/"}},
			wantTree: []string{"kept/"},
		},
		{
			name:     "directory entry with a NUL byte is skipped and later directories are created",
			entries:  []zipSpecEntry{{name: "bad\x00name/"}, {name: "kept/"}},
			wantTree: []string{"kept/"},
		},
		{
			name:      "file after a directory entry is extracted",
			entries:   []zipSpecEntry{{name: "kept/"}, {name: "top.txt", body: "top"}},
			wantTree:  []string{"kept/", "top.txt"},
			wantFiles: map[string]string{"top.txt": "top"},
		},
		{
			name:      "file after a symlink entry is extracted and the link resolves to it",
			entries:   []zipSpecEntry{{name: "link", body: "top.txt", mode: symlinkMode}, {name: "top.txt", body: "top"}},
			wantTree:  []string{"link -> top.txt", "top.txt"},
			wantFiles: map[string]string{"top.txt": "top", "link": "top"},
		},
		{
			name:      "nested symlink may climb back to the extraction root",
			entries:   []zipSpecEntry{{name: "dir/link", body: "../top.txt", mode: symlinkMode}, {name: "top.txt", body: "top"}},
			wantTree:  []string{"dir/", "dir/link -> ../top.txt", "top.txt"},
			wantFiles: map[string]string{"dir/link": "top"},
		},
		{
			name:    "symlink climbing above the extraction root fails the extraction",
			entries: []zipSpecEntry{{name: "top.txt", body: "top"}, {name: "link", body: "../../outside", mode: symlinkMode}},
			wantErr: "symlink target escapes extraction directory",
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

// TestExtractZipAgainOverwritesFiles extracts into a directory that already
// holds the archive's paths, as a retried extraction does.
func TestExtractZipAgainOverwritesFiles(t *testing.T) {
	t.Parallel()
	// The platform default decides whether entries overwrite in place, so this
	// keys on the platform rather than on the switch.
	if runtime.GOOS == "darwin" {
		t.Skip("darwin writes entries whose path is taken under a sibling name")
	}

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

	wantTree := []string{"sub/", "sub/inner.txt", "top.txt"}
	if got := zipSpecTree(t, d); !slices.Equal(got, wantTree) {
		t.Errorf("extracted tree: got = %q, want = %q", got, wantTree)
	}
	for name, want := range map[string]string{"top.txt": "new", "sub/inner.txt": "newer"} {
		data, err := file.ReadFileIn(d, name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if string(data) != want {
			t.Errorf("contents of %s: got = %q, want = %q", name, data, want)
		}
	}
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
