// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	zip "github.com/klauspost/compress/zip"
	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"
	"github.com/ulikunitz/xz/lzma"
)

// zipModeEntry returns a zip holding ok.txt and an entry name whose Unix mode
// is mode and whose content is body.
func zipModeEntry(t *testing.T, name string, mode fs.FileMode, body string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("ok.txt")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(w, "ok")
	hdr := &zip.FileHeader{Name: name, Method: zip.Deflate}
	if mode != 0 {
		hdr.SetMode(mode)
	}
	w, err = zw.CreateHeader(hdr)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(w, body)
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestExtractZipCleansNamesInsteadOfSkipping(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		entry string
		want  string
	}{
		{name: "element containing dots is kept", entry: "lib/a..b.sh", want: "lib/a..b.sh"},
		{name: "leading climb is dropped", entry: "../up.sh", want: "up.sh"},
		{name: "climb past the root through a directory is dropped", entry: "a/../../b.sh", want: "b.sh"},
		{name: "backslashes are part of the name", entry: `..\win.bat`, want: `..\win.bat`},
		{name: "name is cut at a NUL byte", entry: "run.py\x00.txt", want: "run.py"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			src := writeTemp(t, "x.zip", zipModeEntry(t, tt.entry, 0, benignMarker))
			out := filepath.Join(t.TempDir(), "out")
			if err := ExtractZip(t.Context(), out, src); err != nil {
				t.Fatalf("ExtractZip: %v", err)
			}
			pkgsWantFile(t, filepath.Join(out, "ok.txt"), "ok")
			pkgsWantFile(t, filepath.Join(out, tt.want), benignMarker)
		})
	}
}

func TestExtractZipEntryModes(t *testing.T) {
	t.Parallel()
	large := strings.Repeat(benignMarker+"\n", 400)
	tests := []struct {
		name  string
		entry string
		mode  fs.FileMode
		body  string
		want  map[string]string
	}{
		{name: "directory mode without a trailing slash is a file", entry: "run.py", mode: fs.ModeDir | 0o755, body: benignMarker, want: map[string]string{"ok.txt": "ok", "run.py": benignMarker}},
		{name: "symlink is written as a file holding its bytes", entry: "run.py", mode: fs.ModeSymlink | 0o777, body: benignMarker, want: map[string]string{"ok.txt": "ok", "run.py": benignMarker}},
		{name: "symlink longer than any target is written as a file", entry: "run.py", mode: fs.ModeSymlink | 0o777, body: large, want: map[string]string{"ok.txt": "ok", "run.py": large}},
		{name: "trailing slash without content is a directory", entry: "lib/", want: map[string]string{"ok.txt": "ok", "lib": "/"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			src := writeTemp(t, "x.zip", zipModeEntry(t, tt.entry, tt.mode, tt.body))
			out := filepath.Join(t.TempDir(), "out")
			if err := ExtractZip(t.Context(), out, src); err != nil {
				t.Fatalf("ExtractZip: %v", err)
			}
			wantTree(t, out, tt.want)
		})
	}
}

func TestExtractZipDuplicateNamesKeepEveryEntry(t *testing.T) {
	first := benignMarker + strings.Repeat("A", 4096)
	second := strings.Repeat("B", len(first))
	for _, fold := range []bool{false, true} {
		t.Run(fmt.Sprintf("fold=%v", fold), func(t *testing.T) {
			withCaseFolding(t, fold)
			src := writeTemp(t, "x.zip", zipSpecBytes(t, zip.Deflate, []zipSpecEntry{{name: "dup.sh", body: first}, {name: "dup.sh", body: second}}))
			// Paths are reserved in archive order, so they do not depend on
			// how the concurrent writes interleave.
			for range 10 {
				out := filepath.Join(t.TempDir(), "out")
				if err := ExtractZip(t.Context(), out, src); err != nil {
					t.Fatalf("ExtractZip: %v", err)
				}
				wantTree(t, out, map[string]string{"dup.sh": first, "dup_1.sh": second})
			}
		})
	}
}

// zipRawEntry returns a zip holding one entry named name whose data, written
// as it is, was compressed with method from content.
func zipRawEntry(t *testing.T, name string, method uint16, compressed []byte, content string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.CreateRaw(&zip.FileHeader{
		Name:               name,
		Method:             method,
		CRC32:              crc32.ChecksumIEEE([]byte(content)),
		CompressedSize64:   uint64(len(compressed)),
		UncompressedSize64: uint64(len(content)),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(compressed); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestExtractZipCompressionMethods(t *testing.T) {
	t.Parallel()
	content := "print(\"" + benignMarker + "\")\n"
	bz2, err := os.ReadFile(filepath.Join("testdata", "marker.py.bz2"))
	if err != nil {
		t.Fatal(err)
	}
	enc, err := zstd.NewWriter(nil)
	if err != nil {
		t.Fatal(err)
	}
	zst := enc.EncodeAll([]byte(content), nil)
	_ = enc.Close()

	var xzBuf bytes.Buffer
	xw, err := xz.NewWriter(&xzBuf)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(xw, content)
	if err := xw.Close(); err != nil {
		t.Fatal(err)
	}

	// Zip LZMA data: a version, the properties size, and the properties of a
	// classic .lzma header, whose 8-byte size field the zip format omits.
	var lz bytes.Buffer
	lw, err := lzma.WriterConfig{SizeInHeader: true, Size: int64(len(content))}.NewWriter(&lz)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(lw, content)
	if err := lw.Close(); err != nil {
		t.Fatal(err)
	}
	classic := lz.Bytes()
	zipLZMA := slices.Concat([]byte{9, 20}, binary.LittleEndian.AppendUint16(nil, 5), classic[:5], classic[13:])

	tests := []struct {
		name       string
		method     uint16
		compressed []byte
		wantErr    bool
	}{
		{name: "zstd", method: zstd.ZipMethodWinZip, compressed: zst},
		{name: "bzip2", method: 12, compressed: bz2},
		{name: "lzma", method: 14, compressed: zipLZMA},
		{name: "xz", method: 95, compressed: xzBuf.Bytes()},
		{name: "unknown method", method: 99, compressed: []byte(content), wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			src := writeTemp(t, "x.zip", zipRawEntry(t, "run.py", tt.method, tt.compressed, content))
			out := filepath.Join(t.TempDir(), "out")
			err := ExtractZip(t.Context(), out, src)
			if tt.wantErr {
				if !errors.Is(err, ErrUnaccountedBytes) {
					t.Errorf("ExtractZip error: got = %v, want = %v", err, ErrUnaccountedBytes)
				}
				return
			}
			if err != nil {
				t.Fatalf("ExtractZip: %v", err)
			}
			wantTree(t, out, map[string]string{"run.py": content})
		})
	}
}
