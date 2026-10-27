// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	zip "github.com/klauspost/compress/zip"
)

// zipWithout returns zip archive z with the central directory record of
// entry name removed, leaving its local entry in place: what streaming
// readers extract and central-directory readers never see.
func zipWithout(t *testing.T, z []byte, name string) []byte {
	t.Helper()
	eocd := bytes.LastIndex(z, zipEOCDSignature)
	cdSize := int(binary.LittleEndian.Uint32(z[eocd+12:]))
	cdOffset := int(binary.LittleEndian.Uint32(z[eocd+16:]))
	cd := z[cdOffset : cdOffset+cdSize]
	var kept []byte
	n := 0
	for p := 0; p < len(cd); {
		nameLen := int(binary.LittleEndian.Uint16(cd[p+28:]))
		recLen := zipCentralHeaderLen + nameLen + int(binary.LittleEndian.Uint16(cd[p+30:])) + int(binary.LittleEndian.Uint16(cd[p+32:]))
		if string(cd[p+zipCentralHeaderLen:p+zipCentralHeaderLen+nameLen]) != name {
			kept = append(kept, cd[p:p+recLen]...)
			n++
		}
		p += recLen
	}
	end := slices.Clone(z[eocd : eocd+zipEOCDLen])
	binary.LittleEndian.PutUint16(end[8:], uint16(n))
	binary.LittleEndian.PutUint16(end[10:], uint16(n))
	binary.LittleEndian.PutUint32(end[12:], uint32(len(kept)))
	return slices.Concat(z[:cdOffset], kept, end)
}

// zipPrefixedBody is the content of the entry zipPrefixed writes: repeated, so
// that it is deflated and never appears in the archive's raw bytes.
var zipPrefixedBody = strings.Repeat(benignMarker, 8)

// zipPrefixed returns a zip holding entry.txt with prefix before it, its
// offsets counting from the start of the file when absolute is set and from
// the start of the zip otherwise.
func zipPrefixed(t *testing.T, prefix string, absolute bool) []byte {
	t.Helper()
	var buf bytes.Buffer
	buf.WriteString(prefix)
	zw := zip.NewWriter(&buf)
	if absolute {
		zw.SetOffset(int64(len(prefix)))
	}
	w, err := zw.Create("entry.txt")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(w, zipPrefixedBody)
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if absolute {
		return buf.Bytes()
	}
	return slices.Concat([]byte(prefix), buf.Bytes()[len(prefix):])
}

func TestExtractZipAccountsForEveryRegion(t *testing.T) {
	t.Parallel()
	three := zipSpecBytes(t, zip.Deflate, []zipSpecEntry{{name: "a.txt", body: "alpha"}, {name: "hidden.sh", body: benignMarker}, {name: "b.txt", body: "beta"}})
	stored := zipSpecBytes(t, zip.Store, []zipSpecEntry{{name: "a.txt", body: "alpha"}, {name: "b.txt", body: "beta"}})
	valid := zipAuditArchive(t, "")
	eocdAt := len(valid) - zipEOCDLen
	secondLocal := 4 + bytes.Index(stored[4:], zipLocalMagic)
	script := "#!/bin/sh\nexec java -jar \"$0\" \"$@\"\n"

	tests := []struct {
		name    string
		data    []byte
		want    map[string]string
		wantErr string
	}{
		{name: "well-formed archive with data descriptors", data: three, want: map[string]string{"a.txt": "alpha", "hidden.sh": benignMarker, "b.txt": "beta"}},
		{name: "local entry the central directory omits is extracted", data: zipWithout(t, three, "hidden.sh"), want: map[string]string{"a.txt": "alpha", "hidden.sh": benignMarker, "b.txt": "beta"}},
		{name: "bytes appended after the end record are reported", data: slices.Concat(valid, []byte("1234567")), want: map[string]string{"entry.txt": "entry contents"}, wantErr: "7 bytes follow the end-of-central-directory record"},
		{name: "bytes between the central directory and the end record are reported", data: slices.Concat(valid[:eocdAt], make([]byte, 9), valid[eocdAt:]), want: map[string]string{"entry.txt": "entry contents"}, wantErr: "9 bytes lie outside every entry"},
		{name: "bytes between entries are reported", data: insertAt(stored, secondLocal, []byte("JUNKJUNK")), want: map[string]string{"a.txt": "alpha", "b.txt": "beta"}, wantErr: "8 bytes lie outside every entry"},
		{name: "script before a zip whose offsets count it is reported", data: zipPrefixed(t, script, true), want: map[string]string{"entry.txt": zipPrefixedBody}, wantErr: "lie outside every entry"},
		{name: "script before a zip whose offsets do not count it is reported", data: zipPrefixed(t, script, false), want: map[string]string{"entry.txt": zipPrefixedBody}, wantErr: "lie outside every entry"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			src := writeTemp(t, "x.zip", tt.data)
			out := filepath.Join(t.TempDir(), "out")
			err := ExtractZip(t.Context(), out, src)
			switch {
			case tt.wantErr == "" && err != nil:
				t.Errorf("ExtractZip error: got = %v, want = nil", err)
			case tt.wantErr != "" && (!errors.Is(err, ErrUnaccountedBytes) || !strings.Contains(err.Error(), tt.wantErr)):
				t.Errorf("ExtractZip error: got = %v, want %v mentioning %q", err, ErrUnaccountedBytes, tt.wantErr)
			}
			wantTree(t, out, tt.want)
		})
	}
}

// insertAt returns zip archive z with extra inserted at offset i, before the
// central directory, and the offsets in the central directory and end record
// that lie past i moved to match.
func insertAt(z []byte, i int, extra []byte) []byte {
	out := slices.Concat(z[:i], extra, z[i:])
	eocd := bytes.LastIndex(out, zipEOCDSignature)
	cdSize := int(binary.LittleEndian.Uint32(out[eocd+12:]))
	cdOffset := int(binary.LittleEndian.Uint32(out[eocd+16:])) + len(extra)
	binary.LittleEndian.PutUint32(out[eocd+16:], uint32(cdOffset))
	cd := out[cdOffset : cdOffset+cdSize]
	for p := 0; p < len(cd); {
		if local := int(binary.LittleEndian.Uint32(cd[p+42:])); local >= i {
			binary.LittleEndian.PutUint32(cd[p+42:], uint32(local+len(extra)))
		}
		p += zipCentralHeaderLen + int(binary.LittleEndian.Uint16(cd[p+28:])) + int(binary.LittleEndian.Uint16(cd[p+30:])) + int(binary.LittleEndian.Uint16(cd[p+32:]))
	}
	return out
}

func TestExtractZipWritesCommentsToSidecar(t *testing.T) {
	t.Parallel()
	withComments := func(archive, entry string) []byte {
		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)
		w, err := zw.CreateHeader(&zip.FileHeader{Name: "a.txt", Method: zip.Deflate, Comment: entry})
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.WriteString(w, "a")
		if archive != "" {
			_ = zw.SetComment(archive)
		}
		if err := zw.Close(); err != nil {
			t.Fatal(err)
		}
		return buf.Bytes()
	}
	tests := []struct {
		name string
		data []byte
		want map[string]string
	}{
		{name: "archive comment", data: withComments(benignMarker, ""), want: map[string]string{"a.txt": "a", "malcontent-metadata.bin": "zip comment: " + benignMarker + "\n"}},
		{name: "entry comment", data: withComments("", benignMarker), want: map[string]string{"a.txt": "a", "malcontent-metadata.bin": `zip entry "a.txt" comment: ` + benignMarker + "\n"}},
		{name: "no comment writes no sidecar", data: withComments("", ""), want: map[string]string{"a.txt": "a"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			src := writeTemp(t, "x.zip", tt.data)
			out := filepath.Join(t.TempDir(), "out")
			if err := ExtractZip(t.Context(), out, src); err != nil {
				t.Fatalf("ExtractZip: %v", err)
			}
			wantTree(t, out, tt.want)
		})
	}
}
