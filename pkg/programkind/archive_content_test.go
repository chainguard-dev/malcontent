// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package programkind

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"testing"

	"github.com/klauspost/compress/zip"
	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"
)

func zipBytes(t *testing.T, prefix string) []byte {
	t.Helper()
	var buf bytes.Buffer
	buf.WriteString(prefix)
	zw := zip.NewWriter(&buf)
	zw.SetOffset(int64(len(prefix)))
	w, err := zw.Create("a.txt")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Write([]byte("a"))
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestDetectArchiveContent(t *testing.T) {
	t.Parallel()
	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	_ = tw.WriteHeader(&tar.Header{Name: "a", Mode: 0o644, Size: 1})
	_, _ = tw.Write([]byte("a"))
	_ = tw.Close()
	var xzBuf bytes.Buffer
	xw, err := xz.NewWriter(&xzBuf)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = xw.Write([]byte("a"))
	_ = xw.Close()
	enc, err := zstd.NewWriter(nil)
	if err != nil {
		t.Fatal(err)
	}
	zst := enc.EncodeAll([]byte("a"), nil)
	_ = enc.Close()
	var gzBuf bytes.Buffer
	gw := gzip.NewWriter(&gzBuf)
	_, _ = gw.Write([]byte("a"))
	_ = gw.Close()
	elf := append([]byte{0x7f, 'E', 'L', 'F', 2, 1, 1}, make([]byte, 57)...)

	tests := []struct {
		name        string
		path        string
		content     []byte
		wantMIME    string
		wantArchive string
		archive     bool
	}{
		{name: "zip under a data name", path: "payload.dat", content: zipBytes(t, ""), wantMIME: "application/zip", archive: true},
		{name: "zip under a script name", path: "run.py", content: zipBytes(t, ""), wantMIME: "application/zip", archive: true},
		{name: "tar without an extension", path: "layer", content: tarBuf.Bytes(), wantMIME: "application/x-tar", archive: true},
		{name: "xz under a data name", path: "blob.bin", content: xzBuf.Bytes(), wantMIME: "application/x-xz", archive: true},
		{name: "zstd under a data name", path: "blob.dat", content: zst, wantMIME: "application/zstd", archive: true},
		{name: "gzip keeps its kind", path: "blob.dat", content: gzBuf.Bytes(), wantMIME: "application/gzip", archive: true},
		{name: "script with a zip appended keeps its kind", path: "install", content: zipBytes(t, "#!/bin/sh\nexit 0\n"), wantMIME: "text/x-shellscript", wantArchive: "zip", archive: true},
		{name: "binary with a zip appended keeps its kind alone", path: "prog", content: append(elf, zipBytes(t, "")...), wantMIME: "application/x-elf"},
		{name: "plain script is no archive", path: "install", content: []byte("#!/bin/sh\nexit 0\n"), wantMIME: "text/x-shellscript"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ft := Detect(t.Context(), tt.path, tt.content)
			if ft == nil {
				t.Fatalf("Detect(%q): got = nil", tt.path)
			}
			if ft.MIME != tt.wantMIME || ft.Archive != tt.wantArchive {
				t.Errorf("Detect(%q): got = %+v, want MIME %q and Archive %q", tt.path, *ft, tt.wantMIME, tt.wantArchive)
			}
			if got := IsSupportedArchiveKind(tt.path, ft); got != tt.archive {
				t.Errorf("IsSupportedArchiveKind(%q): got = %v, want = %v", tt.path, got, tt.archive)
			}
		})
	}
}
