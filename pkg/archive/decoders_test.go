// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"context"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"io"
	"path/filepath"
	"slices"
	"testing"

	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"
)

// gzipWithHeader returns a gzip member of body whose header carries extra and
// comment.
func gzipWithHeader(t *testing.T, body string, extra []byte, comment string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	gw.Extra = extra
	gw.Comment = comment
	if _, err := io.WriteString(gw, body); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestSingleStreamExtractorsWriteMetadataSidecar(t *testing.T) {
	t.Parallel()
	enc, err := zstd.NewWriter(nil)
	if err != nil {
		t.Fatal(err)
	}
	frame := enc.EncodeAll([]byte("hello"), nil)
	_ = enc.Close()
	skippable := slices.Concat([]byte{0x50, 0x2a, 0x4d, 0x18}, binary.LittleEndian.AppendUint32(nil, uint32(len(benignMarker))), []byte(benignMarker))

	tests := []struct {
		name    string
		file    string
		data    []byte
		extract func(context.Context, string, string) error
		want    map[string]string
	}{
		{
			name:    "gzip extra and comment fields",
			file:    "blob.gz",
			data:    gzipWithHeader(t, "hello", []byte(benignMarker), "note"),
			extract: ExtractGzip,
			want:    map[string]string{"blob": "hello", "malcontent-metadata.bin": "gzip extra: " + benignMarker + "\ngzip comment: note\n"},
		},
		{
			name:    "comment of a later gzip member",
			file:    "blob.gz",
			data:    slices.Concat(gzipWithHeader(t, "hel", nil, ""), gzipWithHeader(t, "lo", nil, benignMarker)),
			extract: ExtractGzip,
			want:    map[string]string{"blob": "hello", "malcontent-metadata.bin": "gzip member 2 comment: " + benignMarker + "\n"},
		},
		{
			name:    "plain gzip writes no sidecar",
			file:    "blob.gz",
			data:    gzipWithHeader(t, "hello", nil, ""),
			extract: ExtractGzip,
			want:    map[string]string{"blob": "hello"},
		},
		{
			name:    "zstd skippable frame",
			file:    "blob.zst",
			data:    slices.Concat(skippable, frame),
			extract: ExtractZstd,
			want:    map[string]string{"out": "/", "out/blob": "hello", "out/malcontent-metadata.bin": "zstd skippable frame: " + benignMarker + "\n"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			src := filepath.Join(t.TempDir(), "out", tt.file)
			writeAt(t, src, tt.data)
			d := filepath.Join(t.TempDir(), "x")
			if err := tt.extract(t.Context(), d, src); err != nil {
				t.Fatalf("extract: %v", err)
			}
			wantTree(t, d, tt.want)
		})
	}
}

// writeAt writes data to path, creating its directory.
func writeAt(t *testing.T, path string, data []byte) {
	t.Helper()
	root := openTestRoot(t, filepath.Dir(filepath.Dir(path)))
	if err := root.MkdirAll(filepath.Base(filepath.Dir(path)), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := root.WriteFile(filepath.Join(filepath.Base(filepath.Dir(path)), filepath.Base(path)), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestExtractZlibReportsDataAfterTheStream(t *testing.T) {
	t.Parallel()
	var zb bytes.Buffer
	zw := zlib.NewWriter(&zb)
	_, _ = io.WriteString(zw, "hello")
	_ = zw.Close()
	tests := []struct {
		name    string
		data    []byte
		wantErr error
	}{
		{name: "stream alone", data: zb.Bytes()},
		{name: "bytes after the stream", data: slices.Concat(zb.Bytes(), []byte(benignMarker)), wantErr: ErrUnaccountedBytes},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			src := writeTemp(t, "blob.zlib", tt.data)
			out := filepath.Join(t.TempDir(), "out")
			err := ExtractZlib(t.Context(), out, src)
			if tt.wantErr == nil && err != nil || tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Errorf("ExtractZlib error: got = %v, want = %v", err, tt.wantErr)
			}
			pkgsWantFile(t, filepath.Join(out, "blob"), "hello")
		})
	}
}

// xzWithDict returns a valid .xz stream of content whose LZMA2 filter
// declares the dictionary that code encodes, from 0 (4 KiB) to 40 (4 GiB - 1).
func xzWithDict(t *testing.T, content string, code byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := xz.NewWriter(&buf)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(w, content)
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	b := buf.Bytes()
	const hdr = 12 // stream header
	size := (int(b[hdr]) + 1) * 4
	if b[hdr+1]&0xc0 != 0 || b[hdr+2] != 0x21 || b[hdr+3] != 1 {
		t.Fatalf("unexpected block header % x", b[hdr:hdr+size])
	}
	b[hdr+4] = code
	binary.LittleEndian.PutUint32(b[hdr+size-4:], crc32.ChecksumIEEE(b[hdr:hdr+size-4]))
	return b
}

func TestDecoderWindowLimits(t *testing.T) {
	t.Parallel()
	zstdHuge := []byte{0x28, 0xb5, 0x2f, 0xfd, 0x00, 19 << 3, 0x29, 0x00, 0x00, 'h', 'e', 'l', 'l', 'o'}
	zstdSmall := []byte{0x28, 0xb5, 0x2f, 0xfd, 0x00, 0, 0x29, 0x00, 0x00, 'h', 'e', 'l', 'l', 'o'}
	tests := []struct {
		name    string
		file    string
		data    []byte
		extract func(context.Context, string, string) error
		wantErr bool
	}{
		{name: "xz declaring a 4 GiB dictionary", file: "blob.xz", data: xzWithDict(t, "hello", 40), extract: ExtractTar, wantErr: true},
		{name: "xz declaring a 256 MiB dictionary", file: "blob.xz", data: xzWithDict(t, "hello", 32), extract: ExtractTar, wantErr: true},
		{name: "xz declaring the 64 MiB dictionary of xz -9", file: "blob.xz", data: xzWithDict(t, "hello", 28), extract: ExtractTar},
		{name: "concatenated xz streams, the second oversized", file: "blob.xz", data: slices.Concat(xzWithDict(t, "hel", 20), xzWithDict(t, "lo", 40)), extract: ExtractTar, wantErr: true},
		{name: "zstd declaring a 512 MiB window", file: "blob.zst", data: zstdHuge, extract: ExtractZstd, wantErr: true},
		{name: "zstd declaring a 1 KiB window", file: "blob.zst", data: zstdSmall, extract: ExtractZstd},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			src := writeTemp(t, tt.file, tt.data)
			out := filepath.Join(t.TempDir(), "out")
			err := tt.extract(t.Context(), out, src)
			if (err != nil) != tt.wantErr {
				t.Errorf("extract error: got = %v, want error = %v", err, tt.wantErr)
			}
		})
	}
}
