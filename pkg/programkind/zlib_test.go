// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package programkind

import (
	"bytes"
	"compress/zlib"
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// zlibPayload is compressible input for building zlib streams in tests.
var zlibPayload = bytes.Repeat([]byte("malcontent zlib detection payload\n"), 256)

// zlibText is plain text that happens to begin with the default-level zlib
// header bytes 'x' and 0x9c.
const zlibText = "x\x9chello this is plain text that happens to start like zlib\n"

// zlibStream compresses payload at level and returns the zlib stream.
func zlibStream(t *testing.T, payload []byte, level int) []byte {
	t.Helper()
	var b bytes.Buffer
	zw, err := zlib.NewWriterLevel(&b, level)
	if err != nil {
		t.Fatalf("zlib.NewWriterLevel(%d): %v", level, err)
	}
	if _, err := zw.Write(payload); err != nil {
		t.Fatalf("write zlib stream: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close zlib stream: %v", err)
	}
	return b.Bytes()
}

// zlibNoise returns n bytes that start with the default-level zlib header
// 0x78 0x9c followed by SHA-256 output, which is fixed across runs but is not
// a deflate stream.
func zlibNoise(n int) []byte {
	out := []byte{0x78, 0x9c}
	for i := 0; len(out) < n; i++ {
		sum := sha256.Sum256(fmt.Appendf(nil, "zlib-noise-%d", i))
		out = append(out, sum[:]...)
	}
	return out[:n]
}

func TestFileDetectsZlibStreams(t *testing.T) {
	t.Parallel()
	zlibType := &FileType{Ext: "Z", MIME: "application/zlib"}

	tests := []struct {
		name    string
		content []byte
		want    *FileType
	}{
		{"level 1 stream", zlibStream(t, zlibPayload, 1), zlibType},
		{"level 5 stream", zlibStream(t, zlibPayload, 5), zlibType},
		{"level 6 stream", zlibStream(t, zlibPayload, 6), zlibType},
		{"level 9 stream", zlibStream(t, zlibPayload, 9), zlibType},
		{"random bytes after a default-level header", zlibNoise(1024), nil},
		{"text starting with x and 0x9c", []byte(zlibText), nil},
		{"empty file", nil, nil},
		{"one-byte file", []byte("x"), nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			path := writeFixture(t, "stream", tt.content)
			got, err := File(t.Context(), path)
			if err != nil {
				t.Fatalf("File(%q) error: %v", path, err)
			}
			if tt.want != nil {
				if diff := cmp.Diff(tt.want, got); diff != "" {
					t.Errorf("File(%q) mismatch (-want +got):\n%s", path, diff)
				}
				return
			}
			if got != nil && got.MIME == zlibType.MIME {
				t.Errorf("File(%q): got = %+v, want a result other than zlib", path, got)
			}
		})
	}
}

func TestIsZlibStream(t *testing.T) {
	t.Parallel()
	short := zlibStream(t, []byte("hi"), 6)
	badChecksum := bytes.Clone(short)
	badChecksum[len(badChecksum)-1] ^= 0xff
	full := zlibStream(t, zlibPayload[:300], 6)
	// The header bits of a preset-dictionary stream whose dictionary ID is the
	// checksum of an empty dictionary, followed by a valid deflate body.
	presetDict := append([]byte{0x78, 0xbb, 0x00, 0x00, 0x00, 0x01}, short[2:]...)

	tests := []struct {
		name string
		in   []byte
		want bool
	}{
		{"level 1 stream", zlibStream(t, zlibPayload, 1), true},
		{"level 5 stream", zlibStream(t, zlibPayload, 5), true},
		{"level 6 stream", zlibStream(t, zlibPayload, 6), true},
		{"level 9 stream", zlibStream(t, zlibPayload, 9), true},
		{"stream of empty input", zlibStream(t, nil, 6), true},
		{"complete stream shorter than the probe", short, true},
		{"stream cut before its checksum", full[:len(full)-4], true},
		{"stream with a corrupted checksum", badChecksum, false},
		{"header without deflate data", []byte{0x78, 0x9c}, false},
		{"reserved deflate block type", []byte{0x78, 0x9c, 0xff, 0xff, 0xff, 0xff}, false},
		{"random bytes after a default-level header", zlibNoise(1024), false},
		{"text starting with x and 0x9c", []byte(zlibText), false},
		{"preset dictionary flag", presetDict, false},
		{"window larger than 32 KiB", []byte{0x88, 0x1c, 0x00, 0x00}, false},
		{"compression method other than deflate", []byte{0x79, 0x18, 0x00, 0x00}, false},
		{"header check bits that do not divide by 31", []byte{0x78, 0x9d, 0x00, 0x00}, false},
		{"single byte", []byte{0x78}, false},
		{"empty", nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := isZlibStream(tt.in); got != tt.want {
				t.Errorf("isZlibStream(% x): got = %v, want = %v", tt.in[:min(len(tt.in), 8)], got, tt.want)
			}
		})
	}
}
