// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package programkind

import (
	"bytes"
	"compress/gzip"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// gzipStream compresses payload into a gzip stream.
func gzipStream(t *testing.T, payload []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := gzip.NewWriter(&b)
	if _, err := zw.Write(payload); err != nil {
		t.Fatalf("write gzip stream: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close gzip stream: %v", err)
	}
	return b.Bytes()
}

func TestFileDetectsGzipContent(t *testing.T) {
	t.Parallel()
	gzipType := &FileType{Ext: "gz", MIME: "application/gzip"}
	stream := gzipStream(t, []byte("malcontent gzip detection payload\n"))
	// A gzip stream whose method byte is 7 instead of 8 (deflate).
	badMethod := bytes.Clone(stream)
	badMethod[2] = 0x07

	tests := []struct {
		name    string
		rel     string
		content []byte
		want    *FileType
	}{
		{"gzip content without an extension", "payload", stream, gzipType},
		{"gzip content under an unrelated extension", "payload.bin", stream, gzipType},
		{"gzip content under a tar.gz name", "payload.tar.gz", stream, gzipType},
		{"gzip magic with an invalid method byte", "payload", badMethod, nil},
		{"gzip magic alone", "payload", []byte{0x1f, 0x8b}, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			path := writeFixture(t, tt.rel, tt.content)
			got, err := File(t.Context(), path)
			if err != nil {
				t.Fatalf("File(%q) error: %v", path, err)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("File(%q) mismatch (-want +got):\n%s", path, diff)
			}
		})
	}
}
