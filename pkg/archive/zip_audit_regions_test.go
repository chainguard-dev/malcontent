// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"bytes"
	"encoding/binary"
	"io"
	"slices"
	"testing"

	zip "github.com/klauspost/compress/zip"
)

// zipAuditEndRecord returns an end-of-central-directory record for an empty
// archive that declares an archive comment of commentLen bytes.
func zipAuditEndRecord(commentLen uint16) []byte {
	rec := make([]byte, zipEOCDLen)
	copy(rec, zipEOCDSignature)
	binary.LittleEndian.PutUint16(rec[20:], commentLen)
	return rec
}

// zipAuditArchive returns a well-formed single-entry zip archive, optionally
// carrying an archive comment.
func zipAuditArchive(t *testing.T, comment string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("entry.txt")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := io.WriteString(w, "entry contents"); err != nil {
		t.Fatalf("write entry: %v", err)
	}
	if comment != "" {
		if err := zw.SetComment(comment); err != nil {
			t.Fatalf("SetComment: %v", err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return buf.Bytes()
}

func TestFindZipEOCDSelection(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		tail []byte
		want int
	}{
		{name: "record at the start of the tail", tail: zipAuditEndRecord(0), want: 0},
		{name: "record after leading bytes", tail: slices.Concat(make([]byte, 10), zipAuditEndRecord(0)), want: 10},
		{name: "comment that exactly fills the tail", tail: slices.Concat(zipAuditEndRecord(5), []byte("notes")), want: 0},
		{name: "declared comment longer than the tail", tail: slices.Concat(zipAuditEndRecord(10), []byte("abc")), want: -1},
		{
			name: "later signature whose comment overruns falls back to an earlier record",
			tail: slices.Concat(zipAuditEndRecord(26), make([]byte, 2), zipAuditEndRecord(100), make([]byte, 2)),
			want: 0,
		},
		{name: "no signature", tail: make([]byte, 40), want: -1},
		{name: "signature without room for a full record", tail: zipEOCDSignature, want: -1},
		{name: "empty tail", tail: nil, want: -1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := findZipEOCD(tt.tail); got != tt.want {
				t.Errorf("findZipEOCD: got = %d, want = %d", got, tt.want)
			}
		})
	}
}
