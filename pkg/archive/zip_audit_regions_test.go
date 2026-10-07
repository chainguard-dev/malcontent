// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"bytes"
	"encoding/binary"
	"io"
	"path/filepath"
	"slices"
	"testing"

	"github.com/chainguard-dev/malcontent/pkg/file"
	zip "github.com/klauspost/compress/zip"
)

// zipAuditEndRecord returns an end-of-central-directory record that declares
// the given central directory size and offset and archive comment length.
func zipAuditEndRecord(cdSize, cdOffset uint32, commentLen uint16) []byte {
	rec := make([]byte, zipEOCDLen)
	copy(rec, zipEOCDSignature)
	binary.LittleEndian.PutUint32(rec[12:], cdSize)
	binary.LittleEndian.PutUint32(rec[16:], cdOffset)
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

func TestZipUnaccountedBytesRegions(t *testing.T) {
	t.Parallel()

	valid := zipAuditArchive(t, "")
	eocdAt := len(valid) - zipEOCDLen
	locator := slices.Concat(zip64LocatorSignature, make([]byte, 16))
	const gap = "central directory does not end where its end record begins"

	tests := []struct {
		name    string
		data    []byte
		wantErr string
	}{
		{name: "well-formed archive is fully accounted for", data: valid},
		{name: "archive comment is part of the end record", data: zipAuditArchive(t, "release notes")},
		{name: "bytes appended after the end record are counted", data: slices.Concat(valid, []byte("1234567")), wantErr: "7 bytes follow the end-of-central-directory record"},
		{name: "bytes between the central directory and the end record are reported", data: slices.Concat(valid[:eocdAt], make([]byte, 9), valid[eocdAt:]), wantErr: gap},
		{name: "file shorter than an end record is not audited", data: make([]byte, zipEOCDLen-1)},
		{name: "file without an end record signature is not audited", data: make([]byte, 64)},
		{name: "lone end record describing an empty archive", data: zipAuditEndRecord(0, 0, 0)},
		{name: "lone end record whose central directory lies past it", data: zipAuditEndRecord(0, 5, 0), wantErr: gap},
		{name: "unparsed bytes before a lone end record are reported", data: slices.Concat(make([]byte, 30), zipAuditEndRecord(0, 0, 0)), wantErr: gap},
		{name: "zip64 sentinel central directory size defers to zip64 records", data: slices.Concat(make([]byte, 10), zipAuditEndRecord(zip64Sentinel, 0, 0))},
		{name: "zip64 sentinel central directory offset defers to zip64 records", data: zipAuditEndRecord(0, zip64Sentinel, 0)},
		{name: "zip64 locator directly before an end record at offset 20", data: slices.Concat(locator, zipAuditEndRecord(0, 0, 0))},
		{name: "zip64 locator directly before an end record after other data", data: slices.Concat(make([]byte, 8), locator, zipAuditEndRecord(0, 0, 0))},
		{name: "zip64 locator not adjacent to the end record is ignored", data: slices.Concat(locator, make([]byte, 4), zipAuditEndRecord(0, 0, 0)), wantErr: gap},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			path := filepath.Join(dir, "audit.zip")
			if err := file.WriteFileIn(dir, "audit.zip", tt.data, 0o600); err != nil {
				t.Fatalf("write fixture: %v", err)
			}
			got := ""
			if err := zipUnaccountedBytes(path, int64(len(tt.data))); err != nil {
				got = err.Error()
			}
			if got != tt.wantErr {
				t.Errorf("zipUnaccountedBytes error: got = %q, want = %q", got, tt.wantErr)
			}
		})
	}
}

func TestFindZipEOCDSelection(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		tail []byte
		want int
	}{
		{name: "record at the start of the tail", tail: zipAuditEndRecord(0, 0, 0), want: 0},
		{name: "record after leading bytes", tail: slices.Concat(make([]byte, 10), zipAuditEndRecord(0, 0, 0)), want: 10},
		{name: "comment that exactly fills the tail", tail: slices.Concat(zipAuditEndRecord(0, 0, 5), []byte("notes")), want: 0},
		{name: "declared comment longer than the tail", tail: slices.Concat(zipAuditEndRecord(0, 0, 10), []byte("abc")), want: -1},
		{
			name: "later signature whose comment overruns falls back to an earlier record",
			tail: slices.Concat(zipAuditEndRecord(0, 0, 26), make([]byte, 2), zipAuditEndRecord(0, 0, 100), make([]byte, 2)),
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
