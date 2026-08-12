// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
)

const testPayload = "MALICIOUS_BYPASS_PAYLOAD_9f2c7a1e"

// rawTarHeader builds a 512-byte ustar header block directly so that tests can
// express structures the archive/tar writer refuses to emit.
func rawTarHeader(name string, size int, typeflag byte) []byte {
	blk := make([]byte, tarBlockSize)
	copy(blk[0:100], name)
	copy(blk[100:108], "0000600\x00")
	copy(blk[108:116], "0000000\x00")
	copy(blk[116:124], "0000000\x00")
	copy(blk[124:136], fmt.Sprintf("%011o\x00", size))
	copy(blk[136:148], "00000000000\x00")
	blk[156] = typeflag
	copy(blk[257:263], "ustar\x00")
	copy(blk[263:265], "00")

	for i := 148; i < 156; i++ {
		blk[i] = ' '
	}
	sum := 0
	for _, b := range blk {
		sum += int(b)
	}
	copy(blk[148:156], fmt.Sprintf("%06o\x00 ", sum))
	return blk
}

// tarWithEntry returns a well-formed single-entry tar including its
// end-of-archive marker.
func tarWithEntry(t *testing.T, name, content string) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(content))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func validTar(t *testing.T) []byte {
	t.Helper()
	return tarWithEntry(t, "benign.txt", "benign")
}

func gzipBytes(t *testing.T, b []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	gw := gzip.NewWriter(&out)
	if _, err := gw.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func writeTemp(t *testing.T, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// corpusContains reports whether any extracted file holds the payload marker.
func corpusContains(t *testing.T, root, marker string) bool {
	t.Helper()
	found := false
	if err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil //nolint:nilerr // unreadable entries simply cannot hold the marker
		}
		data, readErr := os.ReadFile(p) // #nosec G304 -- test-controlled extraction dir
		if readErr == nil && bytes.Contains(data, []byte(marker)) {
			found = true
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return found
}

// TestExtractTarUnaccountedBytes covers archive bytes that the tar reader does
// not surface as entry content. Each must be reported so the caller retains the
// archive for scanning instead of deleting it as fully processed.
func TestExtractTarUnaccountedBytes(t *testing.T) {
	payload := []byte("#!/bin/sh\n# " + testPayload + "\n")
	valid := validTar(t)

	// stuffed hides the payload in the padding between an entry's declared end
	// and its next block boundary, which archive/tar skips without reporting.
	stuffedBody := make([]byte, tarBlockSize)
	stuffedBody[0] = 'x'
	copy(stuffedBody[1:], payload)
	stuffed := slices.Concat(rawTarHeader("small.txt", 1, tar.TypeReg), stuffedBody, make([]byte, 2*tarBlockSize))

	longName := tarWithEntry(t, strings.Repeat("a", 300)+".txt", "benign")

	tests := []struct {
		name       string
		filename   string
		data       []byte
		wantUnacct bool
	}{
		{
			name:       "trailing data after end-of-archive marker",
			filename:   "trailing.tar",
			data:       slices.Concat(valid, payload),
			wantUnacct: true,
		},
		{
			name:       "trailing zero padding to blocking factor is legitimate",
			filename:   "padded.tar",
			data:       slices.Concat(valid, make([]byte, 10240)),
			wantUnacct: false,
		},
		{
			name:       "payload stuffed into entry block padding",
			filename:   "stuffed.tar",
			data:       stuffed,
			wantUnacct: true,
		},
		{
			name:       "well-formed archive reports nothing",
			filename:   "clean.tar",
			data:       valid,
			wantUnacct: false,
		},
		{
			name:       "long entry names use extension headers cleanly",
			filename:   "longname.tar",
			data:       longName,
			wantUnacct: false,
		},
		{
			name:       "trailing data after gzip stream",
			filename:   "trailing.tar.gz",
			data:       slices.Concat(gzipBytes(t, valid), payload),
			wantUnacct: true,
		},
		{
			name:       "well-formed gzip archive reports nothing",
			filename:   "clean.tar.gz",
			data:       gzipBytes(t, valid),
			wantUnacct: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := writeTemp(t, tt.filename, tt.data)
			err := ExtractTar(context.Background(), t.TempDir(), src)
			if got := errors.Is(err, ErrUnaccountedBytes); got != tt.wantUnacct {
				t.Errorf("ErrUnaccountedBytes = %v (err %v), want %v", got, err, tt.wantUnacct)
			}
		})
	}
}

// TestExtractTarDataBearingTypeflag ensures entries whose typeflag is not
// tar.TypeReg but which still carry data reach the extraction directory.
func TestExtractTarDataBearingTypeflag(t *testing.T) {
	payload := []byte("#!/bin/sh\n# " + testPayload + "\n")

	tests := []struct {
		name     string
		typeflag byte
	}{
		{name: "contiguous file", typeflag: tar.TypeCont},
		{name: "unrecognized typeflag", typeflag: 'Z'},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := make([]byte, tarBlockSize)
			copy(body, payload)
			raw := append(rawTarHeader("evil.sh", len(payload), tt.typeflag), body...)
			raw = append(raw, make([]byte, 2*tarBlockSize)...)

			src := writeTemp(t, "typeflag.tar", raw)
			out := t.TempDir()
			if err := ExtractTar(context.Background(), out, src); err != nil {
				t.Fatalf("ExtractTar: %v", err)
			}
			if !corpusContains(t, out, testPayload) {
				t.Error("payload absent from extraction dir; entry content was discarded")
			}
		})
	}
}

// TestExtractTarRealArchives guards against auditor false positives on archives
// produced by real-world tooling.
func TestExtractTarRealArchives(t *testing.T) {
	for _, src := range []string{
		"../action/testdata/apko.tar.gz",
		"../action/testdata/apko_nested.tar.gz",
		"../action/testdata/static.tar.xz",
		"testdata/symlink_valid.tar",
	} {
		t.Run(filepath.Base(src), func(t *testing.T) {
			if _, err := os.Stat(src); err != nil {
				t.Skipf("fixture unavailable: %v", err)
			}
			if err := ExtractTar(context.Background(), t.TempDir(), src); err != nil {
				t.Errorf("ExtractTar(%s) = %v, want nil", src, err)
			}
		})
	}
}

// TestExtractZipUnaccountedBytes covers zip bytes outside the region described
// by the central directory.
func TestExtractZipUnaccountedBytes(t *testing.T) {
	payload := []byte("#!/bin/sh\n# " + testPayload + "\n")

	valid := zipWithEntry(t, "")
	commented := zipWithEntry(t, "a legitimate archive comment")

	tests := []struct {
		name       string
		data       []byte
		wantUnacct bool
	}{
		{
			name:       "data appended after end of central directory",
			data:       slices.Concat(valid, payload),
			wantUnacct: true,
		},
		{
			name:       "well-formed archive reports nothing",
			data:       valid,
			wantUnacct: false,
		},
		{
			name:       "archive comment is legitimate trailing content",
			data:       commented,
			wantUnacct: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := writeTemp(t, "archive.zip", tt.data)
			err := ExtractZip(context.Background(), t.TempDir(), src)
			if got := errors.Is(err, ErrUnaccountedBytes); got != tt.wantUnacct {
				t.Errorf("ErrUnaccountedBytes = %v (err %v), want %v", got, err, tt.wantUnacct)
			}
		})
	}
}

// zipWithEntry returns a well-formed single-entry zip, optionally carrying an
// archive comment.
func zipWithEntry(t *testing.T, comment string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("benign.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("benign")); err != nil {
		t.Fatal(err)
	}
	if comment != "" {
		if err := zw.SetComment(comment); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// TestNestedArchiveWithTrailingDataRetained is the end-to-end case from
// GHSA-fhhv-5r7x-fgjw: a nested tar carrying a payload after its end-of-archive
// marker must stay in the scan corpus rather than be deleted as fully extracted.
func TestNestedArchiveWithTrailingDataRetained(t *testing.T) {
	payload := []byte("#!/bin/sh\n# " + testPayload + "\necho hidden\n")
	evilTar := append(validTar(t), payload...)

	var outer bytes.Buffer
	gw := gzip.NewWriter(&outer)
	tw := tar.NewWriter(gw)
	if err := tw.WriteHeader(&tar.Header{Name: "evil.tar", Mode: 0o600, Size: int64(len(evilTar))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(evilTar); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}

	src := writeTemp(t, "outer.tar.gz", outer.Bytes())
	root, err := ExtractArchiveToTempDir(context.Background(), malcontent.Config{}, src)
	if err != nil {
		t.Fatalf("ExtractArchiveToTempDir: %v", err)
	}
	defer os.RemoveAll(root)

	if !corpusContains(t, root, testPayload) {
		t.Error("hidden payload escaped the scan corpus")
	}
}

// TestTopLevelArchiveRetainedOnFailure covers the top-level path: an archive
// that cannot be fully extracted must still reach the scan corpus, and must not
// fail the scan outright unless ExitExtraction is set.
func TestTopLevelArchiveRetainedOnFailure(t *testing.T) {
	payload := []byte("#!/bin/sh\n# " + testPayload + "\n")

	valid := validTar(t)
	truncated := gzipBytes(t, valid)
	truncated = slices.Concat(truncated[:len(truncated)/2], payload)

	tests := []struct {
		name     string
		filename string
		data     []byte
	}{
		{
			name:     "trailing data after end-of-archive marker",
			filename: "trailing.tar",
			data:     slices.Concat(valid, payload),
		},
		{
			name:     "truncated archive",
			filename: "truncated.tar.gz",
			data:     truncated,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := writeTemp(t, tt.filename, tt.data)

			root, err := ExtractArchiveToTempDir(context.Background(), malcontent.Config{}, src)
			if err != nil {
				t.Fatalf("ExtractArchiveToTempDir: %v", err)
			}
			defer os.RemoveAll(root)

			if !corpusContains(t, root, testPayload) {
				t.Error("payload escaped the scan corpus")
			}

			// ExitExtraction opts into hard failure instead of retention.
			strict, err := ExtractArchiveToTempDir(context.Background(), malcontent.Config{ExitExtraction: true}, src)
			if err == nil {
				os.RemoveAll(strict)
				t.Error("ExtractArchiveToTempDir with ExitExtraction = nil error, want failure")
			}
		})
	}
}
