// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/chainguard-dev/malcontent/pkg/file"
)

// makeTarStream returns a single-entry tar archive carrying body at name.
func makeTarStream(t *testing.T, name string, body []byte) *tar.Reader {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	hdr := &tar.Header{Name: name, Mode: 0o600, Size: int64(len(body)), Typeflag: tar.TypeReg}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatalf("WriteHeader: %v", err)
	}
	if _, err := tw.Write(body); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	tr := tar.NewReader(&buf)
	if _, err := tr.Next(); err != nil {
		t.Fatalf("Next: %v", err)
	}
	return tr
}

// TestHandleFile_NilCounter exercises the nil-counter branch and confirms the
// file is extracted to disk.
func TestHandleFile_NilCounter(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	body := []byte("hello-nil")
	tr := makeTarStream(t, "a.txt", body)
	target := filepath.Join(dir, "a.txt")

	if err := handleFile(target, tr, nil); err != nil {
		t.Fatalf("handleFile(nil counter): %v", err)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("body mismatch: got %q want %q", got, body)
	}
}

// TestHandleFile_WithCounter exercises the non-nil-counter branch and confirms
// the counter accumulates the written byte count.
func TestHandleFile_WithCounter(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	body := []byte("hello-counter")
	tr := makeTarStream(t, "b.txt", body)
	target := filepath.Join(dir, "b.txt")

	counter := &file.ArchiveCounter{}
	if err := handleFile(target, tr, counter); err != nil {
		t.Fatalf("handleFile(counter): %v", err)
	}
	if got := counter.Total.Load(); got != int64(len(body)) {
		t.Fatalf("counter.Total: got %d want %d", got, len(body))
	}
}

// TestHandleFile_ArchiveBudgetBoundsPerMemberWrite verifies that when the
// archive-level byte cap (MaxBytes on the counter) is smaller than the per-file
// ceiling (file.MaxBytes), a single oversize member is rejected WITHOUT writing
// the full member to disk. This exercises the LimitReader bound added to
// handleFile.
func TestHandleFile_ArchiveBudgetBoundsPerMemberWrite(t *testing.T) {
	t.Parallel()

	const archiveCap = 512
	const memberSize = 2048

	dir := t.TempDir()
	body := make([]byte, memberSize)
	for i := range body {
		body[i] = byte(i % 256)
	}
	tr := makeTarStream(t, "oversize.bin", body)
	target := filepath.Join(dir, "oversize.bin")

	counter := &file.ArchiveCounter{MaxBytes: archiveCap, InputBytes: 1 << 20}
	err := handleFile(target, tr, counter)
	if err == nil {
		t.Fatalf("handleFile succeeded; want error for member exceeding archive cap")
	}

	// The written file on disk must not contain the full member body.
	data, readErr := os.ReadFile(target)
	if readErr != nil {
		// File may not exist if we aborted before any write; that is acceptable.
		return
	}
	if int64(len(data)) > archiveCap+1 {
		t.Fatalf("wrote %d bytes to disk, want at most %d (archive cap not enforced per-member)", len(data), archiveCap+1)
	}
}
