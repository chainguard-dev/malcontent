// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"archive/tar"
	"bytes"
	"errors"
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

// TestHandleFile_ArchiveBudgetBoundsPerMemberWrite verifies that when a single
// member exceeds the archive-level byte cap (MaxBytes on the counter), the
// member is rejected WITHOUT writing the full member to disk. The per-level
// budget is the sole extraction bound; there is no separate per-member cap.
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

// TestHandleFile_MemberWithinBudgetExtractsFully is a regression test for the
// "no truncation" requirement: a member larger than the OLD per-member 4 GiB
// style limit but within the counter budget must extract FULLY without error.
func TestHandleFile_MemberWithinBudgetExtractsFully(t *testing.T) {
	t.Parallel()

	// Use a budget comfortably above the member size (8 KiB budget, 5 KiB member).
	const budget = 8192
	const memberSize = 5120

	dir := t.TempDir()
	body := make([]byte, memberSize)
	for i := range body {
		body[i] = byte(i % 251) // non-trivial pattern to detect truncation
	}
	tr := makeTarStream(t, "within_budget.bin", body)
	target := filepath.Join(dir, "within_budget.bin")

	counter := &file.ArchiveCounter{MaxBytes: budget, InputBytes: 1 << 20}
	if err := handleFile(target, tr, counter); err != nil {
		t.Fatalf("handleFile returned error for member within budget: %v", err)
	}

	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if len(got) != memberSize {
		t.Fatalf("extracted size = %d, want %d (member was truncated)", len(got), memberSize)
	}
	if !bytes.Equal(got, body) {
		t.Fatal("extracted content does not match original member body")
	}
	if total := counter.Total.Load(); total != int64(memberSize) {
		t.Fatalf("counter.Total = %d, want %d", total, memberSize)
	}
}

// TestHandleFile_MemberExceedsBudgetErrors is the negative counterpart: a
// member that exceeds the counter budget produces the ErrArchiveBytesCap
// sentinel.
func TestHandleFile_MemberExceedsBudgetErrors(t *testing.T) {
	t.Parallel()

	const budget = 1024
	const memberSize = 4096

	dir := t.TempDir()
	body := make([]byte, memberSize)
	tr := makeTarStream(t, "over_budget.bin", body)
	target := filepath.Join(dir, "over_budget.bin")

	counter := &file.ArchiveCounter{MaxBytes: budget, InputBytes: 1 << 20}
	err := handleFile(target, tr, counter)
	if err == nil {
		t.Fatal("handleFile succeeded; want error for member exceeding counter budget")
	}
	if !errors.Is(err, file.ErrArchiveBytesCap) {
		t.Fatalf("err = %v; want chain containing ErrArchiveBytesCap", err)
	}
}
