// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	zip "github.com/klauspost/compress/zip"
)

// writeSingleEntryZip writes a minimal valid zip with one regular-file entry
// and returns its path.
func writeSingleEntryZip(t *testing.T, dir string) string {
	t.Helper()
	zipPath := filepath.Join(dir, "worker.zip")
	zf, err := os.OpenFile(zipPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatalf("create zip: %v", err)
	}
	zw := zip.NewWriter(zf)
	w, err := zw.Create("payload.bin")
	if err != nil {
		_ = zf.Close()
		t.Fatalf("create entry: %v", err)
	}
	if _, err := w.Write([]byte("data")); err != nil {
		_ = zf.Close()
		t.Fatalf("write payload: %v", err)
	}
	if err := zw.Close(); err != nil {
		_ = zf.Close()
		t.Fatalf("close zip writer: %v", err)
	}
	if err := zf.Close(); err != nil {
		t.Fatalf("close zip file: %v", err)
	}
	return zipPath
}

// TestExtractZip_WorkerPanicRecovered forces a panic inside a worker goroutine
// (the errgroup-spawned closure where the parent recoverExtractor cannot see
// it) and asserts the process survives and the panic is surfaced as an
// ErrExtractorPanic-wrapped error. Without the per-worker recover the panic
// escapes errgroup and crashes the test binary.
func TestExtractZip_WorkerPanicRecovered(t *testing.T) {
	prev := workerPanicHook
	workerPanicHook = func(string) { panic("synthetic worker panic") }
	t.Cleanup(func() { workerPanicHook = prev })

	tmp := t.TempDir()
	zipPath := writeSingleEntryZip(t, tmp)
	dst := filepath.Join(tmp, "out")

	err := ExtractZip(context.Background(), dst, zipPath)
	if err == nil {
		t.Fatal("ExtractZip succeeded; want recovered worker panic error")
	}
	if !errors.Is(err, ErrExtractorPanic) {
		t.Fatalf("ExtractZip err = %v; want chain containing ErrExtractorPanic", err)
	}
}
