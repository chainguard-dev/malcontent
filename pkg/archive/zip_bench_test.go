// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"archive/zip"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// BenchmarkExtractZipManyEntries extracts a zip shaped like a Go module zip:
// 2,000 small files spread over 200 directories four levels deep, so that the
// cost of reaching each entry's directory shows.
func BenchmarkExtractZipManyEntries(b *testing.B) {
	dir := b.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		b.Fatalf("OpenRoot: %v", err)
	}
	defer root.Close()
	f, err := root.Create("many.zip")
	if err != nil {
		b.Fatalf("create zip: %v", err)
	}
	zw := zip.NewWriter(f)
	body := bytes.Repeat([]byte("package x\n"), 20)
	for i := range 2000 {
		w, err := zw.Create(fmt.Sprintf("example.com/mod@v1.0.0/pkg%d/sub/file%d.go", i%200, i))
		if err != nil {
			b.Fatalf("create entry: %v", err)
		}
		if _, err := w.Write(body); err != nil {
			b.Fatalf("write entry: %v", err)
		}
	}
	if err := zw.Close(); err != nil {
		b.Fatalf("close zip writer: %v", err)
	}
	if err := f.Close(); err != nil {
		b.Fatalf("close zip: %v", err)
	}
	zipPath := filepath.Join(dir, "many.zip")

	b.ReportAllocs()
	for b.Loop() {
		out, err := os.MkdirTemp(dir, "out")
		if err != nil {
			b.Fatalf("MkdirTemp: %v", err)
		}
		if err := ExtractZip(b.Context(), out, zipPath); err != nil {
			b.Fatalf("ExtractZip: %v", err)
		}
		if err := root.RemoveAll(filepath.Base(out)); err != nil {
			b.Fatalf("remove: %v", err)
		}
	}
}
