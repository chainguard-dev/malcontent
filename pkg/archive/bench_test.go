// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/chainguard-dev/malcontent/pkg/file"
	"github.com/chainguard-dev/malcontent/pkg/malcontent"
)

// copyFixtureToTempDir copies a fixture file under b.TempDir for isolated reads.
func copyFixtureToTempDir(b *testing.B, src string) string {
	b.Helper()
	in, err := os.Open(src)
	if err != nil {
		b.Fatalf("open fixture: %v", err)
	}
	defer in.Close()
	dst := filepath.Join(b.TempDir(), filepath.Base(src))
	out, err := os.Create(dst)
	if err != nil {
		b.Fatalf("create copy: %v", err)
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		b.Fatalf("copy fixture: %v", err)
	}
	if err := out.Close(); err != nil {
		b.Fatalf("close copy: %v", err)
	}
	return dst
}

// BenchmarkExtractArchiveToTempDir measures end-to-end xz tarball extraction.
func BenchmarkExtractArchiveToTempDir(b *testing.B) {
	src := filepath.Join("..", "action", "testdata", "static.tar.xz")
	if _, err := os.Stat(src); err != nil {
		b.Skipf("fixture %s missing: %v", src, err)
	}
	path := copyFixtureToTempDir(b, src)
	ctx := context.Background()
	cfg := malcontent.Config{Concurrency: 1, MaxDepth: 2}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		dir, err := ExtractArchiveToTempDir(ctx, cfg, path)
		if err != nil {
			b.Fatalf("extract: %v", err)
		}
		_ = os.RemoveAll(dir)
	}
}

// BenchmarkIsValidPath exercises pure path-math fast paths.
func BenchmarkIsValidPath(b *testing.B) {
	dir := "/tmp/extraction-root"
	target := "/tmp/extraction-root/sub/dir/file.txt"
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_ = IsValidPath(target, dir)
	}
}

// BenchmarkHandleFile measures tar-entry extraction with byte accounting.
func BenchmarkHandleFile(b *testing.B) {
	body := bytes.Repeat([]byte("malcontent-bench-payload\n"), 1024)
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	hdr := &tar.Header{Name: "payload", Mode: 0o600, Size: int64(len(body)), Typeflag: tar.TypeReg}
	if err := tw.WriteHeader(hdr); err != nil {
		b.Fatalf("WriteHeader: %v", err)
	}
	if _, err := tw.Write(body); err != nil {
		b.Fatalf("Write: %v", err)
	}
	if err := tw.Close(); err != nil {
		b.Fatalf("Close: %v", err)
	}
	raw := buf.Bytes()
	dir := b.TempDir()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tr := tar.NewReader(bytes.NewReader(raw))
		if _, err := tr.Next(); err != nil {
			b.Fatalf("Next: %v", err)
		}
		target := filepath.Join(dir, "payload")
		counter := &file.ArchiveCounter{MaxBytes: file.DefaultMaxArchiveBytes}
		if err := handleFile(target, tr, counter); err != nil {
			b.Fatalf("handleFile: %v", err)
		}
		_ = os.Remove(target)
	}
}

// BenchmarkExtractionMethod measures the extension dispatch table.
func BenchmarkExtractionMethod(b *testing.B) {
	exts := []string{".tar.gz", ".zip", ".rpm", ".deb", ".zst", ".gz", ".bz2", ".xz", ".unknown"}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ExtractionMethod(exts[i%len(exts)])
	}
}
