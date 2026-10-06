// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cavaliergopher/cpio"
	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	zip "github.com/klauspost/compress/zip"
	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"
)

// The helpers in this file build archives in memory for the decoder
// benchmarks and for the tests that pin decoder output. They use only the
// exported extractors and test helpers that predate the decoder input
// buffering, so the benchmarks also run against earlier revisions.

// decCtx returns a context whose expansion ratio cap admits the highly
// compressible fixtures below.
func decCtx(tb testing.TB) context.Context {
	tb.Helper()
	return malcontent.ContextWithConfig(tb.Context(), &malcontent.Config{MaxArchiveRatio: 1e9})
}

// decTar returns a tar archive holding entries.
func decTar(tb testing.TB, entries []tarEntry) []byte {
	tb.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		hdr := &tar.Header{Name: e.name, Typeflag: e.typeflag, Linkname: e.linkname, Mode: 0o644}
		if e.typeflag == tar.TypeReg {
			hdr.Size = int64(len(e.body))
		}
		if err := tw.WriteHeader(hdr); err != nil {
			tb.Fatalf("write tar header %s: %v", e.name, err)
		}
		if _, err := tw.Write([]byte(e.body)); err != nil {
			tb.Fatalf("write tar body %s: %v", e.name, err)
		}
	}
	if err := tw.Close(); err != nil {
		tb.Fatalf("close tar: %v", err)
	}
	return buf.Bytes()
}

// decXZ compresses each part as its own xz stream, back to back.
func decXZ(tb testing.TB, parts ...[]byte) []byte {
	tb.Helper()
	var buf bytes.Buffer
	for _, p := range parts {
		w, err := xz.NewWriter(&buf)
		if err != nil {
			tb.Fatalf("xz writer: %v", err)
		}
		if _, err := w.Write(p); err != nil {
			tb.Fatalf("xz write: %v", err)
		}
		if err := w.Close(); err != nil {
			tb.Fatalf("xz close: %v", err)
		}
	}
	return buf.Bytes()
}

// decGzip compresses each part as its own gzip member, back to back.
func decGzip(tb testing.TB, parts ...[]byte) []byte {
	tb.Helper()
	var buf bytes.Buffer
	for _, p := range parts {
		w := gzip.NewWriter(&buf)
		if _, err := w.Write(p); err != nil {
			tb.Fatalf("gzip write: %v", err)
		}
		if err := w.Close(); err != nil {
			tb.Fatalf("gzip close: %v", err)
		}
	}
	return buf.Bytes()
}

// decZstd compresses each part as its own zstd frame, back to back.
func decZstd(tb testing.TB, parts ...[]byte) []byte {
	tb.Helper()
	enc, err := zstd.NewWriter(nil, zstd.WithEncoderConcurrency(1))
	if err != nil {
		tb.Fatalf("zstd writer: %v", err)
	}
	defer enc.Close()
	var out []byte
	for _, p := range parts {
		out = enc.EncodeAll(p, out)
	}
	return out
}

// decZlib compresses data as one zlib stream.
func decZlib(tb testing.TB, data []byte) []byte {
	tb.Helper()
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	if _, err := w.Write(data); err != nil {
		tb.Fatalf("zlib write: %v", err)
	}
	if err := w.Close(); err != nil {
		tb.Fatalf("zlib close: %v", err)
	}
	return buf.Bytes()
}

// decBz2 decodes a hex-encoded bzip2 stream and repeats it n times, which
// yields n streams back to back. The module has no bzip2 encoder.
func decBz2(tb testing.TB, stream string, n int) []byte {
	tb.Helper()
	b, err := hex.DecodeString(stream)
	if err != nil {
		tb.Fatalf("decode bzip2 fixture: %v", err)
	}
	return bytes.Repeat(b, n)
}

// decCPIO returns a newc cpio archive holding the directories and regular
// files among entries.
func decCPIO(tb testing.TB, entries []tarEntry) []byte {
	tb.Helper()
	var buf bytes.Buffer
	cw := cpio.NewWriter(&buf)
	for _, e := range entries {
		hdr := &cpio.Header{Name: e.name, Mode: cpio.TypeReg | 0o644, Size: int64(len(e.body))}
		switch e.typeflag {
		case tar.TypeReg:
		case tar.TypeDir:
			hdr.Mode, hdr.Size = cpio.TypeDir|0o755, 0
		default:
			continue
		}
		if err := cw.WriteHeader(hdr); err != nil {
			tb.Fatalf("write cpio header %s: %v", e.name, err)
		}
		if _, err := cw.Write([]byte(e.body)); err != nil {
			tb.Fatalf("write cpio body %s: %v", e.name, err)
		}
	}
	if err := cw.Close(); err != nil {
		tb.Fatalf("close cpio: %v", err)
	}
	return buf.Bytes()
}

// decDeb returns a .deb whose control and data members are tar archives
// compressed by compress and named with ext, such as ".xz". data is the data
// member's tar archive.
func decDeb(tb testing.TB, ext string, compress func(testing.TB, ...[]byte) []byte, data []byte) []byte {
	tb.Helper()
	control := decTar(tb, []tarEntry{{name: "./control", typeflag: tar.TypeReg, body: pkgsDebControl}})
	var b bytes.Buffer
	b.WriteString("!<arch>\n")
	for _, m := range []struct {
		name string
		body []byte
	}{
		{name: "debian-binary", body: []byte("2.0\n")},
		{name: "control.tar" + ext, body: compress(tb, control)},
		{name: "data.tar" + ext, body: compress(tb, data)},
	} {
		// ar member header: name, mtime, uid, gid, mode, size, terminator.
		fmt.Fprintf(&b, "%-16s%-12s%-6s%-6s%-8s%-10d`\n", m.name, "0", "0", "0", "100644", len(m.body))
		b.Write(m.body)
		if len(m.body)%2 == 1 {
			b.WriteByte('\n')
		}
	}
	return b.Bytes()
}

// decZipEntry is a member of an archive built by decZip.
type decZipEntry struct {
	name   string
	method uint16
	body   []byte
}

// decZipEntries returns the regular files among entries as zip members,
// storing every third one and deflating the rest.
func decZipEntries(entries []tarEntry) []decZipEntry {
	var out []decZipEntry
	for _, e := range entries {
		if e.typeflag != tar.TypeReg {
			continue
		}
		method := zip.Deflate
		if len(out)%3 == 2 {
			method = zip.Store
		}
		out = append(out, decZipEntry{name: e.name, method: method, body: []byte(e.body)})
	}
	return out
}

// decZip returns a zip archive holding entries in order.
func decZip(tb testing.TB, entries []decZipEntry) []byte {
	tb.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range entries {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: e.name, Method: e.method})
		if err != nil {
			tb.Fatalf("create zip entry %s: %v", e.name, err)
		}
		if _, err := w.Write(e.body); err != nil {
			tb.Fatalf("write zip entry %s: %v", e.name, err)
		}
	}
	if err := zw.Close(); err != nil {
		tb.Fatalf("close zip: %v", err)
	}
	return buf.Bytes()
}

// decWrite writes data to name in a new directory named "src", whose name the
// single-stream extractors carry into their output path, and returns the path.
func decWrite(tb testing.TB, name string, data []byte) string {
	tb.Helper()
	dir := filepath.Join(tb.TempDir(), "src")
	if err := os.Mkdir(dir, 0o700); err != nil {
		tb.Fatalf("mkdir %s: %v", dir, err)
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		tb.Fatalf("write %s: %v", p, err)
	}
	return p
}

// decBenchEntries returns the members of the benchmark archives, about 3.6 MiB
// in all: many small text files, as in a source tree, and three 1 MiB
// binaries, two of them incompressible.
func decBenchEntries() []tarEntry {
	entries := []tarEntry{{name: "pkg/", typeflag: tar.TypeDir}}
	for i := range 512 {
		body := strings.Repeat(fmt.Sprintf("line %d of source file %d\n", i%7, i), 48)
		entries = append(entries, tarEntry{name: fmt.Sprintf("pkg/src/f%03d.go", i), typeflag: tar.TypeReg, body: body})
	}
	noise := pkgsNoise(2 << 20)
	return append(entries,
		tarEntry{name: "pkg/bin/a", typeflag: tar.TypeReg, body: string(noise[:1<<20])},
		tarEntry{name: "pkg/bin/b", typeflag: tar.TypeReg, body: string(noise[1<<20:])},
		tarEntry{name: "pkg/bin/c", typeflag: tar.TypeReg, body: string(streamsPayload(1 << 20))},
	)
}

// benchExtract measures extract on the archive at src, extracting into the
// same emptied directory on every iteration.
func benchExtract(b *testing.B, extract func(context.Context, string, string) error, src string) {
	b.Helper()
	fi, err := os.Stat(src)
	if err != nil {
		b.Fatalf("stat %s: %v", src, err)
	}
	ctx := decCtx(b)
	out := filepath.Join(b.TempDir(), "out")
	b.SetBytes(fi.Size())
	b.ReportAllocs()
	for b.Loop() {
		if err := extract(ctx, out, src); err != nil {
			b.Fatalf("extract %s: %v", filepath.Base(src), err)
		}
		if err := os.RemoveAll(out); err != nil {
			b.Fatalf("remove %s: %v", out, err)
		}
	}
}

// BenchmarkExtractDecoders measures each decoder path on the same content.
// Single-stream formats decompress the benchmark tar archive as one file,
// except bzip2, which has no encoder here and decodes 8 MiB of zero bytes.
func BenchmarkExtractDecoders(b *testing.B) {
	entries := decBenchEntries()
	tarball := decTar(b, entries)

	cases := []struct {
		name    string
		extract func(context.Context, string, string) error
		file    string
		data    func(testing.TB) []byte
	}{
		{name: "tar", extract: ExtractTar, file: "pkg.tar", data: func(testing.TB) []byte { return tarball }},
		{name: "tar.gz", extract: ExtractTar, file: "pkg.tar.gz", data: func(tb testing.TB) []byte { tb.Helper(); return decGzip(tb, tarball) }},
		{name: "tar.xz", extract: ExtractTar, file: "pkg.tar.xz", data: func(tb testing.TB) []byte { tb.Helper(); return decXZ(tb, tarball) }},
		{name: "xz", extract: ExtractTar, file: "pkg.bin.xz", data: func(tb testing.TB) []byte { tb.Helper(); return decXZ(tb, tarball) }},
		{name: "tar.bz2", extract: ExtractTar, file: "pkg.tar.bz2", data: func(tb testing.TB) []byte { tb.Helper(); return decBz2(tb, streamsBz2ZerosMiB, 8) }},
		{name: "bz2", extract: ExtractBz2, file: "pkg.bin.bz2", data: func(tb testing.TB) []byte { tb.Helper(); return decBz2(tb, streamsBz2ZerosMiB, 8) }},
		{name: "zst", extract: ExtractZstd, file: "pkg.bin.zst", data: func(tb testing.TB) []byte { tb.Helper(); return decZstd(tb, tarball) }},
		{name: "gz", extract: ExtractGzip, file: "pkg.bin.gz", data: func(tb testing.TB) []byte { tb.Helper(); return decGzip(tb, tarball) }},
		{name: "zlib", extract: ExtractZlib, file: "pkg.bin.zlib", data: func(tb testing.TB) []byte { tb.Helper(); return decZlib(tb, tarball) }},
		{name: "rpm/gzip", extract: ExtractRPM, file: "pkg.rpm", data: func(tb testing.TB) []byte {
			tb.Helper()
			return pkgsRPM(pkgsCPIOFormat, pkgsGzip, decGzip(tb, decCPIO(tb, entries)))
		}},
		{name: "rpm/xz", extract: ExtractRPM, file: "pkg.rpm", data: func(tb testing.TB) []byte {
			tb.Helper()
			return pkgsRPM(pkgsCPIOFormat, pkgsXZ, decXZ(tb, decCPIO(tb, entries)))
		}},
		{name: "rpm/zstd", extract: ExtractRPM, file: "pkg.rpm", data: func(tb testing.TB) []byte {
			tb.Helper()
			return pkgsRPM(pkgsCPIOFormat, pkgsZstd, decZstd(tb, decCPIO(tb, entries)))
		}},
		{name: "deb/gz", extract: ExtractDeb, file: "pkg.deb", data: func(tb testing.TB) []byte { tb.Helper(); return decDeb(tb, ".gz", decGzip, tarball) }},
		{name: "deb/xz", extract: ExtractDeb, file: "pkg.deb", data: func(tb testing.TB) []byte { tb.Helper(); return decDeb(tb, ".xz", decXZ, tarball) }},
		{name: "deb/zst", extract: ExtractDeb, file: "pkg.deb", data: func(tb testing.TB) []byte { tb.Helper(); return decDeb(tb, ".zst", decZstd, tarball) }},
		{name: "zip", extract: ExtractZip, file: "pkg.zip", data: func(tb testing.TB) []byte { tb.Helper(); return decZip(tb, decZipEntries(entries)) }},
	}
	for _, c := range cases {
		b.Run(c.name, func(b *testing.B) {
			benchExtract(b, c.extract, decWrite(b, c.file, c.data(b)))
		})
	}
}

// BenchmarkExtractFixtures measures extraction of the sample packages that the
// action tests scan.
func BenchmarkExtractFixtures(b *testing.B) {
	cases := []struct {
		file    string
		extract func(context.Context, string, string) error
	}{
		{file: "static.tar.xz", extract: ExtractTar},
		{file: "apko.tar.gz", extract: ExtractTar},
		{file: "apko.gz", extract: ExtractGzip},
		{file: "yara.tar.zst", extract: ExtractZstd},
		{file: "yara.tar.zlib", extract: ExtractZlib},
		{file: "yara.rpm", extract: ExtractRPM},
		{file: "yara.deb", extract: ExtractDeb},
	}
	for _, c := range cases {
		b.Run(c.file, func(b *testing.B) {
			src := filepath.Join("..", "action", "testdata", c.file)
			if _, err := os.Stat(src); err != nil {
				b.Skipf("fixture %s missing: %v", src, err)
			}
			benchExtract(b, c.extract, copyFixtureToTempDir(b, src))
		})
	}
}
