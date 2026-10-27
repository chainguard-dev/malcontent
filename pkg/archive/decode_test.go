// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"archive/tar"
	"bytes"
	"compress/flate"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"maps"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/chainguard-dev/malcontent/pkg/file"
	kflate "github.com/klauspost/compress/flate"
	zip "github.com/klauspost/compress/zip"
	"github.com/klauspost/compress/zstd"
)

// decTestEntries returns tar members whose sizes fall on either side of the
// 512-byte tar block and the 64 KiB copy buffer, alternating incompressible
// and compressible content, followed by many small members.
func decTestEntries() []tarEntry {
	sizes := []int{0, 1, 511, 512, 513, 4095, 4096, 4097, 65535, 65536, 65537, 200000}
	total := 0
	for _, n := range sizes {
		total += n
	}
	noise := pkgsNoise(total)
	const small = 300
	entries := make([]tarEntry, 0, 1+len(sizes)+small)
	entries = append(entries, tarEntry{name: "pkg/", typeflag: tar.TypeDir})
	off := 0
	for i, n := range sizes {
		body := noise[off : off+n]
		off += n
		if i%2 == 1 {
			body = streamsPayload(n)
		}
		entries = append(entries, tarEntry{name: fmt.Sprintf("pkg/f%02d-%d.bin", i, n), typeflag: tar.TypeReg, body: string(body)})
	}
	for i := range small {
		body := fmt.Sprintf("member %d\n%s", i, strings.Repeat("x", i))
		entries = append(entries, tarEntry{name: fmt.Sprintf("pkg/many/m%03d.txt", i), typeflag: tar.TypeReg, body: body})
	}
	return entries
}

// decWant maps the regular files among entries, by the path extraction gives
// them, to their contents.
func decWant(entries []tarEntry) map[string][]byte {
	want := map[string][]byte{}
	for _, e := range entries {
		if e.typeflag == tar.TypeReg {
			want[filepath.ToSlash(filepath.Clean(e.name))] = []byte(e.body)
		}
	}
	return want
}

// decAssertTree fails unless the regular files under dir are exactly want.
func decAssertTree(t *testing.T, dir string, want map[string][]byte) {
	t.Helper()
	got := streamsTree(t, dir)
	for _, p := range slices.Sorted(maps.Keys(want)) {
		g, ok := got[p]
		switch {
		case !ok:
			t.Errorf("%s: got = missing, want = %d bytes", p, len(want[p]))
		case !bytes.Equal(g, want[p]):
			t.Errorf("%s: got = %d bytes (first difference at offset %d), want = %d bytes",
				p, len(g), streamsFirstDiff(g, want[p]), len(want[p]))
		}
	}
	for _, p := range slices.Sorted(maps.Keys(got)) {
		if _, ok := want[p]; !ok {
			t.Errorf("%s: got = %d bytes, want = absent", p, len(got[p]))
		}
	}
}

// TestDecodersExtractIdenticalContent pins the paths and bytes that every
// decoder path writes, including input split across several compressed
// streams at an offset off any block or buffer boundary.
func TestDecodersExtractIdenticalContent(t *testing.T) {
	t.Parallel()

	entries := decTestEntries()
	tarball := decTar(t, entries)
	cpioball := decCPIO(t, entries)
	tree := decWant(entries)
	// Debian packages also yield their control tarball, in control/.
	debTree := maps.Clone(tree)
	debTree["control/control"] = []byte(pkgsDebControl)
	const split = 70001

	first, second := pkgsNoise(100000), streamsPayload(150000)
	joined := slices.Concat(first, second)
	bz := slices.Concat(decBz2(t, streamsBz2Hello, 1), decBz2(t, streamsBz2Zeros32, 1))
	bzWant := slices.Concat([]byte("hello world\n"), make([]byte, 32))

	tests := []struct {
		name    string
		extract func(context.Context, string, string) error
		file    string
		data    []byte
		want    map[string][]byte
	}{
		{name: "plain tar", extract: ExtractTar, file: "pkg.tar", data: tarball, want: tree},
		{name: "gzip tar", extract: ExtractTar, file: "pkg.tar.gz", data: decGzip(t, tarball), want: tree},
		{name: "gzip tar split across members", extract: ExtractTar, file: "pkg.tgz", data: decGzip(t, tarball[:split], tarball[split:]), want: tree},
		{name: "apk package", extract: ExtractTar, file: "pkg.apk", data: decGzip(t, tarball), want: tree},
		{name: "xz tar", extract: ExtractTar, file: "pkg.tar.xz", data: decXZ(t, tarball), want: tree},
		{
			name:    "xz tar split across streams with padding between them",
			extract: ExtractTar,
			file:    "pkg.tar.xz",
			data:    slices.Concat(decXZ(t, tarball[:split]), make([]byte, 4), decXZ(t, tarball[split:])),
			want:    tree,
		},
		{name: "xz tar followed by stream padding", extract: ExtractTar, file: "pkg.tar.xz", data: slices.Concat(decXZ(t, tarball), make([]byte, 8)), want: tree},
		{name: "xz file split across streams", extract: ExtractTar, file: "notes.xz", data: decXZ(t, first, second), want: map[string][]byte{"src/notes": joined}},
		{name: "tbz file split across streams", extract: ExtractTar, file: "hello.tbz", data: bz, want: map[string][]byte{"src/hello.tar": bzWant}},
		{name: "bzip2 file split across streams", extract: ExtractBz2, file: "payload.bin.bz2", data: bz, want: map[string][]byte{"src/payload.bin": bzWant}},
		{name: "zstd file split across frames", extract: ExtractZstd, file: "payload.bin.zst", data: decZstd(t, first, second), want: map[string][]byte{"src/payload.bin": joined}},
		{name: "gzip file split across members", extract: ExtractGzip, file: "payload.bin.gz", data: decGzip(t, first, second), want: map[string][]byte{"payload.bin": joined}},
		{name: "zlib file", extract: ExtractZlib, file: "payload.bin.zlib", data: decZlib(t, joined), want: map[string][]byte{"payload.bin": joined}},
		{name: "rpm with a gzip payload", extract: ExtractRPM, file: "pkg.rpm", data: pkgsRPM(pkgsCPIOFormat, pkgsGzip, decGzip(t, cpioball)), want: tree},
		{
			name:    "rpm with an xz payload split across streams",
			extract: ExtractRPM,
			file:    "pkg.rpm",
			data:    pkgsRPM(pkgsCPIOFormat, pkgsXZ, decXZ(t, cpioball[:split], cpioball[split:])),
			want:    tree,
		},
		{
			name:    "rpm with a zstd payload split across frames",
			extract: ExtractRPM,
			file:    "pkg.rpm",
			data:    pkgsRPM(pkgsCPIOFormat, pkgsZstd, decZstd(t, cpioball[:split], cpioball[split:])),
			want:    tree,
		},
		{name: "deb with gzip members", extract: ExtractDeb, file: "pkg.deb", data: decDeb(t, ".gz", decGzip, tarball), want: debTree},
		{name: "deb with xz members", extract: ExtractDeb, file: "pkg.deb", data: decDeb(t, ".xz", decXZ, tarball), want: debTree},
		{name: "deb with zstd members", extract: ExtractDeb, file: "pkg.deb", data: decDeb(t, ".zst", decZstd, tarball), want: debTree},
		{name: "zip with deflated and stored entries", extract: ExtractZip, file: "pkg.zip", data: decZip(t, decZipEntries(entries)), want: tree},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			out := t.TempDir()
			if err := tt.extract(decCtx(t), out, decWrite(t, tt.file, tt.data)); err != nil {
				t.Fatalf("extract error: got = %v, want = nil", err)
			}
			decAssertTree(t, out, tt.want)
		})
	}
}

// TestDecodersRejectDataAfterStream pins how the buffered decoders treat bytes
// that follow a compressed stream: the tar audit and the zstd decoder report
// them, so the archive stays in the scan corpus.
func TestDecodersRejectDataAfterStream(t *testing.T) {
	t.Parallel()

	tarball := decTar(t, decTestEntries()[:6])
	payload := []byte("#!/bin/sh\n# " + testPayload + "\n")

	tests := []struct {
		name    string
		extract func(context.Context, string, string) error
		file    string
		data    []byte
		wantErr error
	}{
		{name: "xz tar followed by data", extract: ExtractTar, file: "pkg.tar.xz", data: slices.Concat(decXZ(t, tarball), payload), wantErr: ErrUnaccountedBytes},
		{name: "xz tar followed by partial stream padding", extract: ExtractTar, file: "pkg.tar.xz", data: slices.Concat(decXZ(t, tarball), make([]byte, 3)), wantErr: ErrUnaccountedBytes},
		{name: "zstd file followed by data", extract: ExtractZstd, file: "payload.bin.zst", data: slices.Concat(decZstd(t, payload), payload), wantErr: zstd.ErrMagicMismatch},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.extract(decCtx(t), t.TempDir(), decWrite(t, tt.file, tt.data))
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("extract error: got = %v, want = %v", err, tt.wantErr)
			}
		})
	}
}

// TestExtractZipReportsCorruptDeflateData checks that a deflated entry the
// decoder rejects fails extraction with the decoder's error.
func TestExtractZipReportsCorruptDeflateData(t *testing.T) {
	t.Parallel()

	data := decZip(t, []decZipEntry{{name: "a.bin", method: zip.Deflate, body: streamsPayload(100000)}})
	// The entry's data follows its 30-byte local header, name, and extra field.
	nameLen := int(binary.LittleEndian.Uint16(data[26:28]))
	extraLen := int(binary.LittleEndian.Uint16(data[28:30]))
	// A final block of the reserved type 3 is invalid deflate data.
	data[30+nameLen+extraLen] = 0xff

	err := ExtractZip(decCtx(t), t.TempDir(), decWrite(t, "pkg.zip", data))
	if _, ok := errors.AsType[kflate.CorruptInputError](err); !ok {
		t.Errorf("ExtractZip error: got = %v, want = %T", err, kflate.CorruptInputError(0))
	}
}

// decDeflate returns data as a raw deflate stream.
func decDeflate(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.DefaultCompression)
	if err != nil {
		t.Fatalf("flate writer: %v", err)
	}
	if _, err := w.Write(data); err != nil {
		t.Fatalf("flate write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("flate close: %v", err)
	}
	return buf.Bytes()
}

// TestZipInflaterDecodesEntriesInTurn decodes entries one after another, as a
// zip worker does, so later entries run on decoders that earlier entries
// returned to the pool and must not see their state.
func TestZipInflaterDecodesEntriesInTurn(t *testing.T) {
	t.Parallel()

	payloads := [][]byte{
		streamsPayload(300 << 10),
		pkgsNoise(70 << 10),
		{},
		[]byte("x"),
		streamsPayload(1000),
	}
	for i, p := range payloads {
		rc := newZipInflater(bytes.NewReader(decDeflate(t, p)))
		got, err := io.ReadAll(rc)
		if err != nil {
			t.Fatalf("entry %d: read error: got = %v, want = nil", i, err)
		}
		if !bytes.Equal(got, p) {
			t.Errorf("entry %d: got = %d bytes (first difference at offset %d), want = %d bytes", i, len(got), streamsFirstDiff(got, p), len(p))
		}
		if err := rc.Close(); err != nil {
			t.Errorf("entry %d: close error: got = %v, want = nil", i, err)
		}
	}
}

func TestZipEntryReaderClose(t *testing.T) {
	t.Parallel()

	stream := decDeflate(t, streamsPayload(100000))
	tests := []struct {
		name string
		// input is the compressed data the entry holds.
		input        []byte
		read         bool
		wantReadErr  error
		wantCloseErr error
	}{
		{name: "fully read entry closes cleanly", input: stream, read: true},
		{name: "unread entry closes cleanly", input: stream},
		{name: "truncated entry reports the truncation on close", input: stream[:len(stream)/2], read: true, wantReadErr: io.ErrUnexpectedEOF, wantCloseErr: io.ErrUnexpectedEOF},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rc := newZipInflater(bytes.NewReader(tt.input))
			if tt.read {
				if _, err := io.ReadAll(rc); !errors.Is(err, tt.wantReadErr) {
					t.Errorf("read error: got = %v, want = %v", err, tt.wantReadErr)
				}
			}
			if err := rc.Close(); !errors.Is(err, tt.wantCloseErr) {
				t.Errorf("close error: got = %v, want = %v", err, tt.wantCloseErr)
			}
			if n, err := rc.Read(make([]byte, 1)); n != 0 || !errors.Is(err, errZipEntryClosed) {
				t.Errorf("read after close: got = %d, %v, want = 0, %v", n, err, errZipEntryClosed)
			}
			if err := rc.Close(); err != nil {
				t.Errorf("second close error: got = %v, want = nil", err)
			}
		})
	}
}

// TestReadAheadReaderAtMatchesFile checks that every read returns the bytes,
// count, and error that reading the file directly returns.
func TestReadAheadReaderAtMatchesFile(t *testing.T) {
	t.Parallel()

	size := 3*inputBufferSize + 1234
	src := writeTemp(t, "data.bin", pkgsNoise(size))
	f, err := file.OpenIn(filepath.Dir(src), filepath.Base(src))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	w, end := int64(inputBufferSize), int64(size)

	type read struct {
		off int64
		n   int
	}
	tests := []struct {
		name  string
		reads []read
	}{
		{name: "single bytes across a window boundary", reads: []read{{w - 2, 1}, {w - 1, 1}, {w, 1}, {w + 1, 1}}},
		{name: "read spanning two windows", reads: []read{{w - 10, 20}}},
		{name: "read served by the window filled before it", reads: []read{{100, 10}, {110, 500}, {50, 50}}},
		{name: "read ending at the end", reads: []read{{end - 100, 100}}},
		{name: "read crossing the end", reads: []read{{end - 100, 200}}},
		{name: "read crossing the end of a window that holds the end", reads: []read{{end - 300, 10}, {end - 100, 200}}},
		{name: "read at the end", reads: []read{{end, 10}}},
		{name: "read past the end", reads: []read{{end + 10, 10}}},
		{name: "read larger than the window", reads: []read{{5, int(2 * w)}}},
		{name: "read larger than the window crossing the end", reads: []read{{end - w - 5, int(2 * w)}}},
		{name: "read starting in the window and continuing past it", reads: []read{{0, 10}, {5, int(w) + 100}}},
		{name: "read before the window refills it", reads: []read{{2 * w, 10}, {3, 10}}},
		{name: "read at a negative offset", reads: []read{{-1, 10}}},
		{name: "empty read at a negative offset", reads: []read{{-1, 0}}},
		{name: "empty read", reads: []read{{10, 0}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ra := newReadAheadReaderAt(f)
			for _, r := range tt.reads {
				got := make([]byte, r.n)
				gotN, gotErr := ra.ReadAt(got, r.off)
				want := make([]byte, r.n)
				wantN, wantErr := f.ReadAt(want, r.off)
				if gotN != wantN || fmt.Sprint(gotErr) != fmt.Sprint(wantErr) {
					t.Errorf("ReadAt(%d bytes, %d): got = %d, %v, want = %d, %v", r.n, r.off, gotN, gotErr, wantN, wantErr)
				}
				if !bytes.Equal(got, want) {
					t.Errorf("ReadAt(%d bytes, %d) bytes: got first difference at offset %d", r.n, r.off, streamsFirstDiff(got, want))
				}
			}
		})
	}
}

// decCountingReaderAt counts the reads that reach r.
type decCountingReaderAt struct {
	r     io.ReaderAt
	calls int
}

func (c *decCountingReaderAt) ReadAt(p []byte, off int64) (int, error) {
	c.calls++
	return c.r.ReadAt(p, off)
}

// TestReadAheadReaderAtBatchesSmallReads reads through an io.SectionReader one
// byte at a time, as go-debian's xz decoder does, and checks that the file is
// read once per window rather than once per byte.
func TestReadAheadReaderAtBatchesSmallReads(t *testing.T) {
	t.Parallel()

	const w = inputBufferSize
	tests := []struct {
		name      string
		size      int
		wantCalls int
	}{
		{name: "one byte", size: 1, wantCalls: 1},
		{name: "exactly one window", size: w, wantCalls: 1},
		{name: "one byte past a window", size: w + 1, wantCalls: 2},
		{name: "several windows", size: 3*w + 100, wantCalls: 4},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			data := pkgsNoise(tt.size)
			counter := &decCountingReaderAt{r: bytes.NewReader(data)}
			sr := io.NewSectionReader(newReadAheadReaderAt(counter), 0, int64(len(data)))
			got, err := io.ReadAll(iotest.OneByteReader(sr))
			if err != nil {
				t.Fatalf("read error: got = %v, want = nil", err)
			}
			if !bytes.Equal(got, data) {
				t.Errorf("bytes: got first difference at offset %d", streamsFirstDiff(got, data))
			}
			if counter.calls != tt.wantCalls {
				t.Errorf("reads reaching the file: got = %d, want = %d", counter.calls, tt.wantCalls)
			}
		})
	}
}

// TestExtractTarDecompressesAsContentShows checks that the content alone
// decides how a tar is decompressed, whatever its name says.
func TestExtractTarDecompressesAsContentShows(t *testing.T) {
	t.Parallel()

	noise := string(pkgsNoise(4096))
	plain := decTar(t, []tarEntry{
		{name: "noise.bin", typeflag: tar.TypeReg, body: noise},
		{name: "note.txt", typeflag: tar.TypeReg, body: "note"},
	})
	gz := decGzip(t, plain)

	tests := []struct {
		name string
		file string
		data []byte
	}{
		{name: "plain tar under a tar name", file: "pkg.tar", data: plain},
		{name: "gzip tar under an Alpine package name", file: "pkg.apk", data: gz},
		{name: "gzip tar under an Alpine package name ending in tar.gz", file: "pkg.apk.tar.gz", data: gz},
		{name: "xz tar under an xz tar name", file: "pkg.tar.xz", data: decXZ(t, plain)},
		{name: "gzip tar under a gzip tar name", file: "pkg.tar.gz", data: gz},
		{name: "gzip tar under a tgz name", file: "pkg.tgz", data: gz},
		{name: "plain tar under a gzip tar name", file: "plain.tar.gz", data: plain},
		{name: "gzip tar under a plain tar name", file: "gz.tar", data: gz},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			out := t.TempDir()
			if err := ExtractTar(t.Context(), out, decWrite(t, tt.file, tt.data)); err != nil {
				t.Fatalf("ExtractTar error: got = %v, want = nil", err)
			}
			pkgsWantFile(t, filepath.Join(out, "noise.bin"), noise)
			pkgsWantFile(t, filepath.Join(out, "note.txt"), "note")
		})
	}
}

// TestExtractorsDecideByContent checks that the gzip and zip extractors
// accept or reject a file by its content, whatever it is named.
func TestExtractorsDecideByContent(t *testing.T) {
	t.Parallel()

	payload := []byte("content decides payload\n")
	gz := decGzip(t, payload)
	zipped := decZip(t, []decZipEntry{{name: "a.txt", method: zip.Deflate, body: payload}})

	tests := []struct {
		name     string
		extract  func(context.Context, string, string) error
		file     string
		data     []byte
		wantFile string // holds payload when extraction succeeds
		wantErr  string
	}{
		{name: "gzip content is extracted", extract: ExtractGzip, file: "p.txt.gz", data: gz, wantFile: "p.txt"},
		{name: "other content under a gzip name is rejected", extract: ExtractGzip, file: "p.txt.gz", data: payload, wantErr: "not a valid gzip archive"},
		{name: "zip content is extracted", extract: ExtractZip, file: "p.zip", data: zipped, wantFile: "a.txt"},
		{name: "zip content under a java archive name is extracted", extract: ExtractZip, file: "p.jar", data: zipped, wantFile: "a.txt"},
		{name: "zip content under an office document name is extracted", extract: ExtractZip, file: "p.docx", data: zipped, wantFile: "a.txt"},
		{name: "other content under a zip name is rejected", extract: ExtractZip, file: "p.zip", data: payload, wantErr: "not a valid zip archive"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			out := t.TempDir()
			err := tt.extract(t.Context(), out, decWrite(t, tt.file, tt.data))
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("extract error: got = %v, want = error containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("extract error: got = %v, want = nil", err)
			}
			pkgsWantFile(t, filepath.Join(out, tt.wantFile), string(payload))
		})
	}
}
