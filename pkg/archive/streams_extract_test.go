// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"context"
	"encoding/hex"
	"errors"
	"io/fs"
	"maps"
	"path/filepath"
	"slices"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/chainguard-dev/malcontent/pkg/file"
	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/klauspost/compress/zstd"
	"go.uber.org/goleak"
)

// bzip2 streams taken from the Go standard library's compress/bzip2 test
// vectors; the module has no bzip2 encoder to build them at test time.
const (
	// "hello world\n".
	streamsBz2Hello = "425a68393141592653594eece83600000251800010400006449080200031064c" +
		"4101a7a9a580bb9431f8bb9229c28482776741b0"
	// 32 zero bytes.
	streamsBz2Zeros32 = "425a6839314159265359b5aa5098000000600040000004200021008283177245" +
		"385090b5aa5098"
	// 1 MiB of zero bytes in a single block.
	streamsBz2ZerosMiB = "425a683931415926535938571ce50008084000c0040008200030cc0529a60806" +
		"c4201e2ee48a70a12070ae39ca"
)

// streamsNoByteCap is a byte cap well above every fixture in this file.
const streamsNoByteCap int64 = 1 << 30

type streamsExtractor func(ctx context.Context, d, f string) error

// streamsCancelAfterCtx reports a live context to the first live Err calls
// and context.Canceled to every later call. Done stays the parent's channel,
// so decoders that select on it keep running and only the extractor's own Err
// checks see the cancellation.
type streamsCancelAfterCtx struct {
	context.Context
	live  int64
	calls atomic.Int64
}

func (c *streamsCancelAfterCtx) Err() error {
	if c.calls.Add(1) > c.live {
		return context.Canceled
	}
	return c.Context.Err()
}

// streamsCtx attaches a Config with the given byte cap and a ratio ceiling
// high enough for the highly compressible fixtures below.
func streamsCtx(t *testing.T, maxBytes int64) context.Context {
	t.Helper()
	return malcontent.ContextWithConfig(t.Context(), &malcontent.Config{
		MaxArchiveBytes: maxBytes,
		MaxArchiveRatio: 1e6,
	})
}

// streamsCancelAfterReads returns a context that each extractor sees as live
// at its entry check and for the first reads iterations of its copy loop, and
// as canceled from the next iteration on. Every extractor in this file calls
// Err once on entry and once at the top of each loop iteration, before the
// read; none of their decoders call Err on it.
func streamsCancelAfterReads(t *testing.T, reads int64) *streamsCancelAfterCtx {
	t.Helper()
	return &streamsCancelAfterCtx{Context: streamsCtx(t, streamsNoByteCap), live: 1 + reads}
}

// streamsPayload returns n bytes of a repeating, non-uniform pattern so a
// truncated or shifted copy never matches the original.
func streamsPayload(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i % 251)
	}
	return b
}

func streamsHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode hex fixture: %v", err)
	}
	return b
}

// streamsGzip writes each member as its own gzip stream, back to back.
func streamsGzip(t *testing.T, members ...[]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	for _, m := range members {
		zw := gzip.NewWriter(&buf)
		if _, err := zw.Write(m); err != nil {
			t.Fatalf("gzip write: %v", err)
		}
		if err := zw.Close(); err != nil {
			t.Fatalf("gzip close: %v", err)
		}
	}
	return buf.Bytes()
}

func streamsZlib(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zlib.NewWriter(&buf)
	if _, err := zw.Write(data); err != nil {
		t.Fatalf("zlib write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zlib close: %v", err)
	}
	return buf.Bytes()
}

func streamsZstd(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw, err := zstd.NewWriter(&buf, zstd.WithEncoderConcurrency(1))
	if err != nil {
		t.Fatalf("zstd writer: %v", err)
	}
	if _, err := zw.Write(data); err != nil {
		t.Fatalf("zstd write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zstd close: %v", err)
	}
	return buf.Bytes()
}

// streamsWriteSource writes data to <tmp>/src/<name> and returns the path.
// bz2 and zstd keep the "src" parent directory name in their output path.
func streamsWriteSource(t *testing.T, name string, data []byte) string {
	t.Helper()
	base := t.TempDir()
	dir := filepath.Join(base, "src")
	if err := file.MkdirAllIn(base, "src", 0o700); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	p := filepath.Join(dir, name)
	if err := file.WriteFileIn(dir, name, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", p, err)
	}
	return p
}

// streamsTree maps each regular file under dir, by slash-separated relative
// path, to its contents.
func streamsTree(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	r := openTestRoot(t, dir)
	got := map[string][]byte{}
	err := fs.WalkDir(r.FS(), ".", func(rel string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !d.Type().IsRegular() {
			return nil
		}
		data, err := r.ReadFile(rel)
		if err != nil {
			return err
		}
		got[rel] = data
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", dir, err)
	}
	return got
}

func streamsFirstDiff(a, b []byte) int {
	n := min(len(a), len(b))
	for i := range n {
		if a[i] != b[i] {
			return i
		}
	}
	return n
}

// streamsAssertSingleFile checks that dir holds exactly one regular file, at
// rel, whose contents equal want.
func streamsAssertSingleFile(t *testing.T, dir, rel string, want []byte) {
	t.Helper()
	tree := streamsTree(t, dir)
	data, ok := tree[rel]
	if !ok || len(tree) != 1 {
		t.Fatalf("output files: got = %v, want = [%s]", slices.Sorted(maps.Keys(tree)), rel)
	}
	if !bytes.Equal(data, want) {
		t.Errorf("%s: got = %d bytes (first difference at offset %d), want = %d bytes",
			rel, len(data), streamsFirstDiff(data, want), len(want))
	}
}

func TestStreamExtractorsWriteDecompressedOutput(t *testing.T) {
	t.Parallel()

	small := []byte("hello world\n")
	// A one-byte payload, and a payload one byte past the buffer, each end in
	// a read that returns a single byte.
	one := []byte{'x'}
	bufPlusOne := streamsPayload(int(file.ExtractBuffer) + 1)
	// Spans several reads, so the per-read cancellation check runs against a
	// live context more than once.
	large := streamsPayload(300 << 10)
	zerosMiB := make([]byte, 1<<20)

	cases := []struct {
		name    string
		extract streamsExtractor
		srcName string
		src     []byte
		wantRel string
		want    []byte
	}{
		{
			name:    "gzip small payload",
			extract: ExtractGzip,
			srcName: "payload.txt.gz",
			src:     streamsGzip(t, small),
			wantRel: "payload.txt",
			want:    small,
		},
		{
			name:    "gzip one-byte payload",
			extract: ExtractGzip,
			srcName: "payload.txt.gz",
			src:     streamsGzip(t, one),
			wantRel: "payload.txt",
			want:    one,
		},
		{
			name:    "gzip payload one byte longer than the buffer",
			extract: ExtractGzip,
			srcName: "payload.txt.gz",
			src:     streamsGzip(t, bufPlusOne),
			wantRel: "payload.txt",
			want:    bufPlusOne,
		},
		{
			name:    "zstd one-byte payload",
			extract: ExtractZstd,
			srcName: "payload.txt.zst",
			src:     streamsZstd(t, one),
			wantRel: "src/payload.txt",
			want:    one,
		},
		{
			name:    "zstd payload one byte longer than the buffer",
			extract: ExtractZstd,
			srcName: "payload.txt.zst",
			src:     streamsZstd(t, bufPlusOne),
			wantRel: "src/payload.txt",
			want:    bufPlusOne,
		},
		{
			name:    "zlib one-byte payload",
			extract: ExtractZlib,
			srcName: "payload.txt.zlib",
			src:     streamsZlib(t, one),
			wantRel: "payload.txt",
			want:    one,
		},
		{
			name:    "zlib payload one byte longer than the buffer",
			extract: ExtractZlib,
			srcName: "payload.txt.zlib",
			src:     streamsZlib(t, bufPlusOne),
			wantRel: "payload.txt",
			want:    bufPlusOne,
		},
		{
			name:    "gzip payload larger than the buffer",
			extract: ExtractGzip,
			srcName: "payload.txt.gz",
			src:     streamsGzip(t, large),
			wantRel: "payload.txt",
			want:    large,
		},
		{
			name:    "gzip members are concatenated",
			extract: ExtractGzip,
			srcName: "payload.txt.gz",
			src:     streamsGzip(t, small, large),
			wantRel: "payload.txt",
			want:    slices.Concat(small, large),
		},
		{
			name:    "bz2 small payload",
			extract: ExtractBz2,
			srcName: "payload.txt.bz2",
			src:     streamsHex(t, streamsBz2Hello),
			wantRel: "src/payload.txt",
			want:    small,
		},
		{
			name:    "bz2 long .bzip2 extension is trimmed",
			extract: ExtractBz2,
			srcName: "payload.txt.bzip2",
			src:     streamsHex(t, streamsBz2Hello),
			wantRel: "src/payload.txt",
			want:    small,
		},
		{
			name:    "bz2 payload larger than the buffer",
			extract: ExtractBz2,
			srcName: "payload.txt.bz2",
			src:     streamsHex(t, streamsBz2ZerosMiB),
			wantRel: "src/payload.txt",
			want:    zerosMiB,
		},
		{
			name:    "zstd small payload",
			extract: ExtractZstd,
			srcName: "payload.txt.zst",
			src:     streamsZstd(t, small),
			wantRel: "src/payload.txt",
			want:    small,
		},
		{
			name:    "zstd long .zstd extension is trimmed",
			extract: ExtractZstd,
			srcName: "payload.txt.zstd",
			src:     streamsZstd(t, small),
			wantRel: "src/payload.txt",
			want:    small,
		},
		{
			name:    "zstd payload larger than the buffer",
			extract: ExtractZstd,
			srcName: "payload.txt.zst",
			src:     streamsZstd(t, large),
			wantRel: "src/payload.txt",
			want:    large,
		},
		{
			name:    "zlib small payload",
			extract: ExtractZlib,
			srcName: "payload.txt.zlib",
			src:     streamsZlib(t, small),
			wantRel: "payload.txt",
			want:    small,
		},
		{
			name:    "zlib payload larger than the buffer",
			extract: ExtractZlib,
			srcName: "payload.txt.zlib",
			src:     streamsZlib(t, large),
			wantRel: "payload.txt",
			want:    large,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			src := streamsWriteSource(t, tc.srcName, tc.src)
			dst := t.TempDir()
			if err := tc.extract(streamsCtx(t, streamsNoByteCap), dst, src); err != nil {
				t.Fatalf("extract error: got = %v, want = nil", err)
			}
			streamsAssertSingleFile(t, dst, tc.wantRel, tc.want)
		})
	}
}

// TestStreamExtractorsStopBeforeNextReadWhenCanceled checks that every copy
// loop iteration checks for cancellation before it reads, so the output holds
// exactly the bytes returned by the reads that ran before the cancellation,
// whether or not that total is a multiple of the buffer size.
//
// The fixtures fix each decoder's read sizes against the 64 KiB buffer: pgzip
// returns at most one buffer from a single 1 MiB block of one gzip member,
// pbzip2 returns at most one buffer from a single bzip2 block, zstd fills the
// buffer from 128 KiB blocks, and compress/flate returns one 32 KiB window
// flush per read.
func TestStreamExtractorsStopBeforeNextReadWhenCanceled(t *testing.T) {
	t.Parallel()

	bufSize := int(file.ExtractBuffer)
	const flateWindow = 32 << 10
	half := streamsPayload(bufSize / 2)
	large := streamsPayload(1 << 20)
	zerosMiB := streamsHex(t, streamsBz2ZerosMiB)
	// Each 32-byte stream decodes as its own block and so its own short read.
	bzShort := slices.Concat(bytes.Repeat(streamsHex(t, streamsBz2Zeros32), 4), zerosMiB)
	// Each gzip member shorter than the buffer is its own short read.
	gzShort := streamsGzip(t, half, half, large)
	gzLarge := streamsGzip(t, large)
	zst := streamsZstd(t, large)
	zl := streamsZlib(t, large)

	cases := []struct {
		name    string
		extract streamsExtractor
		srcName string
		src     []byte
		reads   int64
		wantRel string
		want    []byte
	}{
		{
			name:    "gzip canceled before the first read writes nothing",
			extract: ExtractGzip,
			srcName: "payload.txt.gz",
			src:     gzLarge,
			reads:   0,
			wantRel: "payload.txt",
			want:    []byte{},
		},
		{
			name:    "gzip stops after three full-buffer reads",
			extract: ExtractGzip,
			srcName: "payload.txt.gz",
			src:     gzLarge,
			reads:   3,
			wantRel: "payload.txt",
			want:    large[:3*bufSize],
		},
		{
			name:    "gzip stops after one short read",
			extract: ExtractGzip,
			srcName: "payload.txt.gz",
			src:     gzShort,
			reads:   1,
			wantRel: "payload.txt",
			want:    half,
		},
		{
			name:    "gzip stops after two short reads and one full-buffer read",
			extract: ExtractGzip,
			srcName: "payload.txt.gz",
			src:     gzShort,
			reads:   3,
			wantRel: "payload.txt",
			want:    slices.Concat(half, half, large[:bufSize]),
		},
		{
			name:    "bz2 canceled before the first read writes nothing",
			extract: ExtractBz2,
			srcName: "payload.txt.bz2",
			src:     zerosMiB,
			reads:   0,
			wantRel: "src/payload.txt",
			want:    []byte{},
		},
		{
			name:    "bz2 stops after three full-buffer reads",
			extract: ExtractBz2,
			srcName: "payload.txt.bz2",
			src:     zerosMiB,
			reads:   3,
			wantRel: "src/payload.txt",
			want:    make([]byte, 3*bufSize),
		},
		{
			name:    "bz2 stops after one short read",
			extract: ExtractBz2,
			srcName: "payload.txt.bz2",
			src:     bzShort,
			reads:   1,
			wantRel: "src/payload.txt",
			want:    make([]byte, 32),
		},
		{
			name:    "bz2 stops after four short reads and one full-buffer read",
			extract: ExtractBz2,
			srcName: "payload.txt.bz2",
			src:     bzShort,
			reads:   5,
			wantRel: "src/payload.txt",
			want:    make([]byte, 4*32+bufSize),
		},
		{
			name:    "zstd canceled before the first read writes nothing",
			extract: ExtractZstd,
			srcName: "payload.txt.zst",
			src:     zst,
			reads:   0,
			wantRel: "src/payload.txt",
			want:    []byte{},
		},
		{
			name:    "zstd stops after three full-buffer reads",
			extract: ExtractZstd,
			srcName: "payload.txt.zst",
			src:     zst,
			reads:   3,
			wantRel: "src/payload.txt",
			want:    large[:3*bufSize],
		},
		{
			name:    "zlib canceled before the first read writes nothing",
			extract: ExtractZlib,
			srcName: "payload.txt.zlib",
			src:     zl,
			reads:   0,
			wantRel: "payload.txt",
			want:    []byte{},
		},
		{
			name:    "zlib stops after three window-sized reads",
			extract: ExtractZlib,
			srcName: "payload.txt.zlib",
			src:     zl,
			reads:   3,
			wantRel: "payload.txt",
			want:    large[:3*flateWindow],
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			src := streamsWriteSource(t, tc.srcName, tc.src)
			dst := t.TempDir()
			err := tc.extract(streamsCancelAfterReads(t, tc.reads), dst, src)
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("extract error: got = %v, want = %v", err, context.Canceled)
			}
			streamsAssertSingleFile(t, dst, tc.wantRel, tc.want)
		})
	}
}

func TestStreamExtractorsHonorCanceledContextAtEntry(t *testing.T) {
	t.Parallel()

	small := []byte("hello world\n")
	cases := []struct {
		name    string
		extract streamsExtractor
		srcName string
		src     []byte
	}{
		{name: "gzip", extract: ExtractGzip, srcName: "payload.txt.gz", src: streamsGzip(t, small)},
		{name: "bz2", extract: ExtractBz2, srcName: "payload.txt.bz2", src: streamsHex(t, streamsBz2Hello)},
		{name: "zstd", extract: ExtractZstd, srcName: "payload.txt.zst", src: streamsZstd(t, small)},
		{name: "zlib", extract: ExtractZlib, srcName: "payload.txt.zlib", src: streamsZlib(t, small)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			src := streamsWriteSource(t, tc.srcName, tc.src)
			base := t.TempDir()
			dst := filepath.Join(base, "out")
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			err := tc.extract(ctx, dst, src)
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("extract error: got = %v, want = %v", err, context.Canceled)
			}
			if _, err := file.StatIn(base, "out"); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("destination stat error: got = %v, want = %v", err, fs.ErrNotExist)
			}
		})
	}
}

func TestStreamExtractorsSkipEmptyInput(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		extract streamsExtractor
		srcName string
		wantErr bool
	}{
		{name: "bz2 empty file yields no output", extract: ExtractBz2, srcName: "empty.bz2"},
		{name: "zstd empty file yields no output", extract: ExtractZstd, srcName: "empty.zst"},
		{name: "zlib empty file yields no output", extract: ExtractZlib, srcName: "empty.zlib"},
		{name: "gzip empty file is not a gzip archive", extract: ExtractGzip, srcName: "empty.gz", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			src := streamsWriteSource(t, tc.srcName, nil)
			base := t.TempDir()
			dst := filepath.Join(base, "out")
			err := tc.extract(streamsCtx(t, streamsNoByteCap), dst, src)
			if (err != nil) != tc.wantErr {
				t.Fatalf("extract error: got = %v, want error = %t", err, tc.wantErr)
			}
			if _, err := file.StatIn(base, "out"); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("destination stat error: got = %v, want = %v", err, fs.ErrNotExist)
			}
		})
	}
}

func TestStreamExtractorsRejectInvalidInput(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		extract streamsExtractor
		srcName string
		src     []byte
		missing bool
		// wantErr is matched with errors.Is; nil accepts any non-nil error.
		wantErr error
	}{
		{name: "gzip plain text is not a gzip archive", extract: ExtractGzip, srcName: "payload.txt.gz", src: []byte("plain text, not gzip\n")},
		{name: "bz2 plain text fails to decompress", extract: ExtractBz2, srcName: "payload.txt.bz2", src: []byte("plain text, not bzip2\n")},
		{name: "zstd plain text fails to decompress", extract: ExtractZstd, srcName: "payload.txt.zst", src: []byte("plain text, not zstd\n")},
		{name: "zlib plain text has an invalid header", extract: ExtractZlib, srcName: "payload.txt.zlib", src: []byte("plain text, not zlib\n"), wantErr: zlib.ErrHeader},
		{name: "bz2 missing source", extract: ExtractBz2, srcName: "missing.bz2", missing: true, wantErr: fs.ErrNotExist},
		{name: "zstd missing source", extract: ExtractZstd, srcName: "missing.zst", missing: true, wantErr: fs.ErrNotExist},
		{name: "zlib missing source", extract: ExtractZlib, srcName: "missing.zlib", missing: true, wantErr: fs.ErrNotExist},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			src := filepath.Join(t.TempDir(), tc.srcName)
			if !tc.missing {
				src = streamsWriteSource(t, tc.srcName, tc.src)
			}
			err := tc.extract(streamsCtx(t, streamsNoByteCap), t.TempDir(), src)
			if err == nil {
				t.Fatal("extract error: got = nil, want = non-nil")
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Errorf("extract error: got = %v, want = %v", err, tc.wantErr)
			}
		})
	}
}

func TestStreamExtractorsReportDestinationErrors(t *testing.T) {
	t.Parallel()

	small := []byte("hello world\n")
	formats := []struct {
		name    string
		extract streamsExtractor
		srcName string
		src     []byte
		outRel  string
	}{
		{name: "gzip", extract: ExtractGzip, srcName: "payload.txt.gz", src: streamsGzip(t, small), outRel: "payload.txt"},
		{name: "bz2", extract: ExtractBz2, srcName: "payload.txt.bz2", src: streamsHex(t, streamsBz2Hello), outRel: "src/payload.txt"},
		{name: "zstd", extract: ExtractZstd, srcName: "payload.txt.zst", src: streamsZstd(t, small), outRel: "src/payload.txt"},
		{name: "zlib", extract: ExtractZlib, srcName: "payload.txt.zlib", src: streamsZlib(t, small), outRel: "payload.txt"},
	}
	for _, f := range formats {
		t.Run(f.name+" destination below a regular file cannot be created", func(t *testing.T) {
			t.Parallel()
			src := streamsWriteSource(t, f.srcName, f.src)
			base := t.TempDir()
			blocker := filepath.Join(base, "blocker")
			if err := file.WriteFileIn(base, "blocker", []byte("not a directory"), 0o600); err != nil {
				t.Fatalf("write %s: %v", blocker, err)
			}
			err := f.extract(streamsCtx(t, streamsNoByteCap), filepath.Join(blocker, "out"), src)
			if !errors.Is(err, syscall.ENOTDIR) {
				t.Errorf("extract error: got = %v, want = %v", err, syscall.ENOTDIR)
			}
		})
		t.Run(f.name+" output path held by a directory", func(t *testing.T) {
			t.Parallel()
			src := streamsWriteSource(t, f.srcName, f.src)
			dst := t.TempDir()
			if err := file.MkdirAllIn(dst, f.outRel, 0o700); err != nil {
				t.Fatalf("mkdir %s: %v", f.outRel, err)
			}
			err := f.extract(streamsCtx(t, streamsNoByteCap), dst, src)
			if !errors.Is(err, syscall.EISDIR) {
				t.Errorf("extract error: got = %v, want = %v", err, syscall.EISDIR)
			}
		})
	}
}

func TestStreamExtractorsEnforceByteCap(t *testing.T) {
	t.Parallel()

	payload := streamsPayload(256 << 10)
	size := int64(len(payload))
	gz := streamsGzip(t, payload)
	zst := streamsZstd(t, payload)
	zl := streamsZlib(t, payload)
	bz := streamsHex(t, streamsBz2ZerosMiB)
	const bzSize = int64(1 << 20)

	cases := []struct {
		name     string
		extract  streamsExtractor
		srcName  string
		src      []byte
		maxBytes int64
		wantErr  error
	}{
		{name: "gzip output equal to the cap succeeds", extract: ExtractGzip, srcName: "payload.txt.gz", src: gz, maxBytes: size},
		{name: "gzip output one byte over the cap fails", extract: ExtractGzip, srcName: "payload.txt.gz", src: gz, maxBytes: size - 1, wantErr: file.ErrArchiveBytesCap},
		{name: "bz2 output equal to the cap succeeds", extract: ExtractBz2, srcName: "payload.txt.bz2", src: bz, maxBytes: bzSize},
		{name: "bz2 output one byte over the cap fails", extract: ExtractBz2, srcName: "payload.txt.bz2", src: bz, maxBytes: bzSize - 1, wantErr: file.ErrArchiveBytesCap},
		{name: "zstd output equal to the cap succeeds", extract: ExtractZstd, srcName: "payload.txt.zst", src: zst, maxBytes: size},
		{name: "zstd output one byte over the cap fails", extract: ExtractZstd, srcName: "payload.txt.zst", src: zst, maxBytes: size - 1, wantErr: file.ErrArchiveBytesCap},
		{name: "zlib output equal to the cap succeeds", extract: ExtractZlib, srcName: "payload.txt.zlib", src: zl, maxBytes: size},
		{name: "zlib output one byte over the cap fails", extract: ExtractZlib, srcName: "payload.txt.zlib", src: zl, maxBytes: size - 1, wantErr: file.ErrArchiveBytesCap},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			src := streamsWriteSource(t, tc.srcName, tc.src)
			err := tc.extract(streamsCtx(t, tc.maxBytes), t.TempDir(), src)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("extract error: got = %v, want = %v", err, tc.wantErr)
			}
		})
	}
}

// TestExtractBz2ReleasesDecoderOnEarlyReturn is not parallel: it compares the
// process-wide goroutine set before and after extraction.
func TestExtractBz2ReleasesDecoderOnEarlyReturn(t *testing.T) {
	src := streamsWriteSource(t, "payload.txt.bz2", streamsHex(t, streamsBz2ZerosMiB))

	t.Run("byte cap exceeded", func(t *testing.T) {
		ignore := goleak.IgnoreCurrent()
		err := ExtractBz2(streamsCtx(t, file.ExtractBuffer), t.TempDir(), src)
		if !errors.Is(err, file.ErrArchiveBytesCap) {
			t.Fatalf("extract error: got = %v, want = %v", err, file.ErrArchiveBytesCap)
		}
		goleak.VerifyNone(t, ignore)
	})

	t.Run("canceled mid-stream", func(t *testing.T) {
		ignore := goleak.IgnoreCurrent()
		err := ExtractBz2(streamsCancelAfterReads(t, 1), t.TempDir(), src)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("extract error: got = %v, want = %v", err, context.Canceled)
		}
		goleak.VerifyNone(t, ignore)
	})
}
