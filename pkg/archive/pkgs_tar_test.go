// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/chainguard-dev/malcontent/pkg/file"
	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/chainguard-dev/malcontent/pkg/programkind"
	"go.uber.org/goleak"
)

// pkgsHelloBz2 is the hello.bz2 test vector from github.com/cosnicolaou/pbzip2:
// a single-block bzip2 stream of the text "hello world". No bzip2 encoder is
// available among the module's dependencies.
var pkgsHelloBz2 = []byte{
	0x42, 0x5a, 0x68, 0x39, 0x31, 0x41, 0x59, 0x26, 0x53, 0x59, 0x4e, 0xec, 0xe8, 0x36, 0x00, 0x00,
	0x02, 0x51, 0x80, 0x00, 0x10, 0x40, 0x00, 0x06, 0x44, 0x90, 0x80, 0x20, 0x00, 0x31, 0x06, 0x4c,
	0x41, 0x01, 0xa7, 0xa9, 0xa5, 0x80, 0xbb, 0x94, 0x31, 0xf8, 0xbb, 0x92, 0x29, 0xc2, 0x84, 0x82,
	0x77, 0x67, 0x41, 0xb0,
}

// pkgsBz2ZerosMiB is a hex-encoded, single-block bzip2 stream of 1 MiB of
// zero bytes, which pbzip2 returns one full buffer per read.
const pkgsBz2ZerosMiB = "425a683931415926535938571ce50008084000c0040008200030cc0529a60806" +
	"c4201e2ee48a70a12070ae39ca"

// pkgsSingleFileOutput is where ExtractTar writes the decompressed content of
// a compressed single file at src: beneath out, in a directory named for the
// directory holding src.
func pkgsSingleFileOutput(out, src, name string) string {
	return filepath.Join(out, filepath.Base(filepath.Dir(src)), name)
}

// TestExtractTarStreamSelection verifies that the stream handed to the tar
// reader follows the content and name of the archive.
func TestExtractTarStreamSelection(t *testing.T) {
	t.Parallel()

	plain, err := os.ReadFile(writeTar(t, []tarEntry{
		{name: "first.txt", typeflag: tar.TypeReg, body: "first"},
		{name: "second.txt", typeflag: tar.TypeReg, body: "second"},
	}))
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		filename string
		data     []byte
	}{
		{name: "plain tar without a recognized extension", filename: "payload", data: plain},
		{name: "gzip-compressed tar", filename: "pkg.tar.gz", data: gzipBytes(t, plain)},
		{name: "gzip-compressed apk package", filename: "pkg.apk", data: gzipBytes(t, plain)},
		{name: "uncompressed tar carrying a gzip name", filename: "plain.tar.gz", data: plain},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			out := t.TempDir()
			if err := ExtractTar(t.Context(), out, writeTemp(t, tt.filename, tt.data)); err != nil {
				t.Fatalf("ExtractTar: %v", err)
			}
			pkgsWantFile(t, filepath.Join(out, "first.txt"), "first")
			pkgsWantFile(t, filepath.Join(out, "second.txt"), "second")
		})
	}
}

func TestExtractTarSkipsEntries(t *testing.T) {
	t.Parallel()

	const traversal = "path is absolute or contains a relative path traversal"
	endMarker := make([]byte, 2*tarBlockSize)
	member := func(name string) []byte {
		b, err := os.ReadFile(writeTar(t, []tarEntry{{name: name, typeflag: tar.TypeReg, body: "evil"}}))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}

	tests := []struct {
		name    string
		data    []byte
		wantErr string // empty when extraction succeeds
		absent  string
	}{
		{
			name:    "absolute member path is rejected",
			data:    member("/etc/evil"),
			wantErr: traversal,
			absent:  filepath.Join("etc", "evil"),
		},
		{
			name:    "member path climbing out of the directory is rejected",
			data:    member("../evil"),
			wantErr: traversal,
			absent:  filepath.Join("..", "evil"),
		},
		{
			name:   "empty member with an unrecognized typeflag is not written",
			data:   slices.Concat(rawTarHeader("empty.bin", 0, 'Z'), endMarker),
			absent: "empty.bin",
		},
		{
			// archive/tar reads no data for header-only types whatever their
			// size field says.
			name:   "header-only member with a size field is not written",
			data:   slices.Concat(rawTarHeader("pipe", tarBlockSize, tar.TypeFifo), endMarker),
			absent: "pipe",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			out := t.TempDir()
			err := ExtractTar(t.Context(), out, writeTemp(t, "entries.tar", tt.data))
			switch {
			case tt.wantErr == "" && err != nil:
				t.Errorf("ExtractTar error: got = %v, want = nil", err)
			case tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)):
				t.Errorf("ExtractTar error: got = %v, want = error containing %q", err, tt.wantErr)
			}
			pkgsWantAbsent(t, filepath.Join(out, tt.absent))
		})
	}
}

// TestExtractTarSingleFileStreams covers names ExtractTar decompresses to a
// single file rather than reading as a tar stream.
func TestExtractTarSingleFileStreams(t *testing.T) {
	t.Parallel()

	const xzBody = "single xz stream body"
	tests := []struct {
		name     string
		filename string
		data     []byte
		output   string
		want     string
	}{
		{name: "xz stream", filename: "notes.xz", data: pkgsCompress(t, pkgsXZ, []byte(xzBody)), output: "notes", want: xzBody},
		{name: "tbz stream keeps a tar name", filename: "hello.tbz", data: pkgsHelloBz2, output: "hello.tar", want: "hello world"},
		{name: "tar bz2 stream", filename: "hello.tar.bz2", data: pkgsHelloBz2, output: "hello.tar", want: "hello world"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			src := writeTemp(t, tt.filename, tt.data)
			out := t.TempDir()
			if err := ExtractTar(t.Context(), out, src); err != nil {
				t.Fatalf("ExtractTar: %v", err)
			}
			got, err := os.ReadFile(pkgsSingleFileOutput(out, src, tt.output))
			if err != nil {
				t.Fatalf("read decompressed file: %v", err)
			}
			if strings.TrimSpace(string(got)) != tt.want {
				t.Errorf("decompressed content: got = %q, want = %q", got, tt.want)
			}
		})
	}
}

// TestExtractArchiveToTempDirApkNestedTar verifies that a plain tar nested in
// an .apk is read as a plain tar. The temporary directory it lands in is named
// after the .apk, which must not select gzip for the nested tar.
func TestExtractArchiveToTempDirApkNestedTar(t *testing.T) {
	t.Parallel()

	inner := tarWithEntry(t, "member.txt", "apk member")
	src := writeTemp(t, "pkg.apk", gzipBytes(t, tarWithEntry(t, "inner.tar", string(inner))))

	dir, err := ExtractArchiveToTempDir(t.Context(), malcontent.Config{}, src)
	if err != nil {
		t.Fatalf("ExtractArchiveToTempDir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	pkgsWantFile(t, filepath.Join(dir, "inner", "member.txt"), "apk member")
	pkgsWantAbsent(t, filepath.Join(dir, "inner.tar"))
}

// TestExtractArchiveToTempDirBzip2Tar verifies that a bzip2-compressed tar is
// recognized as an archive by name and that its members reach the scan
// corpus, whether it is the scanned archive or nested in one.
// testdata/single.tbz holds single/ and single/file, whose content is "foo\n".
func TestExtractArchiveToTempDirBzip2Tar(t *testing.T) {
	t.Parallel()

	tbz, err := os.ReadFile(filepath.Join("testdata", "single.tbz"))
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		// scanned is the name of the scanned archive.
		scanned string
		// nested, when set, names the compressed tar inside a scanned tar.
		nested string
	}{
		{name: "scanned tbz", scanned: "pkg.tbz"},
		{name: "scanned tar bz2", scanned: "pkg.tar.bz2"},
		{name: "tbz nested in a tar", scanned: "outer.tar", nested: "pkg.tbz"},
		{name: "tar bz2 nested in a tar", scanned: "outer.tar", nested: "pkg.tar.bz2"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			data := tbz
			if tt.nested != "" {
				data = tarWithEntry(t, tt.nested, string(tbz))
			}
			src := writeTemp(t, tt.scanned, data)
			if !programkind.IsSupportedArchive(t.Context(), src) {
				t.Fatalf("IsSupportedArchive(%s): got = false, want = true", tt.scanned)
			}

			dir, err := ExtractArchiveToTempDir(t.Context(), malcontent.Config{}, src)
			if err != nil {
				t.Fatalf("ExtractArchiveToTempDir: %v", err)
			}
			t.Cleanup(func() { _ = os.RemoveAll(dir) })

			// The decompressed tar lands in a directory named for the one
			// holding the compressed tar, and is extracted beside itself.
			out, archive := dir, src
			if tt.nested != "" {
				out, archive = filepath.Join(dir, "pkg"), filepath.Join(dir, tt.nested)
			}
			tarDir := pkgsSingleFileOutput(out, archive, "pkg")
			pkgsWantFile(t, filepath.Join(tarDir, "single", "file"), "foo\n")
			pkgsWantAbsent(t, tarDir+".tar")
		})
	}
}

func TestExtractTarSingleFileStreamErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		maxBytes int64
		data     []byte
		wantErr  error
		wantMsg  string
	}{
		{
			name:    "xz stream that is not xz",
			data:    []byte("not an xz stream"),
			wantMsg: "failed to create xz reader",
		},
		{
			name:     "xz stream larger than the byte cap",
			maxBytes: 1024,
			data:     pkgsCompress(t, pkgsXZ, pkgsNoise(4096)),
			wantErr:  file.ErrArchiveBytesCap,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()
			if tt.maxBytes > 0 {
				ctx = malcontent.ContextWithConfig(ctx, &malcontent.Config{MaxArchiveBytes: tt.maxBytes})
			}
			err := ExtractTar(ctx, t.TempDir(), writeTemp(t, "data.xz", tt.data))
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Fatalf("ExtractTar error: got = %v, want = %v", err, tt.wantErr)
			}
			if tt.wantMsg != "" && (err == nil || !strings.Contains(err.Error(), tt.wantMsg)) {
				t.Fatalf("ExtractTar error: got = %v, want = error containing %q", err, tt.wantMsg)
			}
		})
	}
}

// TestExtractTarXZCancellation verifies that decompressing a standalone xz
// stream consults the context before every read. ExtractTar also consults it
// once on entry, which the allowances below include.
func TestExtractTarXZCancellation(t *testing.T) {
	t.Parallel()

	data := pkgsCompress(t, pkgsXZ, pkgsNoise(3*int(file.ExtractBuffer)))
	tests := []struct {
		name     string
		allow    int64
		wantErr  error
		wantSize int64
	}{
		{
			name:     "cancellation before the first read writes nothing",
			allow:    1,
			wantErr:  context.Canceled,
			wantSize: 0,
		},
		{
			name:     "cancellation after one read stops decompression",
			allow:    2,
			wantErr:  context.Canceled,
			wantSize: file.ExtractBuffer,
		},
		{
			name:     "live context decompresses the whole stream",
			allow:    math.MaxInt64,
			wantErr:  nil,
			wantSize: 3 * file.ExtractBuffer,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			src := writeTemp(t, "big.xz", data)
			out := t.TempDir()
			ctx := &pkgsCountdownContext{Context: t.Context(), allow: tt.allow}

			if err := ExtractTar(ctx, out, src); !errors.Is(err, tt.wantErr) {
				t.Fatalf("ExtractTar error: got = %v, want = %v", err, tt.wantErr)
			}
			fi, err := os.Stat(pkgsSingleFileOutput(out, src, "big"))
			if err != nil {
				t.Fatal(err)
			}
			if fi.Size() != tt.wantSize {
				t.Errorf("decompressed size: got = %d, want = %d", fi.Size(), tt.wantSize)
			}
		})
	}
}

// TestExtractTarBz2EarlyReturn verifies that a tbz stream abandoned before
// its end, by the byte cap or by cancellation, stops after the read that
// triggered it and releases the decoder's goroutines. goleak inspects every
// goroutine in the process, so this test does not run in parallel.
func TestExtractTarBz2EarlyReturn(t *testing.T) {
	zeros, err := hex.DecodeString(pkgsBz2ZerosMiB)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		maxBytes int64
		allow    int64
		wantErr  error
	}{
		{
			// The first read reaches the cap exactly; the second exceeds it.
			name:     "byte cap exceeded",
			maxBytes: file.ExtractBuffer,
			allow:    math.MaxInt64,
			wantErr:  file.ErrArchiveBytesCap,
		},
		{
			// One check on entry and one before the first read pass.
			name:    "canceled after the first read",
			allow:   2,
			wantErr: context.Canceled,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ignore := goleak.IgnoreCurrent()
			src := writeTemp(t, "zeros.tbz", zeros)
			out := t.TempDir()
			// The zero-filled stream expands far past the default ratio cap.
			cfg := &malcontent.Config{MaxArchiveBytes: tt.maxBytes, MaxArchiveRatio: 1e6}
			ctx := &pkgsCountdownContext{Context: malcontent.ContextWithConfig(t.Context(), cfg), allow: tt.allow}

			if err := ExtractTar(ctx, out, src); !errors.Is(err, tt.wantErr) {
				t.Fatalf("ExtractTar error: got = %v, want = %v", err, tt.wantErr)
			}
			fi, err := os.Stat(pkgsSingleFileOutput(out, src, "zeros.tar"))
			if err != nil {
				t.Fatal(err)
			}
			if fi.Size() != file.ExtractBuffer {
				t.Errorf("decompressed size: got = %d, want = %d", fi.Size(), file.ExtractBuffer)
			}
			goleak.VerifyNone(t, ignore)
		})
	}
}

// TestAuditTarTrailerLimit covers the bound on how much of the region past the
// end-of-archive marker is examined. It shrinks a package variable, so it does
// not run in parallel with other tests.
func TestAuditTarTrailerLimit(t *testing.T) {
	orig := maxTrailerAudit
	maxTrailerAudit = 64
	t.Cleanup(func() { maxTrailerAudit = orig })

	tests := []struct {
		name    string
		trailer int
		wantErr bool
	}{
		{name: "zero padding at the limit is accepted", trailer: 64, wantErr: false},
		{name: "zero padding past the limit is rejected", trailer: 65, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := auditTarTrailer(bytes.NewReader(make([]byte, tt.trailer)), newTarAuditor())
			if got := err != nil; got != tt.wantErr {
				t.Errorf("auditTarTrailer error: got = %v, want error = %v", err, tt.wantErr)
			}
		})
	}
}

// TestExtractTarEmptyInput verifies that an empty file extracts nothing and
// succeeds whatever compression its name implies, since there is no stream to
// decode.
func TestExtractTarEmptyInput(t *testing.T) {
	t.Parallel()

	for _, name := range []string{"empty.apk", "empty.xz", "empty.tbz", "empty.tar"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			out := t.TempDir()
			if err := ExtractTar(t.Context(), out, writeTemp(t, name, nil)); err != nil {
				t.Fatalf("ExtractTar error: got = %v, want = nil", err)
			}
			entries, err := os.ReadDir(out)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 0 {
				t.Errorf("extracted entries: got = %d, want = 0", len(entries))
			}
		})
	}
}
