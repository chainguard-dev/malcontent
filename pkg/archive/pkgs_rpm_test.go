// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"io/fs"
	"math"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/cavaliergopher/cpio"
	"github.com/chainguard-dev/malcontent/pkg/file"
)

const (
	pkgsCPIOFormat = "cpio"
	pkgsRPMTool    = "#!/bin/sh\necho rpm tool\n"
)

// pkgsCPIOEntry describes one member of a synthesized RPM payload. For a
// symlink, body is the link target.
type pkgsCPIOEntry struct {
	name  string
	mode  cpio.FileMode
	body  string
	links int
	inode int64
}

// pkgsCPIO returns a newc cpio archive holding entries.
func pkgsCPIO(t *testing.T, entries []pkgsCPIOEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	cw := cpio.NewWriter(&buf)
	for _, e := range entries {
		hdr := &cpio.Header{Name: e.name, Mode: e.mode, Size: int64(len(e.body)), Links: e.links, Inode: e.inode}
		if err := cw.WriteHeader(hdr); err != nil {
			t.Fatalf("write cpio header %s: %v", e.name, err)
		}
		if _, err := cw.Write([]byte(e.body)); err != nil {
			t.Fatalf("write cpio body %s: %v", e.name, err)
		}
	}
	if err := cw.Close(); err != nil {
		t.Fatalf("close cpio: %v", err)
	}
	return buf.Bytes()
}

// pkgsRPMTag is a string entry in an RPM header.
type pkgsRPMTag struct {
	id    uint32
	value string
}

// pkgsRPMHeader encodes an RPM header structure holding string tags.
func pkgsRPMHeader(tags []pkgsRPMTag) []byte {
	const stringType = 6 // RPM_STRING_TYPE
	index := make([]byte, 0, 16*len(tags))
	store := make([]byte, 0, 64)
	for _, tag := range tags {
		for _, v := range []uint32{tag.id, stringType, uint32(len(store)), 1} {
			index = binary.BigEndian.AppendUint32(index, v)
		}
		store = append(store, tag.value...)
		store = append(store, 0)
	}
	hdr := []byte{0x8e, 0xad, 0xe8, 0x01, 0, 0, 0, 0}
	hdr = binary.BigEndian.AppendUint32(hdr, uint32(len(tags)))
	hdr = binary.BigEndian.AppendUint32(hdr, uint32(len(store)))
	return slices.Concat(hdr, index, store)
}

// pkgsRPM returns an RPM carrying payload: a lead, a signature header with no
// entries (an empty store needs no alignment padding), and a main header that
// names the payload format and compression.
func pkgsRPM(format, compression string, payload []byte) []byte {
	lead := make([]byte, 96)
	copy(lead, []byte{0xed, 0xab, 0xee, 0xdb, 3, 0})
	return slices.Concat(lead, pkgsRPMHeader(nil), pkgsRPMHeader([]pkgsRPMTag{
		{id: 1124, value: format},      // RPMTAG_PAYLOADFORMAT
		{id: 1125, value: compression}, // RPMTAG_PAYLOADCOMPRESSOR
	}), payload)
}

// pkgsRPMLayout returns one member of each kind ExtractRPM distinguishes: a
// directory, a regular file, a symlink, and a FIFO, which it skips.
func pkgsRPMLayout() []pkgsCPIOEntry {
	return []pkgsCPIOEntry{
		{name: "./usr/bin", mode: cpio.TypeDir | 0o755},
		{name: "./usr/bin/tool", mode: cpio.TypeReg | 0o755, body: pkgsRPMTool},
		{name: "./usr/bin/link", mode: cpio.TypeSymlink | 0o777, body: "tool"},
		{name: "./run/pipe", mode: cpio.TypeFifo | 0o644},
	}
}

func TestExtractRPMPayloads(t *testing.T) {
	t.Parallel()

	for _, compression := range []string{pkgsGzip, pkgsXZ, pkgsZstd} {
		t.Run(compression+" payload", func(t *testing.T) {
			t.Parallel()
			payload := pkgsCompress(t, compression, pkgsCPIO(t, pkgsRPMLayout()))
			src := writeTemp(t, "pkg.rpm", pkgsRPM(pkgsCPIOFormat, compression, payload))
			out := t.TempDir()

			if err := ExtractRPM(t.Context(), out, src); err != nil {
				t.Fatalf("ExtractRPM: %v", err)
			}
			pkgsWantFile(t, filepath.Join(out, "usr", "bin", "tool"), pkgsRPMTool)
			pkgsWantSymlink(t, filepath.Join(out, "usr", "bin", "link"), "tool")
			pkgsWantAbsent(t, filepath.Join(out, "run", "pipe"))
		})
	}
}

func TestExtractRPMRejectsMalformedPackages(t *testing.T) {
	t.Parallel()

	member := func(name string, mode cpio.FileMode, body string) []byte {
		entries := []pkgsCPIOEntry{{name: name, mode: mode, body: body}}
		return pkgsRPM(pkgsCPIOFormat, pkgsGzip, pkgsCompress(t, pkgsGzip, pkgsCPIO(t, entries)))
	}

	tests := []struct {
		name    string
		data    []byte
		wantErr string
		absent  string
	}{
		{
			name:    "file that is not an rpm",
			data:    []byte("not an rpm package"),
			wantErr: "failed to read RPM package headers",
		},
		{
			name:    "payload format other than cpio",
			data:    pkgsRPM("tar", pkgsGzip, pkgsCompress(t, pkgsGzip, []byte("payload"))),
			wantErr: "unsupported payload format",
		},
		{
			name:    "payload compression without a decoder",
			data:    pkgsRPM(pkgsCPIOFormat, "bzip2", pkgsCPIO(t, pkgsRPMLayout())),
			wantErr: "unsupported compression format",
		},
		{
			name:    "gzip payload that is not gzip",
			data:    pkgsRPM(pkgsCPIOFormat, pkgsGzip, []byte("not a gzip stream")),
			wantErr: "failed to create gzip reader",
		},
		{
			name:    "xz payload that is not xz",
			data:    pkgsRPM(pkgsCPIOFormat, pkgsXZ, []byte("not an xz stream")),
			wantErr: "failed to create xz reader",
		},
		{
			name:    "absolute member path",
			data:    member("/etc/evil", cpio.TypeReg|0o644, "evil"),
			wantErr: "path is absolute",
			absent:  filepath.Join("etc", "evil"),
		},
		{
			name:    "member path climbing out of the directory",
			data:    member("../evil", cpio.TypeReg|0o644, "evil"),
			wantErr: "relative path traversal",
		},
		{
			name:    "symlink escaping the directory",
			data:    member("./esc", cpio.TypeSymlink|0o777, "../../outside"),
			wantErr: "failed to create symlink",
			absent:  "esc",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			out := t.TempDir()
			err := ExtractRPM(t.Context(), out, writeTemp(t, "pkg.rpm", tt.data))
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("ExtractRPM error: got = %v, want = error containing %q", err, tt.wantErr)
			}
			if tt.absent != "" {
				pkgsWantAbsent(t, filepath.Join(out, tt.absent))
			}
		})
	}
}

func TestExtractRPMInputs(t *testing.T) {
	t.Parallel()

	valid := pkgsRPM(pkgsCPIOFormat, pkgsGzip, pkgsCompress(t, pkgsGzip, pkgsCPIO(t, pkgsRPMLayout())))

	tests := []struct {
		name     string
		canceled bool
		data     []byte // nil leaves the package file missing
		wantErr  error
	}{
		{name: "canceled context extracts nothing", canceled: true, data: valid, wantErr: context.Canceled},
		{name: "empty file extracts nothing", data: []byte{}, wantErr: nil},
		{name: "missing file is reported", data: nil, wantErr: fs.ErrNotExist},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()
			if tt.canceled {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			dir := t.TempDir()
			src := filepath.Join(dir, "pkg.rpm")
			if tt.data != nil {
				if err := file.WriteFileIn(dir, "pkg.rpm", tt.data, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			out := t.TempDir()

			if err := ExtractRPM(ctx, out, src); !errors.Is(err, tt.wantErr) {
				t.Fatalf("ExtractRPM error: got = %v, want = %v", err, tt.wantErr)
			}
			entries, err := fs.ReadDir(openTestRoot(t, out).FS(), ".")
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 0 {
				t.Errorf("extracted entries: got = %d, want = 0", len(entries))
			}
		})
	}
}

func TestExtractRPMHardLinks(t *testing.T) {
	t.Parallel()

	const shared = "shared hard link content"
	tests := []struct {
		name    string
		entries []pkgsCPIOEntry
		want    map[string]string
		same    [][2]string
	}{
		{
			// newc writers such as GNU cpio store a hard link set's content
			// with its last member and leave the earlier members empty.
			name: "content stored with the last link reaches every link",
			entries: []pkgsCPIOEntry{
				{name: "./lib/a", mode: cpio.TypeReg | 0o644, links: 2, inode: 1000},
				{name: "./lib/b", mode: cpio.TypeReg | 0o644, body: shared, links: 2, inode: 1000},
			},
			want: map[string]string{"lib/a": shared, "lib/b": shared},
			same: [][2]string{{"lib/a", "lib/b"}},
		},
		{
			name: "content stored with the first link reaches every link",
			entries: []pkgsCPIOEntry{
				{name: "./lib/first", mode: cpio.TypeReg | 0o644, body: shared, links: 2, inode: 2000},
				{name: "./lib/second", mode: cpio.TypeReg | 0o644, links: 2, inode: 2000},
			},
			want: map[string]string{"lib/first": shared, "lib/second": shared},
			same: [][2]string{{"lib/first", "lib/second"}},
		},
		{
			name: "files sharing an inode number without hard links stay separate",
			entries: []pkgsCPIOEntry{
				{name: "./lib/one", mode: cpio.TypeReg | 0o644, body: "one", links: 1, inode: 3000},
				{name: "./lib/two", mode: cpio.TypeReg | 0o644, body: "two", links: 1, inode: 3000},
			},
			want: map[string]string{"lib/one": "one", "lib/two": "two"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			payload := pkgsCompress(t, pkgsGzip, pkgsCPIO(t, tt.entries))
			src := writeTemp(t, "pkg.rpm", pkgsRPM(pkgsCPIOFormat, pkgsGzip, payload))
			out := t.TempDir()

			if err := ExtractRPM(t.Context(), out, src); err != nil {
				t.Fatalf("ExtractRPM: %v", err)
			}
			for path, want := range tt.want {
				pkgsWantFile(t, filepath.Join(out, path), want)
			}
			for _, pair := range tt.same {
				pkgsWantSameFile(t, filepath.Join(out, pair[0]), filepath.Join(out, pair[1]))
			}
		})
	}
}

// pkgsShortReader returns at most limit bytes from each Read, as stream
// decompressors commonly do.
type pkgsShortReader struct {
	r     io.Reader
	limit int
}

func (s *pkgsShortReader) Read(p []byte) (int, error) {
	return s.r.Read(p[:min(len(p), s.limit)])
}

// TestExtractFileFromCPIOCancellation verifies that the member copy loop
// consults the context before every read, so cancellation takes effect even
// when reads return less than a full buffer.
func TestExtractFileFromCPIOCancellation(t *testing.T) {
	t.Parallel()

	body := pkgsNoise(3 * int(file.ExtractBuffer))
	payload := pkgsCPIO(t, []pkgsCPIOEntry{{name: "big.bin", mode: cpio.TypeReg | 0o600, body: string(body)}})
	// A read size that never sums to a multiple of the buffer within body.
	const shortRead = 1000

	tests := []struct {
		name     string
		readSize int // 0 lets each read fill the buffer
		allow    int64
		wantErr  error
		wantSize int64
	}{
		{
			name:     "cancellation before the first read writes nothing",
			allow:    0,
			wantErr:  context.Canceled,
			wantSize: 0,
		},
		{
			name:     "cancellation after one full read stops the copy",
			allow:    1,
			wantErr:  context.Canceled,
			wantSize: file.ExtractBuffer,
		},
		{
			name:     "cancellation after one short read stops the copy",
			readSize: shortRead,
			allow:    1,
			wantErr:  context.Canceled,
			wantSize: shortRead,
		},
		{
			name:     "live context copies the whole member through short reads",
			readSize: shortRead,
			allow:    math.MaxInt64,
			wantErr:  nil,
			wantSize: 3 * file.ExtractBuffer,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var src io.Reader = bytes.NewReader(payload)
			if tt.readSize > 0 {
				src = &pkgsShortReader{r: src, limit: tt.readSize}
			}
			cr := cpio.NewReader(src)
			if _, err := cr.Next(); err != nil {
				t.Fatalf("cpio Next: %v", err)
			}
			root := openTestRoot(t, t.TempDir())
			ctx := &pkgsCountdownContext{Context: t.Context(), allow: tt.allow}
			buf := make([]byte, file.ExtractBuffer)

			err := extractFileFromCPIO(ctx, cr, testEntryRoots(t, root), "big.bin", buf, nil)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("extractFileFromCPIO error: got = %v, want = %v", err, tt.wantErr)
			}
			fi, err := root.Stat("big.bin")
			if err != nil {
				t.Fatal(err)
			}
			if fi.Size() != tt.wantSize {
				t.Errorf("extracted size: got = %d, want = %d", fi.Size(), tt.wantSize)
			}
		})
	}
}

// TestExtractFileFromCPIOSingleByteReads verifies that reads returning a
// single byte each are all written, as a decompressor may return them.
func TestExtractFileFromCPIOSingleByteReads(t *testing.T) {
	t.Parallel()

	const body = "member read one byte at a time"
	payload := pkgsCPIO(t, []pkgsCPIOEntry{{name: "small.bin", mode: cpio.TypeReg | 0o600, body: body}})
	cr := cpio.NewReader(&pkgsShortReader{r: bytes.NewReader(payload), limit: 1})
	if _, err := cr.Next(); err != nil {
		t.Fatalf("cpio Next: %v", err)
	}
	dir := t.TempDir()

	if err := extractFileFromCPIO(t.Context(), cr, testEntryRoots(t, openTestRoot(t, dir)), "small.bin", make([]byte, file.ExtractBuffer), nil); err != nil {
		t.Fatalf("extractFileFromCPIO: %v", err)
	}
	pkgsWantFile(t, filepath.Join(dir, "small.bin"), body)
}
