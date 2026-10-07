// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package programkind

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io/fs"
	"path/filepath"
	"slices"
	"testing"

	"github.com/chainguard-dev/malcontent/pkg/file"
	"github.com/google/go-cmp/cmp"
)

// zipArchive returns a small zip archive of text members.
func zipArchive(tb testing.TB) []byte {
	tb.Helper()
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	for i := range 8 {
		w, err := zw.Create(fmt.Sprintf("dir/member%d.txt", i))
		if err != nil {
			tb.Fatalf("create zip member: %v", err)
		}
		if _, err := w.Write(bytes.Repeat([]byte("zip member payload\n"), 256)); err != nil {
			tb.Fatalf("write zip member: %v", err)
		}
	}
	if err := zw.Close(); err != nil {
		tb.Fatalf("close zip archive: %v", err)
	}
	return b.Bytes()
}

// androidPackage returns a zip archive whose classes.dex entry, which marks
// an Android package, follows a stored entry of lead bytes.
func androidPackage(t *testing.T, lead int) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	if lead > 0 {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: "assets/blob", Method: zip.Store})
		if err != nil {
			t.Fatalf("create stored zip member: %v", err)
		}
		if _, err := w.Write(bytes.Repeat([]byte("a"), lead)); err != nil {
			t.Fatalf("write stored zip member: %v", err)
		}
	}
	w, err := zw.Create("classes.dex")
	if err != nil {
		t.Fatalf("create classes.dex: %v", err)
	}
	if _, err := w.Write([]byte("dex\n035\x00")); err != nil {
		t.Fatalf("write classes.dex: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip archive: %v", err)
	}
	return b.Bytes()
}

// jsonDocument returns a JSON document of roughly 64 KiB.
func jsonDocument() []byte {
	var b bytes.Buffer
	b.WriteString(`{"items": [`)
	for i := range 1500 {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, `{"id": %d, "name": "item-%d", "ok": true}`, i, i)
	}
	b.WriteString("]}\n")
	return b.Bytes()
}

// detectFixture names a file for the detection equivalence tests.
type detectFixture struct {
	name string
	path string
}

// detectFixtures returns every non-empty file under testdata and generated
// files covering each detection branch, including files of several MiB. None
// holds the UPX marker, so detecting them never runs a UPX binary.
func detectFixtures(t *testing.T) []detectFixture {
	t.Helper()
	fixtures := make([]detectFixture, 0, 64)
	err := fs.WalkDir(programkindRoot(t, "testdata").FS(), ".", func(rel string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		path := filepath.Join("testdata", filepath.FromSlash(rel))
		info, err := d.Info()
		if err != nil {
			return err
		}
		if info.Mode().IsRegular() && info.Size() > 0 {
			fixtures = append(fixtures, detectFixture{name: path, path: path})
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk testdata: %v", err)
	}

	elf := append([]byte{0x7f, 'E', 'L', 'F', 0x02, 0x01, 0x01, 0x00}, make([]byte, 120)...)
	binaryPHP := append([]byte{0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15}, "<?php echo 1; ?>\n"...)
	requireJS := []byte("const fs = require('fs');\n")
	largeScript := bytes.Repeat([]byte("echo large\n"), 4<<20/11)
	largeBinary := append(bytes.Repeat([]byte{0x00, 0x01, 0x02, 0x03}, 1<<20), "<?php echo 1; ?>"...)
	archive := zipArchive(t)
	generated := []struct {
		rel     string
		content []byte
	}{
		{"gzip/payload", gzipStream(t, []byte("gzip payload\n"))},
		{"gzip/payload.bin", gzipStream(t, []byte("gzip payload\n"))},
		{"zlib/stream", zlibStream(t, zlibPayload, 6)},
		{"zlib/noise", zlibNoise(1024)},
		{"php/blob.q", binaryPHP},
		{"php/blob.qz", binaryPHP},
		{"php/app-1.2.3", []byte("<?php echo 1; ?>\n")},
		{"js/loader.qz", requireJS},
		{"js/dist/tool.js", []byte("#!/bin/sh\nset -e\n")},
		{"usr/share/man/man1/loader.1", requireJS},
		{"json/package.json", []byte(`{"name": "fixture"}` + "\n")},
		{"json/data.json", jsonDocument()},
		{"yaml/pnpm-lock.yaml", []byte("lockfileVersion: '9.0'\n")},
		{"script/tool", []byte("#!/usr/bin/env node\nconsole.log(1)\n")},
		{"script/run", []byte("set -e\nexport PATH=/bin\n")},
		{"python/tool", []byte("import os\nprint(os.getcwd())\n")},
		{"c/header", []byte("#include <stdio.h>\n")},
		{"beam/module", []byte("FOR1\x00\x00\x00\x40BEAMAtU8\x00\x00\x00\x10")},
		{"zip/bundle.zip", archive},
		{"zip/bundle", archive},
		{"elf/program", elf},
		{"elf/lib/libfoo.so.1", elf},
		{"text/notes.txt", []byte("plain text notes\n")},
		{"text/notes", []byte("plain text notes\n")},
		{"large/big.sh", largeScript},
		{"large/big", largeBinary},
	}
	dir := t.TempDir()
	r := programkindRoot(t, dir)
	for _, g := range generated {
		p := filepath.Join(dir, g.rel)
		if err := r.MkdirAll(filepath.Dir(g.rel), 0o700); err != nil {
			t.Fatalf("MkdirAll(%q): %v", filepath.Dir(p), err)
		}
		if err := r.WriteFile(g.rel, g.content, 0o600); err != nil {
			t.Fatalf("WriteFile(%q): %v", p, err)
		}
		fixtures = append(fixtures, detectFixture{name: g.rel, path: p})
	}
	return fixtures
}

func TestDetectMatchesFile(t *testing.T) {
	t.Parallel()
	for _, fx := range detectFixtures(t) {
		t.Run(fx.name, func(t *testing.T) {
			t.Parallel()
			path := fx.path
			want, err := File(t.Context(), path)
			if err != nil {
				t.Fatalf("File(%q) error: %v", path, err)
			}
			fc, err := file.ReadFile(path)
			if err != nil {
				t.Fatalf("ReadFile(%q): %v", path, err)
			}
			if diff := cmp.Diff(want, Detect(t.Context(), path, fc)); diff != "" {
				t.Errorf("Detect(%q) differs from File (-File +Detect):\n%s", path, diff)
			}
		})
	}
}

func TestIsSupportedArchiveKindMatchesIsSupportedArchive(t *testing.T) {
	t.Parallel()
	for _, fx := range detectFixtures(t) {
		t.Run(fx.name, func(t *testing.T) {
			t.Parallel()
			path := fx.path
			kind, err := File(t.Context(), path)
			if err != nil {
				t.Fatalf("File(%q) error: %v", path, err)
			}
			want := IsSupportedArchive(t.Context(), path)
			if got := IsSupportedArchiveKind(path, kind); got != want {
				t.Errorf("IsSupportedArchiveKind(%q, %+v): got = %v, want = %v (IsSupportedArchive)", path, kind, got, want)
			}
		})
	}
}

func TestIsSupportedArchiveKind(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		path string
		ft   *FileType
		want bool
	}{
		{"archive extension without a kind", "bundle.zip", nil, true},
		{"versioned archive extension", "pkg-1.2.3.tar.gz", nil, true},
		{"archive extension with a program kind", "tool.jar", &FileType{Ext: "elf", MIME: "application/x-elf"}, true},
		{"UPX content under any name", "tool", &FileType{Ext: "upx", MIME: "application/x-upx"}, true},
		{"gzip content under any name", "payload", &FileType{Ext: "gz", MIME: "application/gzip"}, true},
		{"zlib content under any name", "stream", &FileType{Ext: "Z", MIME: "application/zlib"}, true},
		{"program content without an archive extension", "tool", &FileType{Ext: "elf", MIME: "application/x-elf"}, false},
		{"script without an archive extension", "run.sh", &FileType{Ext: "sh", MIME: mimeShellScript}, false},
		{"no kind and no archive extension", "notes", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := IsSupportedArchiveKind(tt.path, tt.ft); got != tt.want {
				t.Errorf("IsSupportedArchiveKind(%q, %+v): got = %v, want = %v", tt.path, tt.ft, got, tt.want)
			}
		})
	}
}

func TestDetectReadsArchiveEntriesPastTheFirstBlock(t *testing.T) {
	t.Parallel()
	apk := &FileType{Ext: "apk", MIME: "application/vnd.android.package-archive"}
	tests := []struct {
		name    string
		content []byte
		want    *FileType
	}{
		{"Android package with classes.dex first", androidPackage(t, 0), apk},
		// The classes.dex entry begins past the first 8 KiB, beyond the
		// 4 KiB that MIME detection examines by default.
		{"Android package with classes.dex past the first 8 KiB", androidPackage(t, 8<<10), apk},
		{"zip archive without Android entries", zipArchive(t), &FileType{Ext: "zip", MIME: "application/zip"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if diff := cmp.Diff(tt.want, Detect(t.Context(), "bundle.zip", tt.content)); diff != "" {
				t.Errorf("Detect(%q) mismatch (-want +got):\n%s", "bundle.zip", diff)
			}
		})
	}
}

func TestDetectExaminesOnlyTheLeadingBytes(t *testing.T) {
	// Not parallel: it lowers the package detection limit, which stands in
	// for file.MaxBytes so the test needs no 4 GiB input.
	prev := detectLimit
	detectLimit = 16
	t.Cleanup(func() { detectLimit = prev })

	php := []byte("<?php echo 1; ?>\n")
	binaryHead := []byte{0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d}
	tests := []struct {
		name    string
		content []byte
		want    *FileType
	}{
		{"marker within the limit is seen", php, &FileType{Ext: "php", MIME: "text/x-php"}},
		{"marker past the limit is not seen", slices.Concat(binaryHead, php), nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if diff := cmp.Diff(tt.want, Detect(t.Context(), "blob.q", tt.content)); diff != "" {
				t.Errorf("Detect() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
