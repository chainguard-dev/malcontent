// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"archive/tar"
	"bytes"
	"errors"
	"fmt"
	"maps"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	zip "github.com/klauspost/compress/zip"
	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"
)

func TestExtractTarKeepsEntriesAfterAnUnusableOne(t *testing.T) {
	t.Parallel()
	first := tarSpecBytes(t, []tarSpec{{name: "a.txt", body: "first"}}, false)
	payload := tarSpecBytes(t, []tarSpec{{name: "payload.sh", body: benignMarker}}, true)
	kept := map[string]string{"a.txt": "first", "payload.sh": benignMarker}
	with := func(extra map[string]string) map[string]string {
		out := map[string]string{"a.txt": "first", "payload.sh": benignMarker}
		maps.Copy(out, extra)
		return out
	}

	tests := []struct {
		name    string
		between []byte
		want    map[string]string
		wantErr error
	}{
		{
			name: "no unusable entry",
			want: kept,
		},
		{
			name:    "name climbing above the root is extracted beneath it",
			between: tarSpecBytes(t, []tarSpec{{name: "../escape.txt", body: "x"}}, false),
			want:    with(map[string]string{"escape.txt": "x"}),
		},
		{
			name:    "absolute name is extracted beneath the root",
			between: tarSpecBytes(t, []tarSpec{{name: "/abs.txt", body: "x"}}, false),
			want:    with(map[string]string{"abs.txt": "x"}),
		},
		{
			name:    "element ending in dots is a name, not a climb",
			between: tarSpecBytes(t, []tarSpec{{name: "v1../notes.txt", body: "x"}}, false),
			want:    with(map[string]string{"v1..": "/", "v1../notes.txt": "x"}),
		},
		{
			name:    "symlink leaving the root is skipped",
			between: tarSpecBytes(t, []tarSpec{{name: "lnk", typeflag: tar.TypeSymlink, linkname: "../../outside"}}, false),
			want:    kept,
		},
		{
			name:    "file then a path beneath it gets a sibling directory",
			between: tarSpecBytes(t, []tarSpec{{name: "x", body: "file"}, {name: "x/y", body: "z"}}, false),
			want:    with(map[string]string{"x": "file", "x_1": "/", "x_1/y": "z"}),
		},
		{
			name:    "corrupt header block is skipped and the archive reported",
			between: bytes.Repeat([]byte{'Z'}, tarBlockSize),
			want:    kept,
			wantErr: ErrUnaccountedBytes,
		},
		{
			name:    "lone zero block before a header is skipped",
			between: make([]byte, tarBlockSize),
			want:    kept,
			wantErr: ErrUnaccountedBytes,
		},
		{
			name:    "header whose checksum matches but archive/tar rejects is skipped once",
			between: rejectedTarHeader(),
			want:    kept,
			wantErr: ErrUnaccountedBytes,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			src := writeTemp(t, "pkg.tar.gz", gzipBytes(t, slices.Concat(first, tt.between, payload)))
			out := filepath.Join(t.TempDir(), "out")
			err := ExtractTar(t.Context(), out, src)
			if tt.wantErr == nil && err != nil || tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Errorf("ExtractTar error: got = %v, want = %v", err, tt.wantErr)
			}
			wantTree(t, out, tt.want)
		})
	}
}

// rejectedTarHeader returns a header block whose checksum matches but whose
// size field holds a digit octal does not have, which archive/tar rejects.
func rejectedTarHeader() []byte {
	blk := rawTarHeader("bad", 0, tar.TypeReg)
	copy(blk[124:136], "99999999999\x00")
	for i := 148; i < 156; i++ {
		blk[i] = ' '
	}
	sum := 0
	for _, b := range blk {
		sum += int(b)
	}
	copy(blk[148:156], fmt.Sprintf("%06o\x00 ", sum))
	return blk
}

func TestExtractTarRejectsStreamsEndingInsideAHeader(t *testing.T) {
	t.Parallel()
	script := []byte("#!/bin/sh\n# " + benignMarker + "\n")
	entries := tarSpecBytes(t, []tarSpec{{name: "a.txt", body: "benign"}}, false)
	tests := []struct {
		name    string
		file    string
		data    []byte
		want    map[string]string
		wantErr bool
	}{
		{name: "small file that is no tar", file: "script.tar", data: script, want: map[string]string{}, wantErr: true},
		{name: "bytes after the last entry", file: "trailer.tar", data: slices.Concat(entries, script), want: map[string]string{"a.txt": "benign"}, wantErr: true},
		{name: "compressed bytes after the last entry", file: "trailer.tar.gz", data: gzipBytes(t, slices.Concat(entries, script)), want: map[string]string{"a.txt": "benign"}, wantErr: true},
		{name: "archive ending on a block boundary without its end marker", file: "plain.tar", data: entries, want: map[string]string{"a.txt": "benign"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			src := writeTemp(t, tt.file, tt.data)
			out := filepath.Join(t.TempDir(), "out")
			err := ExtractTar(t.Context(), out, src)
			if (err != nil) != tt.wantErr {
				t.Errorf("ExtractTar error: got = %v, want error = %v", err, tt.wantErr)
			}
			wantTree(t, out, tt.want)
			if tt.wantErr && !openTreeHas(t, src, benignMarker) && bytes.Contains(tt.data, []byte(benignMarker)) {
				t.Errorf("OpenTree: the archive did not stay in the scan corpus")
			}
		})
	}
}

// openTreeHas reports whether the tree OpenTree extracts from src holds
// marker in any file.
func openTreeHas(t *testing.T, src, marker string) bool {
	t.Helper()
	tree, err := OpenTree(t.Context(), malcontent.Config{}, src)
	if err != nil {
		t.Fatalf("OpenTree: %v", err)
	}
	defer tree.Close()
	return corpusContains(t, tree.Dir(), marker)
}

func TestExtractTarNeverReplacesEntries(t *testing.T) {
	benign := strings.Repeat("B", len(benignMarker))
	tests := []struct {
		name    string
		fold    bool
		entries []tarSpec
		want    map[string]string
		same    [2]string
	}{
		{
			name: "file named like an earlier hard link keeps the linked file",
			entries: []tarSpec{
				{name: "a.sh", body: benignMarker},
				{name: "b.sh", typeflag: tar.TypeLink, linkname: "a.sh"},
				{name: "b.sh", body: benign},
			},
			want: map[string]string{"a.sh": benignMarker, "b.sh": benignMarker, "b_1.sh": benign},
			same: [2]string{"a.sh", "b.sh"},
		},
		{
			name:    "duplicate names keep both contents",
			entries: []tarSpec{{name: "dup.sh", body: "one"}, {name: "dup.sh", body: "two"}},
			want:    map[string]string{"dup.sh": "one", "dup_1.sh": "two"},
		},
		{
			name:    "names differing only in case keep both contents where case folds",
			fold:    true,
			entries: []tarSpec{{name: "Run.sh", body: benignMarker}, {name: "run.sh", body: benign}},
			want:    map[string]string{"Run.sh": benignMarker, "run_1.sh": benign},
		},
		{
			name:    "symlink named like an earlier file keeps the file",
			entries: []tarSpec{{name: "f.txt", body: "data"}, {name: "f.txt", typeflag: tar.TypeSymlink, linkname: "g"}},
			want:    map[string]string{"f.txt": "data", "f_1.txt": "-> g"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withCaseFolding(t, tt.fold || caseInsensitiveFS)
			src := writeTemp(t, "x.tar", tarSpecBytes(t, tt.entries, true))
			out := filepath.Join(t.TempDir(), "out")
			if err := ExtractTar(t.Context(), out, src); err != nil {
				t.Fatalf("ExtractTar: %v", err)
			}
			wantTree(t, out, tt.want)
			if tt.same[0] != "" {
				pkgsWantSameFile(t, filepath.Join(out, tt.same[0]), filepath.Join(out, tt.same[1]))
			}
		})
	}
}

// TestExtractTarSymlinkedDirectories covers entries beneath a symlinked
// directory. bsdtar refuses to extract through the link and drops such an
// entry; GNU tar follows the link. Extraction follows a link that stays
// beneath the root and leads to a directory, and otherwise writes the entry
// in a sibling directory, so its content is never lost.
func TestExtractTarSymlinkedDirectories(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		entries []tarSpec
		want    map[string]string
	}{
		{
			name: "entry beneath a link to a directory lands where the link leads",
			entries: []tarSpec{
				{name: "usr/lib/", typeflag: tar.TypeDir},
				{name: "lib", typeflag: tar.TypeSymlink, linkname: "usr/lib"},
				{name: "lib/x", body: "payload"},
			},
			want: map[string]string{"usr": "/", "usr/lib": "/", "usr/lib/x": "payload", "lib": "-> usr/lib"},
		},
		{
			name: "link named like a directory holding entries gets a sibling name",
			entries: []tarSpec{
				{name: "lib/x", body: "payload"},
				{name: "lib", typeflag: tar.TypeSymlink, linkname: "usr/lib"},
			},
			want: map[string]string{"lib": "/", "lib/x": "payload", "lib_1": "-> usr/lib"},
		},
		{
			name: "entry beneath a dangling link gets a sibling directory",
			entries: []tarSpec{
				{name: "lib", typeflag: tar.TypeSymlink, linkname: "usr/lib"},
				{name: "lib/x", body: "payload"},
			},
			want: map[string]string{"lib": "-> usr/lib", "lib_1": "/", "lib_1/x": "payload"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			src := writeTemp(t, "x.tar", tarSpecBytes(t, tt.entries, true))
			out := filepath.Join(t.TempDir(), "out")
			if err := ExtractTar(t.Context(), out, src); err != nil {
				t.Fatalf("ExtractTar: %v", err)
			}
			wantTree(t, out, tt.want)
		})
	}
}

func TestExtractTarWritesPAXCommentsToSidecar(t *testing.T) {
	t.Parallel()
	comment := map[string]string{"comment": benignMarker}
	tests := []struct {
		name    string
		entries []tarSpec
		want    map[string]string
	}{
		{
			name:    "comment record is written to the sidecar",
			entries: []tarSpec{{name: "a.txt", body: "a", pax: comment}},
			want:    map[string]string{"a.txt": "a", "malcontent-metadata.bin": `tar entry "a.txt" comment: ` + benignMarker + "\n"},
		},
		{
			name:    "no comment writes no sidecar",
			entries: []tarSpec{{name: "a.txt", body: "a", pax: map[string]string{"SCHILY.fflags": "nodump"}}},
			want:    map[string]string{"a.txt": "a"},
		},
		{
			name:    "entry named like the sidecar keeps its name",
			entries: []tarSpec{{name: "malcontent-metadata.bin", body: "real", pax: comment}},
			want: map[string]string{
				"malcontent-metadata.bin":   "real",
				"malcontent-metadata_1.bin": `tar entry "malcontent-metadata.bin" comment: ` + benignMarker + "\n",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			src := writeTemp(t, "x.tar", tarSpecBytes(t, tt.entries, true))
			out := filepath.Join(t.TempDir(), "out")
			if err := ExtractTar(t.Context(), out, src); err != nil {
				t.Fatalf("ExtractTar: %v", err)
			}
			wantTree(t, out, tt.want)
		})
	}
}

func TestExtractTarDecompressesByContent(t *testing.T) {
	t.Parallel()
	tarData := tarSpecBytes(t, []tarSpec{{name: "payload.sh", body: benignMarker}}, true)
	var xzBuf bytes.Buffer
	xw, err := xz.NewWriter(&xzBuf)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = xw.Write(tarData)
	if err := xw.Close(); err != nil {
		t.Fatal(err)
	}
	enc, err := zstd.NewWriter(nil)
	if err != nil {
		t.Fatal(err)
	}
	zstdData := enc.EncodeAll(tarData, nil)
	_ = enc.Close()

	tests := []struct {
		name string
		file string
		data []byte
		want map[string]string
	}{
		{name: "gzip content named as a plain tar", file: "pkg.tar", data: gzipBytes(t, tarData), want: map[string]string{"payload.sh": benignMarker}},
		{name: "xz content named as a gzip tar", file: "pkg.tar.gz", data: xzBuf.Bytes(), want: map[string]string{"payload.sh": benignMarker}},
		{name: "zstd content named as a plain tar", file: "pkg.tar", data: zstdData, want: map[string]string{"payload.sh": benignMarker}},
		{name: "plain tar named as a gzip tar", file: "pkg.tgz", data: tarData, want: map[string]string{"payload.sh": benignMarker}},
		{
			name: "zip named as an Alpine package, as Android packages are",
			file: "app.apk",
			data: zipSpecBytes(t, zip.Deflate, []zipSpecEntry{{name: "classes.dex", body: benignMarker}}),
			want: map[string]string{"classes.dex": benignMarker},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			src := writeTemp(t, tt.file, tt.data)
			out := filepath.Join(t.TempDir(), "out")
			if err := ExtractTar(t.Context(), out, src); err != nil {
				t.Fatalf("ExtractTar: %v", err)
			}
			wantTree(t, out, tt.want)
		})
	}
}
