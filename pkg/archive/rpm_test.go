// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cavaliergopher/cpio"
	"github.com/ulikunitz/xz/lzma"
)

// rpmTool is the member every payload fixture in this file holds.
const rpmTool = "#!/bin/sh\n# " + benignMarker + "\n"

func TestExtractRPMHardLinkSetsKeepEveryContent(t *testing.T) {
	t.Parallel()
	benign := strings.Repeat("B", len(benignMarker))
	payload := pkgsCompress(t, pkgsGzip, pkgsCPIO(t, []pkgsCPIOEntry{
		{name: "./usr/bin/tool", mode: cpio.TypeReg | 0o755, body: benignMarker, links: 2, inode: 7},
		{name: "./usr/share/doc/README", mode: cpio.TypeReg | 0o644, body: benign, links: 2, inode: 7},
	}))
	src := writeTemp(t, "pkg.rpm", pkgsRPM(pkgsCPIOFormat, pkgsGzip, payload))
	out := filepath.Join(t.TempDir(), "out")
	if err := ExtractRPM(t.Context(), out, src); err != nil {
		t.Fatalf("ExtractRPM: %v", err)
	}
	pkgsWantFile(t, filepath.Join(out, "usr/bin/tool"), benignMarker)
	pkgsWantFile(t, filepath.Join(out, "usr/share/doc/README"), benign)
}

func TestExtractRPMPayloadCompressors(t *testing.T) {
	t.Parallel()
	bz2, err := os.ReadFile(filepath.Join("testdata", "rpm-payload.cpio.bz2"))
	if err != nil {
		t.Fatal(err)
	}
	cpioData := pkgsCPIO(t, []pkgsCPIOEntry{{name: "./usr/bin/tool", mode: cpio.TypeReg | 0o755, body: rpmTool}})
	var lz bytes.Buffer
	lw, err := lzma.NewWriter(&lz)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = lw.Write(cpioData)
	if err := lw.Close(); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name, compressor string
		payload          []byte
	}{
		{name: "bzip2", compressor: "bzip2", payload: bz2},
		{name: "lzma", compressor: "lzma", payload: lz.Bytes()},
		{name: "empty compressor tag means gzip", compressor: "", payload: pkgsCompress(t, pkgsGzip, cpioData)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			src := writeTemp(t, "pkg.rpm", pkgsRPM(pkgsCPIOFormat, tt.compressor, tt.payload))
			out := filepath.Join(t.TempDir(), "out")
			if err := ExtractRPM(t.Context(), out, src); err != nil {
				t.Fatalf("ExtractRPM: %v", err)
			}
			pkgsWantFile(t, filepath.Join(out, "usr/bin/tool"), rpmTool)
		})
	}
}

func TestExtractRPMMembers(t *testing.T) {
	t.Parallel()
	full := pkgsCPIO(t, []pkgsCPIOEntry{{name: "./a", mode: cpio.TypeReg | 0o644, body: "a"}})
	tests := []struct {
		name    string
		cpio    []byte
		want    map[string]string
		wantErr bool
	}{
		{
			name: "member of an unknown type carrying data is written",
			// The writer adds the regular type to a mode with no type bits, so
			// the member names an unknown type instead.
			cpio: pkgsCPIO(t, []pkgsCPIOEntry{{name: "./odd", mode: cpio.FileMode(0o110644), body: benignMarker}, {name: "./fifo", mode: cpio.TypeFifo | 0o644}}),
			want: map[string]string{"odd": benignMarker},
		},
		{
			name: "names leaving the root are extracted beneath it",
			cpio: pkgsCPIO(t, []pkgsCPIOEntry{{name: "../escape", mode: cpio.TypeReg | 0o644, body: "x"}, {name: "/abs", mode: cpio.TypeReg | 0o644, body: "y"}}),
			want: map[string]string{"escape": "x", "abs": "y"},
		},
		{
			name: "symlink leaving the root is skipped",
			cpio: pkgsCPIO(t, []pkgsCPIOEntry{{name: "./esc", mode: cpio.TypeSymlink | 0o777, body: "../../outside"}, {name: "./kept", mode: cpio.TypeReg | 0o644, body: "k"}}),
			want: map[string]string{"kept": "k"},
		},
		{
			name:    "payload ending inside a header is an error",
			cpio:    full[:len(full)-60],
			want:    map[string]string{"a": "a"},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			src := writeTemp(t, "pkg.rpm", pkgsRPM(pkgsCPIOFormat, pkgsGzip, pkgsCompress(t, pkgsGzip, tt.cpio)))
			out := filepath.Join(t.TempDir(), "out")
			err := ExtractRPM(t.Context(), out, src)
			if (err != nil) != tt.wantErr {
				t.Errorf("ExtractRPM error: got = %v, want error = %v", err, tt.wantErr)
			}
			wantTree(t, out, tt.want)
		})
	}
}
