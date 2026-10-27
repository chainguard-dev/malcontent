// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"archive/tar"
	"bytes"
	"maps"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ulikunitz/xz"
)

func TestExtractDebExtractsEveryMember(t *testing.T) {
	t.Parallel()
	control := gzipBytes(t, tarWithEntry(t, "./control", pkgsDebControl))
	scripts := gzipBytes(t, tarSpecBytes(t, []tarSpec{
		{name: "./control", body: pkgsDebControl},
		{name: "./postinst", body: "#!/bin/sh\n# " + benignMarker + "\n"},
	}, true))
	data := func(body string) []byte {
		return gzipBytes(t, tarWithEntry(t, "./usr/bin/tool", body))
	}
	var xzData bytes.Buffer
	xw, err := xz.NewWriter(&xzData)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = xw.Write(tarWithEntry(t, "./usr/bin/tool", "second"))
	if err := xw.Close(); err != nil {
		t.Fatal(err)
	}
	binary := arMember{"debian-binary", []byte("2.0\n")}
	tool := map[string]string{"usr": "/", "usr/bin": "/", "usr/bin/tool": "first"}
	with := func(extra map[string]string) map[string]string {
		out := map[string]string{"control": "/", "control/control": pkgsDebControl}
		maps.Copy(out, tool)
		maps.Copy(out, extra)
		return out
	}

	tests := []struct {
		name    string
		members []arMember
		want    map[string]string
	}{
		{
			name:    "maintainer scripts are extracted into control",
			members: []arMember{binary, {"control.tar.gz", scripts}, {"data.tar.gz", data("first")}},
			want:    with(map[string]string{"control/postinst": "#!/bin/sh\n# " + benignMarker + "\n"}),
		},
		{
			name:    "second data member of one name goes to a sibling directory",
			members: []arMember{binary, {"control.tar.gz", control}, {"data.tar.gz", data("first")}, {"data.tar.gz", data(benignMarker)}},
			want:    with(map[string]string{"data_1": "/", "data_1/usr": "/", "data_1/usr/bin": "/", "data_1/usr/bin/tool": benignMarker}),
		},
		{
			name:    "second data member of another compression goes to a sibling directory",
			members: []arMember{binary, {"control.tar.gz", control}, {"data.tar.gz", data("first")}, {"data.tar.xz", xzData.Bytes()}},
			want:    with(map[string]string{"data_1": "/", "data_1/usr": "/", "data_1/usr/bin": "/", "data_1/usr/bin/tool": "second"}),
		},
		{
			name:    "member that is no tarball is written as a file",
			members: []arMember{binary, {"control.tar.gz", control}, {"data.tar.gz", data("first")}, {"_extra", []byte(benignMarker)}},
			want:    with(map[string]string{"_extra": benignMarker}),
		},
		{
			name:    "debian-binary holding more than the format version is written",
			members: []arMember{{"debian-binary", []byte("2.0\n" + benignMarker)}, {"control.tar.gz", control}, {"data.tar.gz", data("first")}},
			want:    with(map[string]string{"debian-binary": "2.0\n" + benignMarker}),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			src := writeTemp(t, "pkg.deb", arBytes(tt.members))
			out := filepath.Join(t.TempDir(), "out")
			if err := ExtractDeb(t.Context(), out, src); err != nil {
				t.Fatalf("ExtractDeb: %v", err)
			}
			wantTree(t, out, tt.want)
		})
	}
}

func TestExtractDebDataEntryTypes(t *testing.T) {
	t.Parallel()
	benign := strings.Repeat("B", len(benignMarker))
	tests := []struct {
		name    string
		entries []tarEntry
		raw     []tarSpec
		want    map[string]string
	}{
		{
			name: "file named like an earlier hard link keeps the linked file",
			entries: []tarEntry{
				{name: "./a.sh", typeflag: tar.TypeReg, body: benignMarker},
				{name: "./b.sh", typeflag: tar.TypeLink, linkname: "./a.sh"},
				{name: "./b.sh", typeflag: tar.TypeReg, body: benign},
			},
			want: map[string]string{"a.sh": benignMarker, "b.sh": benignMarker, "b_1.sh": benign},
		},
		{
			name: "contiguous and unknown typeflags carrying data are written as files",
			raw: []tarSpec{
				{name: "./cont.bin", typeflag: tar.TypeCont, body: benignMarker},
				{name: "./odd.bin", typeflag: 'Z', body: benign},
				{name: "./fifo", typeflag: tar.TypeFifo},
			},
			want: map[string]string{"cont.bin": benignMarker, "odd.bin": benign},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var src string
			if tt.raw != nil {
				src = writeTemp(t, "pkg.deb", arBytes([]arMember{
					{"debian-binary", []byte("2.0\n")},
					{"control.tar.gz", gzipBytes(t, tarWithEntry(t, "./control", pkgsDebControl))},
					{"data.tar.gz", gzipBytes(t, tarSpecBytes(t, tt.raw, true))},
				}))
			} else {
				src = pkgsDeb(t, tt.entries)
			}
			out := filepath.Join(t.TempDir(), "out")
			if err := ExtractDeb(t.Context(), out, src); err != nil {
				t.Fatalf("ExtractDeb: %v", err)
			}
			got := treeContents(t, out)
			for _, k := range []string{"control", "control/control"} {
				delete(got, k)
			}
			for k, v := range tt.want {
				if got[k] != v {
					t.Errorf("%s: got = %q, want = %q", k, got[k], v)
				}
			}
			if len(got) != len(tt.want) {
				t.Errorf("tree: got = %q, want = %q besides control", got, tt.want)
			}
		})
	}
}
