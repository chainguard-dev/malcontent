// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"

	"github.com/chainguard-dev/malcontent/pkg/file"
)

const (
	pkgsDebTool    = "#!/bin/sh\necho deb tool\n"
	pkgsDebControl = "Package: pkgs-test\nVersion: 1.0\nArchitecture: all\nMaintainer: Test <test@example.com>\nDescription: test package\n"
)

// pkgsDeb writes a .deb whose gzip-compressed data archive holds entries and
// returns its path.
func pkgsDeb(t *testing.T, entries []tarEntry) string {
	t.Helper()
	tarPath := writeTar(t, entries)
	data, err := file.ReadFileIn(filepath.Dir(tarPath), filepath.Base(tarPath))
	if err != nil {
		t.Fatal(err)
	}

	var b bytes.Buffer
	b.WriteString("!<arch>\n")
	for _, m := range []struct {
		name string
		body []byte
	}{
		{name: "debian-binary", body: []byte("2.0\n")},
		{name: "control.tar.gz", body: gzipBytes(t, tarWithEntry(t, "./control", pkgsDebControl))},
		{name: "data.tar.gz", body: gzipBytes(t, data)},
	} {
		// ar member header: name, mtime, uid, gid, mode, size, terminator.
		fmt.Fprintf(&b, "%-16s%-12s%-6s%-6s%-8s%-10d`\n", m.name, "0", "0", "0", "100644", len(m.body))
		b.Write(m.body)
		if len(m.body)%2 == 1 {
			b.WriteByte('\n')
		}
	}
	return writeTemp(t, "pkg.deb", b.Bytes())
}

func TestExtractDebLayout(t *testing.T) {
	t.Parallel()

	src := pkgsDeb(t, []tarEntry{
		{name: "./usr/", typeflag: tar.TypeDir},
		{name: "./usr/bin/", typeflag: tar.TypeDir},
		{name: "./usr/bin/tool", typeflag: tar.TypeReg, body: pkgsDebTool},
		{name: "./usr/bin/link", typeflag: tar.TypeSymlink, linkname: "tool"},
		{name: "./usr/bin/hard", typeflag: tar.TypeLink, linkname: "./usr/bin/tool"},
	})
	out := t.TempDir()

	if err := ExtractDeb(t.Context(), out, src); err != nil {
		t.Fatalf("ExtractDeb: %v", err)
	}
	bin := filepath.Join(out, "usr", "bin")
	pkgsWantFile(t, filepath.Join(bin, "tool"), pkgsDebTool)
	pkgsWantSymlink(t, filepath.Join(bin, "link"), "tool")
	pkgsWantSameFile(t, filepath.Join(bin, "tool"), filepath.Join(bin, "hard"))
}

func TestExtractDebRejectsUnsafeEntries(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		entries []tarEntry
		wantErr string
		absent  string
	}{
		{
			name:    "absolute member path",
			entries: []tarEntry{{name: "/etc/evil", typeflag: tar.TypeReg, body: "evil"}},
			wantErr: "path is absolute",
			absent:  filepath.Join("etc", "evil"),
		},
		{
			name:    "member path climbing out of the directory",
			entries: []tarEntry{{name: "../evil", typeflag: tar.TypeReg, body: "evil"}},
			wantErr: "relative path traversal",
		},
		{
			name:    "symlink escaping the directory",
			entries: []tarEntry{{name: "./esc", typeflag: tar.TypeSymlink, linkname: "../../outside"}},
			wantErr: "failed to create symlink",
			absent:  "esc",
		},
		{
			name:    "hardlink to a file outside the directory",
			entries: []tarEntry{{name: "./hard", typeflag: tar.TypeLink, linkname: "../outside"}},
			wantErr: "failed to create hardlink",
			absent:  "hard",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			out := t.TempDir()
			err := ExtractDeb(t.Context(), out, pkgsDeb(t, tt.entries))
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("ExtractDeb error: got = %v, want = error containing %q", err, tt.wantErr)
			}
			if tt.absent != "" {
				pkgsWantAbsent(t, filepath.Join(out, tt.absent))
			}
		})
	}
}

func TestExtractDebInputs(t *testing.T) {
	t.Parallel()

	valid := pkgsDeb(t, []tarEntry{{name: "./tool", typeflag: tar.TypeReg, body: pkgsDebTool}})
	notDeb := writeTemp(t, "bad.deb", []byte("not a deb archive"))
	missing := filepath.Join(t.TempDir(), "missing.deb")

	tests := []struct {
		name     string
		canceled bool
		src      string
		wantErr  error
		wantMsg  string
	}{
		{name: "canceled context extracts nothing", canceled: true, src: valid, wantErr: context.Canceled},
		{name: "missing file is reported", src: missing, wantErr: fs.ErrNotExist},
		{name: "file that is not a deb", src: notDeb, wantMsg: "failed to load file"},
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
			out := t.TempDir()

			err := ExtractDeb(ctx, out, tt.src)
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Fatalf("ExtractDeb error: got = %v, want = %v", err, tt.wantErr)
			}
			if tt.wantMsg != "" && (err == nil || !strings.Contains(err.Error(), tt.wantMsg)) {
				t.Fatalf("ExtractDeb error: got = %v, want = error containing %q", err, tt.wantMsg)
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
