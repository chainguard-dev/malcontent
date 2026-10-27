// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"archive/tar"
	"context"
	"errors"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cavaliergopher/cpio"
	"github.com/chainguard-dev/malcontent/pkg/file"
)

// entryRootsTestTree returns a directory holding dir/existing (a file),
// dir/link (a symlink to it), and leaf (a file), as an extraction may have
// left them.
func entryRootsTestTree(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	for name, body := range map[string]string{filepath.Join("dir", "existing"): "old", "leaf": "leaf"} {
		if err := file.MkdirAllIn(d, filepath.Dir(name), 0o700); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := file.WriteFileIn(d, name, []byte(body), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	if err := openTestRoot(t, d).Symlink("existing", filepath.Join("dir", "link")); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	return d
}

// entryRootsTreeState describes every entry beneath d: its type and, for a
// file, its contents.
func entryRootsTreeState(t *testing.T, d string) []string {
	t.Helper()
	r := openTestRoot(t, d)
	var state []string
	if err := file.WalkDir(r, ".", func(path string, e fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		desc := path + " " + e.Type().String()
		if e.Type().IsRegular() {
			body, err := r.ReadFile(path)
			if err != nil {
				return err
			}
			desc += " " + string(body)
		}
		state = append(state, desc)
		return nil
	}); err != nil {
		t.Fatalf("walk %s: %v", d, err)
	}
	return state
}

func TestEntryRootsOpenExclusiveNeverReplaces(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		path    string
		wantErr error
		anyErr  bool // any error will do
	}{
		{name: "new file in an existing directory", path: filepath.Join("dir", "new")},
		{name: "new file in new directories", path: filepath.Join("x", "y", "z", "new")},
		{name: "new file in the root", path: "new"},
		{name: "existing file is kept", path: filepath.Join("dir", "existing"), wantErr: fs.ErrExist},
		{name: "existing symlink is kept", path: filepath.Join("dir", "link"), wantErr: fs.ErrExist},
		{name: "beneath a file", path: filepath.Join("leaf", "new"), anyErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			d := entryRootsTestTree(t)
			before := entryRootsTreeState(t, d)
			er := testEntryRoots(t, openTestRoot(t, d))
			f, err := er.openExclusive(tt.path)
			if f != nil {
				_ = f.Close()
			}
			wantErr := tt.wantErr != nil || tt.anyErr
			if wantErr != (err != nil) || tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Fatalf("openExclusive(%q) error: got = %v, want = %v", tt.path, err, tt.wantErr)
			}
			if wantErr {
				if after := entryRootsTreeState(t, d); strings.Join(after, "\n") != strings.Join(before, "\n") {
					t.Errorf("tree after a refused openExclusive(%q): got = %q, want = %q", tt.path, after, before)
				}
			}
		})
	}
}

func TestExtractTarKeepsEntriesNamedLikeEarlierOnes(t *testing.T) {
	t.Parallel()
	// "link/a" is written through the symlink; the regular file "link" takes
	// a sibling name rather than replacing it, so "link/b" is written through
	// the symlink too.
	archive := writeTar(t, []tarEntry{
		{name: "real/", typeflag: tar.TypeDir},
		{name: "link", typeflag: tar.TypeSymlink, linkname: "real"},
		{name: "link/a", typeflag: tar.TypeReg, body: "a"},
		{name: "link", typeflag: tar.TypeReg, body: "file"},
		{name: "link/b", typeflag: tar.TypeReg, body: "b"},
	})
	d := t.TempDir()
	if err := ExtractTar(t.Context(), d, archive); err != nil {
		t.Fatalf("ExtractTar error: got = %v, want = nil", err)
	}
	wantTree(t, d, map[string]string{"real": "/", "real/a": "a", "real/b": "b", "link": "-> real", "link_1": "file"})
}

// entryRootsLinkCases are archive layouts in which an entry is named like an
// earlier link that files were written through. The later entry takes a
// sibling name, so the link, and every file written through it, stays.
var entryRootsLinkCases = []struct {
	name    string
	entries []tarEntry
	want    []string // entries, beneath the extraction directory, that must exist
}{
	{
		name: "second symlink of one name",
		entries: []tarEntry{
			{name: "real1/", typeflag: tar.TypeDir},
			{name: "real2/", typeflag: tar.TypeDir},
			{name: "link", typeflag: tar.TypeSymlink, linkname: "real1"},
			{name: "link/a", typeflag: tar.TypeReg, body: "a"},
			{name: "link", typeflag: tar.TypeSymlink, linkname: "real2"},
			{name: "link/b", typeflag: tar.TypeReg, body: "b"},
		},
		want: []string{filepath.Join("real1", "a"), filepath.Join("real1", "b"), "link_1"},
	},
	{
		name: "hard link named like a symlink",
		entries: []tarEntry{
			{name: "real1/", typeflag: tar.TypeDir},
			{name: "target", typeflag: tar.TypeReg, body: "t"},
			{name: "link", typeflag: tar.TypeSymlink, linkname: "real1"},
			{name: "link/a", typeflag: tar.TypeReg, body: "a"},
			{name: "link", typeflag: tar.TypeLink, linkname: "target"},
			{name: "link/b", typeflag: tar.TypeReg, body: "b"},
		},
		want: []string{filepath.Join("real1", "a"), filepath.Join("real1", "b"), "link_1"},
	},
}

func TestExtractKeepsLinksNamedLikeLaterEntries(t *testing.T) {
	t.Parallel()
	formats := []struct {
		name    string
		extract func(ctx context.Context, d, f string) error
		archive func(t *testing.T, entries []tarEntry) string
	}{
		{name: "tar", extract: ExtractTar, archive: writeTar},
		{name: "deb", extract: ExtractDeb, archive: pkgsDeb},
		{name: "rpm", extract: ExtractRPM, archive: entryRootsRPM},
	}
	for _, format := range formats {
		for _, tt := range entryRootsLinkCases {
			t.Run(format.name+"/"+tt.name, func(t *testing.T) {
				t.Parallel()
				d := t.TempDir()
				if err := format.extract(t.Context(), d, format.archive(t, tt.entries)); err != nil {
					t.Errorf("extract error: got = %v, want = nil", err)
				}
				for _, name := range tt.want {
					if _, err := file.LstatIn(d, name); err != nil {
						t.Errorf("%s: got err = %v, want it written", name, err)
					}
				}
			})
		}
	}
}

// entryRootsRPM writes an RPM whose payload holds entries as cpio members, a
// hard link as a second, empty member sharing its target's inode, and
// returns its path.
func entryRootsRPM(t *testing.T, entries []tarEntry) string {
	t.Helper()
	members := make([]pkgsCPIOEntry, 0, len(entries))
	inodes := map[string]int64{}
	for i, e := range entries {
		m := pkgsCPIOEntry{name: "./" + strings.TrimSuffix(e.name, "/"), inode: int64(i + 1)}
		switch e.typeflag {
		case tar.TypeDir:
			m.mode = cpio.TypeDir | 0o755
		case tar.TypeSymlink:
			m.mode, m.body = cpio.TypeSymlink|0o777, e.linkname
		case tar.TypeLink:
			m.mode, m.links, m.inode = cpio.TypeReg|0o644, 2, inodes[e.linkname]
		default:
			m.mode, m.body, m.links = cpio.TypeReg|0o644, e.body, 2
			inodes[e.name] = m.inode
		}
		members = append(members, m)
	}
	payload := pkgsCompress(t, pkgsGzip, pkgsCPIO(t, members))
	return writeTemp(t, "pkg.rpm", pkgsRPM(pkgsCPIOFormat, pkgsGzip, payload))
}
