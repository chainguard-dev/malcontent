// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"archive/tar"
	"context"
	"fmt"
	"io/fs"
	"os"
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

func TestEntryRootsCreateFileMatchesCreateFile(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		path string
	}{
		{name: "new file in an existing directory", path: filepath.Join("dir", "new")},
		{name: "new file in new directories", path: filepath.Join("x", "y", "z", "new")},
		{name: "new file in the root", path: "new"},
		{name: "existing file", path: filepath.Join("dir", "existing")},
		{name: "existing symlink", path: filepath.Join("dir", "link")},
		{name: "beneath a file", path: filepath.Join("leaf", "new")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			want, got := entryRootsTestTree(t), entryRootsTestTree(t)
			er := testEntryRoots(t, openTestRoot(t, got))
			// Reach the directories first, so that they are open.
			if _, _, release, err := er.dirs.Parent(tt.path); err == nil {
				release()
			}
			_ = er.validPath(filepath.Join(got, tt.path), got)

			wantFile, wantErr := createFile(openTestRoot(t, want), tt.path)
			gotFile, gotErr := er.createFile(tt.path)
			for _, f := range []*os.File{wantFile, gotFile} {
				if f != nil {
					if _, err := f.WriteString("new"); err != nil {
						t.Errorf("write: %v", err)
					}
					_ = f.Close()
				}
			}
			if fmt.Sprint(gotErr) != fmt.Sprint(wantErr) {
				t.Errorf("createFile(%q) error: got = %v, want = %v", tt.path, gotErr, wantErr)
			}
			if g, w := entryRootsTreeState(t, got), entryRootsTreeState(t, want); strings.Join(g, "\n") != strings.Join(w, "\n") {
				t.Errorf("tree after createFile(%q): got = %q, want = %q", tt.path, g, w)
			}
		})
	}
}

func TestEntryRootsValidPathMatchesIsValidPath(t *testing.T) {
	t.Parallel()
	d := entryRootsTestTree(t)
	outside := t.TempDir()
	r := openTestRoot(t, d)
	if err := openTestRoot(t, outside).Symlink("/", "escape"); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	for _, link := range []struct{ target, name string }{
		{target: "/", name: "abs"},
		{target: outside, name: "outdir"},
		{target: "dir", name: "indir"},
	} {
		if err := r.Symlink(link.target, link.name); err != nil {
			t.Fatalf("symlink: %v", err)
		}
	}
	er := testEntryRoots(t, r)
	for _, name := range []string{
		filepath.Join("dir", "existing"),
		filepath.Join("dir", "link"),
		filepath.Join("dir", "missing"),
		filepath.Join("missing", "a", "b"),
		"abs",
		filepath.Join("outdir", "escape"),
		filepath.Join("indir", "link"),
		filepath.Join("leaf", "x"),
		".",
	} {
		target := filepath.Join(d, name)
		if got, want := er.validPath(target, d), IsValidPath(target, d); got != want {
			t.Errorf("validPath(%q): got = %v, want = %v", name, got, want)
		}
	}
}

func TestExtractTarForgetsDirectoriesReplacedByFiles(t *testing.T) {
	t.Parallel()
	// "link/a" is written through the symlink, which the regular file "link"
	// then replaces, so "link/b" names a path beneath a file.
	archive := writeTar(t, []tarEntry{
		{name: "real/", typeflag: tar.TypeDir},
		{name: "link", typeflag: tar.TypeSymlink, linkname: "real"},
		{name: "link/a", typeflag: tar.TypeReg, body: "a"},
		{name: "link", typeflag: tar.TypeReg, body: "file"},
		{name: "link/b", typeflag: tar.TypeReg, body: "b"},
	})
	d := t.TempDir()
	err := ExtractTar(t.Context(), d, archive)
	if err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Errorf("ExtractTar error: got = %v, want one creating link/b beneath a file", err)
	}
	for name, want := range map[string]string{filepath.Join("real", "a"): "a", "link": "file"} {
		if got, err := file.ReadFileIn(d, name); err != nil || string(got) != want {
			t.Errorf("%s: got = (%q, %v), want = (%q, nil)", name, got, err, want)
		}
	}
	if _, err := file.LstatIn(d, filepath.Join("real", "b")); err == nil {
		t.Error("real/b: got it written through the replaced symlink, want it absent")
	}
}

// entryRootsLinkCases are archive layouts in which a link replaces an entry
// that an earlier file was written through, and the file after it must be
// written where the link now leads, or fail as the root would fail.
var entryRootsLinkCases = []struct {
	name     string
	entries  []tarEntry
	want     []string // files, beneath the extraction directory, that must exist
	absent   []string
	wantFail string // part of the error extraction must report, if any
}{
	{
		name: "symlink pointed elsewhere",
		entries: []tarEntry{
			{name: "real1/", typeflag: tar.TypeDir},
			{name: "real2/", typeflag: tar.TypeDir},
			{name: "link", typeflag: tar.TypeSymlink, linkname: "real1"},
			{name: "link/a", typeflag: tar.TypeReg, body: "a"},
			{name: "link", typeflag: tar.TypeSymlink, linkname: "real2"},
			{name: "link/b", typeflag: tar.TypeReg, body: "b"},
		},
		want:   []string{filepath.Join("real1", "a"), filepath.Join("real2", "b")},
		absent: []string{filepath.Join("real1", "b")},
	},
	{
		name: "symlink replaced by a hard link",
		entries: []tarEntry{
			{name: "real1/", typeflag: tar.TypeDir},
			{name: "target", typeflag: tar.TypeReg, body: "t"},
			{name: "link", typeflag: tar.TypeSymlink, linkname: "real1"},
			{name: "link/a", typeflag: tar.TypeReg, body: "a"},
			{name: "link", typeflag: tar.TypeLink, linkname: "target"},
			{name: "link/b", typeflag: tar.TypeReg, body: "b"},
		},
		want:     []string{filepath.Join("real1", "a")},
		absent:   []string{filepath.Join("real1", "b")},
		wantFail: "not a directory",
	},
}

func TestExtractFollowsLinksThatReplaceEntries(t *testing.T) {
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
				err := format.extract(t.Context(), d, format.archive(t, tt.entries))
				if (err != nil) != (tt.wantFail != "") || (err != nil && !strings.Contains(err.Error(), tt.wantFail)) {
					t.Errorf("extract error: got = %v, want one containing %q", err, tt.wantFail)
				}
				for _, name := range tt.want {
					if _, err := file.LstatIn(d, name); err != nil {
						t.Errorf("%s: got err = %v, want it written", name, err)
					}
				}
				for _, name := range tt.absent {
					if _, err := file.LstatIn(d, name); err == nil {
						t.Errorf("%s: got it written through the replaced link, want it absent", name)
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
