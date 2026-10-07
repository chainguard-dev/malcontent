// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/malcontent/pkg/file"
	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/puzpuzpuz/xsync/v4"
)

// openTestRoot opens dir as an os.Root that is closed when tb finishes.
func openTestRoot(tb testing.TB, dir string) *os.Root {
	tb.Helper()
	root, err := os.OpenRoot(dir)
	if err != nil {
		tb.Fatalf("open root %s: %v", dir, err)
	}
	tb.Cleanup(func() { _ = root.Close() })
	return root
}

// testEntryRoots returns entry roots on root, closed when the test ends.
func testEntryRoots(tb testing.TB, root *os.Root) *entryRoots {
	tb.Helper()
	er := newEntryRoots(root)
	tb.Cleanup(er.close)
	return er
}

type tarEntry struct {
	name     string
	typeflag byte
	linkname string
	body     string
}

func writeTar(t *testing.T, entries []tarEntry) string {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		hdr := &tar.Header{Name: e.name, Typeflag: e.typeflag, Linkname: e.linkname, Mode: 0o644}
		switch e.typeflag {
		case tar.TypeDir:
			hdr.Mode = 0o755
		case tar.TypeReg:
			hdr.Size = int64(len(e.body))
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("write header %s: %v", e.name, err)
		}
		if e.typeflag == tar.TypeReg {
			if _, err := tw.Write([]byte(e.body)); err != nil {
				t.Fatalf("write body %s: %v", e.name, err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	dir := t.TempDir()
	if err := file.WriteFileIn(dir, "evil.tar", buf.Bytes(), 0o600); err != nil {
		t.Fatalf("write tar: %v", err)
	}
	return filepath.Join(dir, "evil.tar")
}

// climbChain returns entries whose final link, "yN", lexically resolves to the
// extraction directory but, when followed by the kernel, climbs to "/".
func climbChain() []tarEntry {
	entries := []tarEntry{
		{name: "x/", typeflag: tar.TypeDir},
		{name: "x/up", typeflag: tar.TypeSymlink, linkname: ".."},
		{name: "y01", typeflag: tar.TypeSymlink, linkname: "x/up/.."},
	}
	for i := 2; i <= chainHops; i++ {
		entries = append(entries, tarEntry{
			name:     fmt.Sprintf("y%02d", i),
			typeflag: tar.TypeSymlink,
			linkname: fmt.Sprintf("y%02d/..", i-1),
		})
	}
	return entries
}

const chainHops = 12

// viaChain returns a link target that reaches the absolute path p through the
// final link of climbChain.
func viaChain(t *testing.T, p string) string {
	t.Helper()
	resolved, err := filepath.EvalSymlinks(p)
	if err != nil {
		t.Fatalf("resolve %s: %v", p, err)
	}
	if strings.Count(resolved, string(filepath.Separator)) >= chainHops {
		t.Skipf("temp dir %s is too deep for a %d-hop chain", resolved, chainHops)
	}
	return fmt.Sprintf("y%02d", chainHops) + resolved
}

// assertContained fails if any symlink beneath root resolves outside of it.
func assertContained(t *testing.T, root string) {
	t.Helper()
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatalf("resolve root: %v", err)
	}
	r := openTestRoot(t, root)
	err = fs.WalkDir(r.FS(), ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil || d.Type()&fs.ModeSymlink == 0 {
			return err
		}
		path := filepath.Join(root, name)
		resolved, err := filepath.EvalSymlinks(path)
		if err != nil {
			return nil //nolint:nilerr // dangling and looping links are not followed
		}
		rel, err := filepath.Rel(resolvedRoot, resolved)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			target, _ := r.Readlink(name)
			t.Errorf("symlink %s -> %s resolves outside the extraction directory: %s", path, target, resolved)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
}

func TestSymlinkChainEscape(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		entries func(t *testing.T, outside string) []tarEntry
		// leaked, when set, reports whether the archive reached outside by a
		// means other than an escaping symlink.
		leaked func(t *testing.T, outside, extractDir string) bool
	}{
		{
			name: "chained links climbing out of the extraction dir",
			entries: func(t *testing.T, outside string) []tarEntry {
				t.Helper()
				return append(climbChain(), tarEntry{name: "leak", typeflag: tar.TypeSymlink, linkname: viaChain(t, outside)})
			},
		},
		{
			name: "link resolved through a component created later",
			entries: func(_ *testing.T, _ string) []tarEntry {
				return []tarEntry{
					{name: "early", typeflag: tar.TypeSymlink, linkname: "x/up/../outside"},
					{name: "x/", typeflag: tar.TypeDir},
					{name: "x/up", typeflag: tar.TypeSymlink, linkname: ".."},
				}
			},
		},
		{
			name: "link resolved through a directory later replaced by a link",
			entries: func(_ *testing.T, _ string) []tarEntry {
				return []tarEntry{
					{name: "x/", typeflag: tar.TypeDir},
					{name: "early", typeflag: tar.TypeSymlink, linkname: "x/../outside"},
					{name: "x", typeflag: tar.TypeSymlink, linkname: "."},
				}
			},
		},
		{
			name: "hardlink relocating a symlink to a shallower directory",
			entries: func(_ *testing.T, _ string) []tarEntry {
				return []tarEntry{
					{name: "a/b/c/", typeflag: tar.TypeDir},
					{name: "a/b/c/l", typeflag: tar.TypeSymlink, linkname: "../../.."},
					{name: "top", typeflag: tar.TypeLink, linkname: "a/b/c/l"},
				}
			},
		},
		{
			name: "file written into a new directory beneath an escaping link",
			entries: func(t *testing.T, outside string) []tarEntry {
				t.Helper()
				return append(climbChain(), tarEntry{name: viaChain(t, outside) + "/newdir/file.txt", typeflag: tar.TypeReg, body: "pwned"})
			},
			leaked: func(_ *testing.T, outside, _ string) bool {
				_, err := file.LstatIn(outside, "newdir")
				return err == nil
			},
		},
		{
			name: "file written through a dangling escaping link",
			entries: func(t *testing.T, outside string) []tarEntry {
				t.Helper()
				return append(climbChain(),
					tarEntry{name: "w", typeflag: tar.TypeSymlink, linkname: viaChain(t, outside) + "/dangling.txt"},
					tarEntry{name: "w", typeflag: tar.TypeReg, body: "pwned"},
				)
			},
			leaked: func(_ *testing.T, outside, _ string) bool {
				_, err := file.LstatIn(outside, "dangling.txt")
				return err == nil
			},
		},
		{
			name: "hardlink to a file outside the extraction dir",
			entries: func(t *testing.T, outside string) []tarEntry {
				t.Helper()
				return append(climbChain(), tarEntry{name: "hard", typeflag: tar.TypeLink, linkname: viaChain(t, outside) + "/secret.txt"})
			},
			leaked: func(t *testing.T, outside, extractDir string) bool {
				t.Helper()
				secret, err := file.StatIn(outside, "secret.txt")
				if err != nil {
					t.Fatalf("stat secret: %v", err)
				}
				hard, err := file.StatIn(extractDir, "hard")
				return err == nil && os.SameFile(secret, hard)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// Keep the outside directory and extraction directory on the same
			// filesystem so that hardlinks between them are possible.
			base := t.TempDir()
			outside := filepath.Join(base, "outside")
			extractDir := filepath.Join(base, "extract")
			r := openTestRoot(t, base)
			for _, d := range []string{"outside", "extract"} {
				if err := r.Mkdir(d, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			if err := r.WriteFile(filepath.Join("outside", "secret.txt"), []byte("secret"), 0o600); err != nil {
				t.Fatal(err)
			}

			// Extraction may fail; what matters is that nothing escaped.
			_ = ExtractTar(t.Context(), extractDir, writeTar(t, tt.entries(t, outside)))

			assertContained(t, extractDir)
			if tt.leaked != nil && tt.leaked(t, outside, extractDir) {
				t.Error("archive reached outside the extraction directory")
			}
		})
	}
}

// TestNestedArchiveSymlinkDisclosure reproduces GHSA-p8q7-h7hm-jjxx: a link to
// an archive outside the extraction directory must not be followed and
// extracted into the scan corpus.
func TestNestedArchiveSymlinkDisclosure(t *testing.T) {
	t.Parallel()

	const marker = "curl -s http://internal.corp.example/bootstrap.sh | sh"
	secretDir := t.TempDir()
	secretZip := filepath.Join(secretDir, "backup.zip")
	var zbuf bytes.Buffer
	zw := zip.NewWriter(&zbuf)
	w, err := zw.Create("deploy_key.sh")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte(marker)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.WriteFileIn(secretDir, "backup.zip", zbuf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	tarPath := writeTar(t, append(climbChain(), tarEntry{
		name:     "payload.zip",
		typeflag: tar.TypeSymlink,
		linkname: viaChain(t, secretZip),
	}))

	dir, err := ExtractArchiveToTempDir(t.Context(), malcontent.Config{}, tarPath)
	if err != nil {
		return
	}
	defer file.RemoveAllIn(filepath.Dir(dir), filepath.Base(dir))

	assertContained(t, dir)
	r := openTestRoot(t, dir)
	err = fs.WalkDir(r.FS(), ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() {
			return err
		}
		data, err := r.ReadFile(name)
		if err != nil {
			return err
		}
		if bytes.Contains(data, []byte(marker)) {
			t.Errorf("host archive contents disclosed at %s", filepath.Join(dir, name))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
}

// TestExtractNestedArchiveSkipsSymlinks verifies that nested extraction never
// follows a link, even one that points inside the extraction directory.
func TestExtractNestedArchiveSkipsSymlinks(t *testing.T) {
	t.Parallel()

	srcData, err := file.ReadFileIn("../../pkg/action/testdata", "apko.gz")
	if err != nil {
		t.Fatalf("failed to read test archive: %v", err)
	}
	outsideDir := t.TempDir()
	outside := filepath.Join(outsideDir, "apko.gz")
	if err := file.WriteFileIn(outsideDir, "apko.gz", srcData, 0o600); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	r := openTestRoot(t, dir)
	if err := r.Symlink(outside, "link.gz"); err != nil {
		t.Fatal(err)
	}

	ctx := t.Context()
	extracted := xsync.NewMap[string, bool]()
	if err := extractNestedArchive(ctx, malcontent.Config{}, dir, "link.gz", extracted, clog.FromContext(ctx), 1); err != nil {
		t.Fatalf("extractNestedArchive: %v", err)
	}

	if _, err := r.Lstat("link"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("symlinked archive was extracted (lstat err: %v)", err)
	}
	if _, err := r.Lstat("link.gz"); err != nil {
		t.Errorf("symlink should be left in place: %v", err)
	}
	if _, err := file.StatIn(outsideDir, "apko.gz"); err != nil {
		t.Errorf("link target should be untouched: %v", err)
	}
}

// TestZipSymlinkChainEscape verifies that zip symlink entries, which share
// handleSymlink with tar, cannot build a chain that climbs out of the
// extraction directory.
func TestZipSymlinkChainEscape(t *testing.T) {
	t.Parallel()

	base := t.TempDir()
	outside := filepath.Join(base, "outside")
	extractDir := filepath.Join(base, "extract")
	r := openTestRoot(t, base)
	for _, d := range []string{"outside", "extract"} {
		if err := r.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}

	var zbuf bytes.Buffer
	zw := zip.NewWriter(&zbuf)
	for _, e := range append(climbChain(), tarEntry{name: "leak", typeflag: tar.TypeSymlink, linkname: viaChain(t, outside)}) {
		hdr := &zip.FileHeader{Name: e.name, Method: zip.Store}
		switch e.typeflag {
		case tar.TypeDir:
			hdr.SetMode(fs.ModeDir | 0o755)
		case tar.TypeSymlink:
			hdr.SetMode(fs.ModeSymlink | 0o777)
		}
		w, err := zw.CreateHeader(hdr)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(e.linkname)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	zipDir := t.TempDir()
	zipPath := filepath.Join(zipDir, "evil.zip")
	if err := file.WriteFileIn(zipDir, "evil.zip", zbuf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	_ = ExtractZip(t.Context(), extractDir, zipPath)
	assertContained(t, extractDir)
}

// TestSymlinkLayoutPreserved verifies that symlinks which stay within the
// extraction directory keep working after target canonicalization.
func TestSymlinkLayoutPreserved(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		entries []tarEntry
		// want maps a path to the content it must resolve to.
		want map[string]string
		// regular lists paths that must be regular files, not symlinks.
		regular []string
	}{
		{
			name: "file written through a symlinked directory",
			entries: []tarEntry{
				{name: "usr/lib/", typeflag: tar.TypeDir},
				{name: "lib", typeflag: tar.TypeSymlink, linkname: "usr/lib"},
				{name: "lib/libfoo.so", typeflag: tar.TypeReg, body: "elf"},
			},
			want:    map[string]string{"usr/lib/libfoo.so": "elf", "lib/libfoo.so": "elf"},
			regular: []string{"usr/lib/libfoo.so"},
		},
		{
			name: "relative targets with leading parents and dot elements",
			entries: []tarEntry{
				{name: "usr/lib/libfoo.so.1", typeflag: tar.TypeReg, body: "v1"},
				{name: "usr/lib/libfoo.so", typeflag: tar.TypeSymlink, linkname: "./libfoo.so.1"},
				{name: "usr/bin/foo", typeflag: tar.TypeSymlink, linkname: "../lib/libfoo.so"},
			},
			want: map[string]string{"usr/lib/libfoo.so": "v1", "usr/bin/foo": "v1"},
		},
		{
			name: "hardlink to a symlink is recreated as a symlink",
			entries: []tarEntry{
				{name: "a/real.txt", typeflag: tar.TypeReg, body: "real"},
				{name: "a/link", typeflag: tar.TypeSymlink, linkname: "real.txt"},
				{name: "a/hard", typeflag: tar.TypeLink, linkname: "a/link"},
			},
			want: map[string]string{"a/hard": "real"},
		},
		{
			name: "later regular entry replaces an earlier one",
			entries: []tarEntry{
				{name: "dup.txt", typeflag: tar.TypeReg, body: "first, longer body"},
				{name: "dup.txt", typeflag: tar.TypeReg, body: "second"},
			},
			want:    map[string]string{"dup.txt": "second"},
			regular: []string{"dup.txt"},
		},
		{
			name: "hardlink to itself keeps the file",
			entries: []tarEntry{
				{name: "self.txt", typeflag: tar.TypeReg, body: "self"},
				{name: "self.txt", typeflag: tar.TypeLink, linkname: "self.txt"},
			},
			want: map[string]string{"self.txt": "self"},
		},
		{
			name: "hardlink replaces an existing entry in a new directory",
			entries: []tarEntry{
				{name: "src.txt", typeflag: tar.TypeReg, body: "src"},
				{name: "a/b/dst.txt", typeflag: tar.TypeLink, linkname: "src.txt"},
				{name: "old.txt", typeflag: tar.TypeReg, body: "old"},
				{name: "old.txt", typeflag: tar.TypeLink, linkname: "src.txt"},
			},
			want: map[string]string{"a/b/dst.txt": "src", "old.txt": "src"},
		},
		{
			name: "regular file replaces an existing symlink",
			entries: []tarEntry{
				{name: "f", typeflag: tar.TypeSymlink, linkname: "other.txt"},
				{name: "f", typeflag: tar.TypeReg, body: "replaced"},
			},
			want:    map[string]string{"f": "replaced"},
			regular: []string{"f"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			if err := ExtractTar(t.Context(), dir, writeTar(t, tt.entries)); err != nil {
				t.Fatalf("ExtractTar: %v", err)
			}
			assertContained(t, dir)
			r := openTestRoot(t, dir)
			for path, want := range tt.want {
				got, err := r.ReadFile(path)
				if err != nil {
					t.Errorf("read %s: %v", path, err)
					continue
				}
				if string(got) != want {
					t.Errorf("%s: got = %q, want = %q", path, got, want)
				}
			}
			for _, path := range tt.regular {
				fi, err := r.Lstat(path)
				if err != nil || !fi.Mode().IsRegular() {
					t.Errorf("%s is not a regular file (err: %v)", path, err)
				}
			}
			if _, err := r.Lstat("other.txt"); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("write followed a replaced symlink (lstat err: %v)", err)
			}
		})
	}
}
