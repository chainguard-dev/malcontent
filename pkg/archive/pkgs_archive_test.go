// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/zlib"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/puzpuzpuz/xsync/v4"
)

func TestIsValidPathContainment(t *testing.T) {
	t.Parallel()

	base := t.TempDir()
	dir := filepath.Join(base, "extract")
	outside := filepath.Join(base, "outside")
	inside := filepath.Join(dir, "sub")
	for _, d := range []string{outside, inside} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for name, target := range map[string]string{
		"out":      outside,
		"up":       base,
		"in":       inside,
		"dangling": filepath.Join(dir, "missing"),
	} {
		if err := os.Symlink(target, filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}

	tests := []struct {
		name   string
		target string
		dir    string
		want   bool
	}{
		{name: "path beneath the directory", target: filepath.Join(inside, "a.txt"), dir: dir, want: true},
		{name: "the directory itself", target: dir, dir: dir, want: true},
		{name: "sibling whose name extends the directory name", target: dir + "2", dir: dir, want: false},
		{name: "parent of the directory", target: base, dir: dir, want: false},
		{name: "symlink resolving outside", target: filepath.Join(dir, "out"), dir: dir, want: false},
		{name: "symlink resolving to the parent", target: filepath.Join(dir, "up"), dir: dir, want: false},
		{name: "symlink resolving inside", target: filepath.Join(dir, "in"), dir: dir, want: true},
		{name: "dangling symlink", target: filepath.Join(dir, "dangling"), dir: dir, want: true},
		{name: "NUL byte in the target", target: dir + "/a\x00b", dir: dir, want: false},
		{name: "NUL byte in the directory", target: filepath.Join(dir, "a.txt"), dir: dir + "\x00", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := IsValidPath(tt.target, tt.dir); got != tt.want {
				t.Errorf("IsValidPath(%q, %q): got = %v, want = %v", tt.target, tt.dir, got, tt.want)
			}
		})
	}
}

func TestValidateResolvedPathParents(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "file.txt"), []byte("file"), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		clean   string
		wantErr bool
	}{
		{name: "missing parents beneath the directory", clean: filepath.Join("a", "b", "c.txt"), wantErr: false},
		{name: "parent beneath a regular file", clean: filepath.Join("file.txt", "child", "leaf.txt"), wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateResolvedPath(filepath.Join(dir, tt.clean), dir, tt.clean)
			if got := err != nil; got != tt.wantErr {
				t.Errorf("ValidateResolvedPath error: got = %v, want error = %v", err, tt.wantErr)
			}
		})
	}
}

func TestCreateFileExistingEntries(t *testing.T) {
	t.Parallel()

	t.Run("regular file is truncated in place", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		path := filepath.Join(dir, "f")
		twin := filepath.Join(dir, "twin")
		if err := os.WriteFile(path, []byte("old content, longer than the new"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(path, twin); err != nil {
			t.Fatal(err)
		}

		out, err := createFile(openTestRoot(t, dir), "f")
		if err != nil {
			t.Fatalf("createFile: %v", err)
		}
		if _, err := out.WriteString("new"); err != nil {
			t.Fatal(err)
		}
		if err := out.Close(); err != nil {
			t.Fatal(err)
		}
		// Writing through the existing inode reaches every link to it.
		pkgsWantFile(t, twin, "new")
	})

	t.Run("directory is left in place", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		path := filepath.Join(dir, "d")
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}

		out, err := createFile(openTestRoot(t, dir), "d")
		if err == nil {
			_ = out.Close()
			t.Fatal("createFile on a directory: got = nil error, want = error")
		}
		if fi, err := os.Lstat(path); err != nil || !fi.IsDir() {
			t.Errorf("entry after createFile: got = %v (err %v), want = directory", fi, err)
		}
	})
}

func TestHandleSymlinkReplacesExistingEntry(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		symlink bool
	}{
		{name: "existing symlink", symlink: true},
		{name: "existing regular file", symlink: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			path := filepath.Join(dir, "l")
			var err error
			if tt.symlink {
				err = os.Symlink("old.txt", path)
			} else {
				err = os.WriteFile(path, []byte("old"), 0o600)
			}
			if err != nil {
				t.Fatal(err)
			}

			if err := handleSymlink(openTestRoot(t, dir), "l", "new.txt"); err != nil {
				t.Fatalf("handleSymlink: %v", err)
			}
			pkgsWantSymlink(t, path, "new.txt")
		})
	}
}

func TestRetainArchive(t *testing.T) {
	t.Parallel()

	const archiveBody = "archive bytes that could not be extracted"

	t.Run("archive is retained under its own name", func(t *testing.T) {
		t.Parallel()
		src := writeTemp(t, "pkg.tar", []byte(archiveBody))
		dir := t.TempDir()

		name, err := retainArchive(dir, src)
		if err != nil {
			t.Fatalf("retainArchive: %v", err)
		}
		if name != "pkg.tar" {
			t.Errorf("retained name: got = %q, want = %q", name, "pkg.tar")
		}
		pkgsWantFile(t, filepath.Join(dir, "pkg.tar"), archiveBody)
	})

	t.Run("existing entry keeps its name and the archive is retained beside it", func(t *testing.T) {
		t.Parallel()
		src := writeTemp(t, "pkg.tar", []byte(archiveBody))
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "pkg.tar"), []byte("extracted entry"), 0o600); err != nil {
			t.Fatal(err)
		}

		name, err := retainArchive(dir, src)
		if err != nil {
			t.Fatalf("retainArchive: %v", err)
		}
		if !strings.HasPrefix(name, "pkg.tar_") {
			t.Fatalf("retained name: got = %q, want = prefix %q", name, "pkg.tar_")
		}
		pkgsWantFile(t, filepath.Join(dir, name), archiveBody)
		pkgsWantFile(t, filepath.Join(dir, "pkg.tar"), "extracted entry")
	})

	// A missing archive must be reported as unreadable, whether or not an
	// entry already holds its name, rather than as a failure to create the
	// retention file or as success.
	for _, existing := range []bool{false, true} {
		name := "unreadable archive reports the read failure"
		if existing {
			name += " beside an existing entry"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			if existing {
				if err := os.WriteFile(filepath.Join(dir, "missing.tar"), []byte("extracted entry"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			got, err := retainArchive(dir, filepath.Join(t.TempDir(), "missing.tar"))
			if !errors.Is(err, fs.ErrNotExist) || !strings.Contains(err.Error(), "failed to open archive for retention") {
				t.Errorf("retainArchive error: got = %v, want = failure to open the archive wrapping %v", err, fs.ErrNotExist)
			}
			if got != "" {
				t.Errorf("retained name: got = %q, want = empty", got)
			}
		})
	}
}

// TestExtractNestedArchiveDepthLimit verifies that an archive past the depth
// limit is left in place to be scanned as a file, and fails extraction only
// when extraction failures are fatal.
func TestExtractNestedArchiveDepthLimit(t *testing.T) {
	t.Parallel()

	archive := tarWithEntry(t, "inside.txt", "inside content")
	tests := []struct {
		name          string
		maxDepth      int
		depth         int
		exitOnFailure bool
		wantErr       bool
		wantExtracted bool
	}{
		{name: "archive at the depth limit is extracted", maxDepth: 3, depth: 3, wantExtracted: true},
		{name: "archive past the depth limit is left in place", maxDepth: 3, depth: 4},
		{name: "archive past the depth limit fails when failures are fatal", maxDepth: 3, depth: 4, exitOnFailure: true, wantErr: true},
		{name: "zero limit extracts at the safety bound", maxDepth: 0, depth: maxNestingDepth, wantExtracted: true},
		{name: "zero limit leaves an archive past the safety bound in place", maxDepth: 0, depth: maxNestingDepth + 1},
		{name: "negative limit fails past the safety bound when failures are fatal", maxDepth: -1, depth: maxNestingDepth + 1, exitOnFailure: true, wantErr: true},
		{name: "configured limit above the safety bound is honored", maxDepth: 2 * maxNestingDepth, depth: 2 * maxNestingDepth, wantExtracted: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "a.tar"), archive, 0o600); err != nil {
				t.Fatal(err)
			}
			ctx := t.Context()
			cfg := malcontent.Config{MaxDepth: tt.maxDepth, ExitExtraction: tt.exitOnFailure}

			err := extractNestedArchive(ctx, cfg, dir, "a.tar", xsync.NewMap[string, bool](), clog.FromContext(ctx), tt.depth)
			if got := err != nil; got != tt.wantErr {
				t.Fatalf("extractNestedArchive error: got = %v, want error = %v", err, tt.wantErr)
			}
			if tt.wantExtracted {
				pkgsWantFile(t, filepath.Join(dir, "a", "inside.txt"), "inside content")
				pkgsWantAbsent(t, filepath.Join(dir, "a.tar"))
				return
			}
			pkgsWantFile(t, filepath.Join(dir, "a.tar"), string(archive))
			pkgsWantAbsent(t, filepath.Join(dir, "a"))
		})
	}
}

// TestExtractNestedArchiveContents verifies that extracting an archive also
// extracts the archives inside it, and leaves the archives beside it to the
// caller's own walk.
func TestExtractNestedArchiveContents(t *testing.T) {
	t.Parallel()

	outer, err := os.ReadFile(writeTar(t, []tarEntry{
		{name: "from-outer.txt", typeflag: tar.TypeReg, body: "outer content"},
		{name: "inner.tar", typeflag: tar.TypeReg, body: string(tarWithEntry(t, "from-inner.txt", "inner content"))},
	}))
	if err != nil {
		t.Fatal(err)
	}
	sibling := tarWithEntry(t, "from-sibling.txt", "sibling content")

	tests := []struct {
		name      string
		canceled  bool
		wantErr   error
		extracted bool
	}{
		{name: "archives inside the extracted archive are extracted", extracted: true},
		{name: "canceled context extracts nothing", canceled: true, wantErr: context.Canceled},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			for name, data := range map[string][]byte{"outer.tar": outer, "sibling.tar": sibling} {
				if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			ctx := t.Context()
			if tt.canceled {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}

			err := extractNestedArchive(ctx, malcontent.Config{}, dir, "outer.tar", xsync.NewMap[string, bool](), clog.FromContext(ctx), 1)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("extractNestedArchive error: got = %v, want = %v", err, tt.wantErr)
			}
			pkgsWantFile(t, filepath.Join(dir, "sibling.tar"), string(sibling))
			pkgsWantAbsent(t, filepath.Join(dir, "sibling"))
			if !tt.extracted {
				pkgsWantAbsent(t, filepath.Join(dir, "outer"))
				return
			}
			pkgsWantFile(t, filepath.Join(dir, "outer", "from-outer.txt"), "outer content")
			pkgsWantFile(t, filepath.Join(dir, "outer", "inner", "from-inner.txt"), "inner content")
			pkgsWantAbsent(t, filepath.Join(dir, "outer.tar"))
			pkgsWantAbsent(t, filepath.Join(dir, "outer", "inner.tar"))
		})
	}
}

// pkgsNestedTars returns layers levels of tar, each holding the next as
// n.tar, with the innermost holding deepest.txt. Every level differs from the
// others, so none is a copy of another.
func pkgsNestedTars(t *testing.T, layers int) []byte {
	t.Helper()
	b := tarWithEntry(t, "deepest.txt", "deepest content")
	for range layers - 1 {
		b = tarWithEntry(t, "n.tar", string(b))
	}
	return b
}

// pkgsNestedPath returns the path, beneath dir, of the directory into which
// level levels of pkgsNestedTars are extracted, each level into a directory
// named n beside it.
func pkgsNestedPath(dir string, levels int) string {
	return filepath.Join(dir, strings.Repeat("n"+string(filepath.Separator), levels))
}

// TestExtractNestedArchiveNestingDepth verifies that the depth limit counts
// levels of nesting, an archive found inside another being one level deeper,
// that an unlimited depth still stops at the safety bound, and that the levels
// above the limit stay extracted.
func TestExtractNestedArchiveNestingDepth(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		maxDepth  int
		layers    int
		extracted int
	}{
		{name: "limit equal to the nesting depth extracts every level", maxDepth: 3, layers: 3, extracted: 3},
		{name: "limit one below the nesting depth keeps the levels above it", maxDepth: 2, layers: 3, extracted: 2},
		{name: "unlimited depth extracts nesting as deep as the safety bound", maxDepth: 0, layers: maxNestingDepth, extracted: maxNestingDepth},
		{name: "unlimited depth stops nesting at the safety bound", maxDepth: 0, layers: maxNestingDepth + 1, extracted: maxNestingDepth},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "n.tar"), pkgsNestedTars(t, tt.layers), 0o600); err != nil {
				t.Fatal(err)
			}
			ctx := t.Context()
			cfg := malcontent.Config{MaxDepth: tt.maxDepth}

			if err := extractNestedArchive(ctx, cfg, dir, "n.tar", xsync.NewMap[string, bool](), clog.FromContext(ctx), 1); err != nil {
				t.Fatalf("extractNestedArchive: %v", err)
			}
			if tt.extracted == tt.layers {
				pkgsWantFile(t, filepath.Join(pkgsNestedPath(dir, tt.layers), "deepest.txt"), "deepest content")
				return
			}
			// The first level past the limit is left in place as a file.
			kept := filepath.Join(pkgsNestedPath(dir, tt.extracted), "n.tar")
			if fi, err := os.Lstat(kept); err != nil || !fi.Mode().IsRegular() {
				t.Errorf("archive past the limit: got = %v (err %v), want = regular file at %s", fi, err, kept)
			}
			pkgsWantAbsent(t, pkgsNestedPath(dir, tt.extracted+1))
		})
	}
}

// TestExtractArchiveToTempDirDepthLimit verifies that an archive nested past
// the depth limit cannot hide the rest of the scanned archive: what lies above
// the limit stays extracted and the over-deep archive stays in place as a
// file, unless extraction failures are fatal.
func TestExtractArchiveToTempDirDepthLimit(t *testing.T) {
	t.Parallel()

	// The scanned archive is level 0; its n.tar entry is level 1.
	deep := pkgsNestedTars(t, 1)
	levels := tarWithEntry(t, "n.tar", string(tarWithEntry(t, "n.tar", string(deep))))
	scanned, err := os.ReadFile(writeTar(t, []tarEntry{
		{name: "top.txt", typeflag: tar.TypeReg, body: "top content"},
		{name: "n.tar", typeflag: tar.TypeReg, body: string(levels)},
	}))
	if err != nil {
		t.Fatal(err)
	}
	src := writeTemp(t, "scanned.tar", scanned)

	tests := []struct {
		name          string
		exitOnFailure bool
		wantErr       bool
	}{
		{name: "content above the limit and the over-deep archive remain", exitOnFailure: false, wantErr: false},
		{name: "exceeding the limit fails when failures are fatal", exitOnFailure: true, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir, err := ExtractArchiveToTempDir(t.Context(), malcontent.Config{MaxDepth: 2, ExitExtraction: tt.exitOnFailure}, src)
			if dir != "" {
				t.Cleanup(func() { _ = os.RemoveAll(dir) })
			}
			if got := err != nil; got != tt.wantErr {
				t.Fatalf("ExtractArchiveToTempDir error: got = %v, want error = %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			pkgsWantFile(t, filepath.Join(dir, "top.txt"), "top content")
			// Levels 1 and 2 are extracted; level 3 is past the limit of 2.
			pkgsWantFile(t, filepath.Join(pkgsNestedPath(dir, 2), "n.tar"), string(deep))
			pkgsWantAbsent(t, pkgsNestedPath(dir, 3))
			pkgsWantAbsent(t, filepath.Join(dir, "n.tar"))
		})
	}
}

// TestNestedArchiveIdenticalCopies verifies that identical archives in
// different places of one extraction tree are each extracted, so findings are
// reported at every location.
func TestNestedArchiveIdenticalCopies(t *testing.T) {
	t.Parallel()

	inner := tarWithEntry(t, "payload.txt", "repeated payload")
	holder := tarWithEntry(t, "copy.tar", string(inner))
	outer, err := os.ReadFile(writeTar(t, []tarEntry{
		{name: "a.tar", typeflag: tar.TypeReg, body: string(inner)},
		{name: "b.tar", typeflag: tar.TypeReg, body: string(holder)},
		{name: "c/dep.tar", typeflag: tar.TypeReg, body: string(inner)},
	}))
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		extract func(t *testing.T) string
	}{
		{
			// Every copy is found while extracting the archive holding them,
			// within one call.
			name: "copies nested inside one archive",
			extract: func(t *testing.T) string {
				t.Helper()
				dir := t.TempDir()
				if err := os.WriteFile(filepath.Join(dir, "outer.tar"), outer, 0o600); err != nil {
					t.Fatal(err)
				}
				ctx := t.Context()
				if err := extractNestedArchive(ctx, malcontent.Config{}, dir, "outer.tar", xsync.NewMap[string, bool](), clog.FromContext(ctx), 1); err != nil {
					t.Fatalf("extractNestedArchive: %v", err)
				}
				return filepath.Join(dir, "outer")
			},
		},
		{
			// The copies are reached from separate entries of the scanned
			// archive, which share one extraction tree.
			name: "copies reached from separate entries of the scanned archive",
			extract: func(t *testing.T) string {
				t.Helper()
				dir, err := ExtractArchiveToTempDir(t.Context(), malcontent.Config{}, writeTemp(t, "outer.tar", outer))
				if err != nil {
					t.Fatalf("ExtractArchiveToTempDir: %v", err)
				}
				t.Cleanup(func() { _ = os.RemoveAll(dir) })
				return dir
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			root := tt.extract(t)
			for _, rel := range []string{"a/payload.txt", "b/copy/payload.txt", "c/dep/payload.txt"} {
				pkgsWantFile(t, filepath.Join(root, filepath.FromSlash(rel)), "repeated payload")
			}
			for _, rel := range []string{"a.tar", "b/copy.tar", "c/dep.tar"} {
				pkgsWantAbsent(t, filepath.Join(root, filepath.FromSlash(rel)))
			}
		})
	}
}

// TestNestedArchiveCopyOfAncestor verifies that an archive identical to one
// containing it is left in place and scanned as it is, which is what stops an
// archive holding a copy of itself from nesting without end. A tar cannot hold
// a byte-identical copy of itself, so the tree's root is recorded from a
// separate file with the copy's content: the check compares digests, and the
// root counts as containing every archive in the tree.
func TestNestedArchiveCopyOfAncestor(t *testing.T) {
	t.Parallel()

	inner := tarWithEntry(t, "payload.txt", "ancestor payload")
	// Entries are examined in name order, so the copy in a.tar is passed over
	// before the archives after it are extracted.
	outer, err := os.ReadFile(writeTar(t, []tarEntry{
		{name: "a.tar", typeflag: tar.TypeReg, body: string(inner)},
		{name: "b.tar", typeflag: tar.TypeReg, body: string(tarWithEntry(t, "copy.tar", string(inner)))},
		{name: "c.tar", typeflag: tar.TypeReg, body: string(tarWithEntry(t, "note.txt", "side content"))},
	}))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "outer.tar"), outer, 0o600); err != nil {
		t.Fatal(err)
	}

	tree := newNestedTree(xsync.NewMap[string, bool]())
	if err := tree.setRoot(writeTemp(t, "ancestor.tar", inner)); err != nil {
		t.Fatalf("setRoot: %v", err)
	}
	ctx := t.Context()
	if err := tree.extract(ctx, malcontent.Config{}, dir, "outer.tar", clog.FromContext(ctx), 1); err != nil {
		t.Fatalf("extract: %v", err)
	}

	for _, rel := range []string{"a.tar", "b/copy.tar"} {
		pkgsWantFile(t, filepath.Join(dir, "outer", filepath.FromSlash(rel)), string(inner))
		// Each copy left in place is recorded as handled, so no later pass
		// examines it again.
		if _, ok := tree.extracted.Load(filepath.Join("outer", filepath.FromSlash(rel))); !ok {
			t.Errorf("%s recorded as handled: got = false, want = true", rel)
		}
	}
	pkgsWantAbsent(t, filepath.Join(dir, "outer", "a"))
	pkgsWantAbsent(t, filepath.Join(dir, "outer", "b", "copy"))
	pkgsWantFile(t, filepath.Join(dir, "outer", "c", "note.txt"), "side content")
}

// TestExtractNestedArchiveReportsEachArchivePastLimit verifies that every
// archive past the depth limit is logged as a warning and recorded as handled,
// not only the first one found.
func TestExtractNestedArchiveReportsEachArchivePastLimit(t *testing.T) {
	t.Parallel()

	outer, err := os.ReadFile(writeTar(t, []tarEntry{
		{name: "x.tar", typeflag: tar.TypeReg, body: string(tarWithEntry(t, "x.txt", "x content"))},
		{name: "y.tar", typeflag: tar.TypeReg, body: string(tarWithEntry(t, "y.txt", "y content"))},
	}))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "outer.tar"), outer, 0o600); err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	logger := clog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelWarn}))
	extracted := xsync.NewMap[string, bool]()

	// outer.tar is at the limit of 1, so x.tar and y.tar are both past it.
	if err := extractNestedArchive(t.Context(), malcontent.Config{MaxDepth: 1}, dir, "outer.tar", extracted, logger, 1); err != nil {
		t.Fatalf("extractNestedArchive: %v", err)
	}

	for _, rel := range []string{filepath.Join("outer", "x.tar"), filepath.Join("outer", "y.tar")} {
		if fi, err := os.Lstat(filepath.Join(dir, rel)); err != nil || !fi.Mode().IsRegular() {
			t.Errorf("%s: got = %v (err %v), want = regular file left in place", rel, fi, err)
		}
		if _, ok := extracted.Load(rel); !ok {
			t.Errorf("%s recorded as handled: got = false, want = true", rel)
		}
		if !strings.Contains(logs.String(), rel) {
			t.Errorf("warnings: got = %q, want = a warning naming %s", logs.String(), rel)
		}
	}
}

// TestExtractNestedArchiveFailureNamesArchive verifies that a fatal failure
// names the nested archive that caused it, and leaves the error for the
// archive extraction started from unchanged.
func TestExtractNestedArchiveFailureNamesArchive(t *testing.T) {
	t.Parallel()

	const prefix = "process nested file"
	// A full block of non-header bytes fails the tar reader outright.
	bad := []byte(strings.Repeat("x", 2*tarBlockSize))

	tests := []struct {
		name       string
		file       string
		data       []byte
		wantPrefix string // empty when the error must not carry the prefix
	}{
		{name: "failure of the named archive is returned unchanged", file: "bad.tar", data: bad},
		{
			name:       "failure of a nested archive names it",
			file:       "outer.tar",
			data:       tarWithEntry(t, "bad.tar", string(bad)),
			wantPrefix: prefix + " " + filepath.Join("outer", "bad.tar"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, tt.file), tt.data, 0o600); err != nil {
				t.Fatal(err)
			}
			ctx := t.Context()

			err := extractNestedArchive(ctx, malcontent.Config{ExitExtraction: true}, dir, tt.file, xsync.NewMap[string, bool](), clog.FromContext(ctx), 1)
			if err == nil {
				t.Fatal("extractNestedArchive error: got = nil, want = extraction failure")
			}
			if tt.wantPrefix == "" && strings.Contains(err.Error(), prefix) {
				t.Errorf("error: got = %q, want = no %q prefix", err, prefix)
			}
			if tt.wantPrefix != "" && !strings.Contains(err.Error(), tt.wantPrefix) {
				t.Errorf("error: got = %q, want = error containing %q", err, tt.wantPrefix)
			}
		})
	}
}

// TestExtractArchiveToTempDirUnsupportedLeavesNothing verifies that an archive
// no extractor handles leaves no temporary directory behind. It points TMPDIR
// at its own directory, so it does not run in parallel.
func TestExtractArchiveToTempDirUnsupportedLeavesNothing(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	// Named like an archive, but neither zlib content nor an extension with
	// an extractor.
	src := writeTemp(t, "data.zlib", []byte("not compressed at all"))

	dir, err := ExtractArchiveToTempDir(t.Context(), malcontent.Config{}, src)
	if err == nil {
		_ = os.RemoveAll(dir)
		t.Fatal("ExtractArchiveToTempDir error: got = nil, want = unsupported archive type")
	}
	entries, err := os.ReadDir(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("entries left in the temporary directory: got = %d, want = 0", len(entries))
	}
}

// TestExtractNestedArchiveWithoutExtractor verifies that a file named like an
// archive whose content no extractor handles is left in place for scanning.
func TestExtractNestedArchiveWithoutExtractor(t *testing.T) {
	t.Parallel()

	const content = "not compressed at all"
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "data.zlib"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()

	if err := extractNestedArchive(ctx, malcontent.Config{}, dir, "data.zlib", xsync.NewMap[string, bool](), clog.FromContext(ctx), 1); err != nil {
		t.Fatalf("extractNestedArchive: %v", err)
	}
	pkgsWantFile(t, filepath.Join(dir, "data.zlib"), content)
	pkgsWantAbsent(t, filepath.Join(dir, "data"))
}

func TestExtractArchiveToTempDirNestedArchive(t *testing.T) {
	t.Parallel()

	inner := tarWithEntry(t, "payload.txt", "nested payload")
	src := writeTemp(t, "outer.tar", tarWithEntry(t, "inner.tar", string(inner)))

	dir, err := ExtractArchiveToTempDir(t.Context(), malcontent.Config{}, src)
	if err != nil {
		t.Fatalf("ExtractArchiveToTempDir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	pkgsWantFile(t, filepath.Join(dir, "inner", "payload.txt"), "nested payload")
	pkgsWantAbsent(t, filepath.Join(dir, "inner.tar"))
}

// TestExtractArchiveToTempDirDeepNesting verifies that archives nested at any
// depth reach the scan corpus as extracted files rather than opaque archives.
func TestExtractArchiveToTempDirDeepNesting(t *testing.T) {
	t.Parallel()

	const script = "#!/bin/sh\necho nested three levels deep\n"
	var zbuf bytes.Buffer
	zw := zip.NewWriter(&zbuf)
	w, err := zw.Create("payload.sh")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte(script)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	mid := gzipBytes(t, tarWithEntry(t, "inner.zip", zbuf.String()))

	sameNames, err := os.ReadFile(writeTar(t, []tarEntry{
		{name: "x/inner.tar", typeflag: tar.TypeReg, body: string(tarWithEntry(t, "x.txt", "x content"))},
		{name: "y/inner.tar", typeflag: tar.TypeReg, body: string(tarWithEntry(t, "y.txt", "y content"))},
	}))
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		outer  []byte
		want   map[string]string
		absent []string
	}{
		{
			name:   "script in a zip in a gzip tar in a subdirectory of a tar",
			outer:  tarWithEntry(t, "sub/mid.tar.gz", string(mid)),
			want:   map[string]string{"sub/mid/inner/payload.sh": script},
			absent: []string{"sub/mid.tar.gz", "sub/mid/inner.zip"},
		},
		{
			name:   "archives sharing a name in different directories",
			outer:  tarWithEntry(t, "pkg.tar", string(sameNames)),
			want:   map[string]string{"pkg/x/inner/x.txt": "x content", "pkg/y/inner/y.txt": "y content"},
			absent: []string{"pkg/x/inner.tar", "pkg/y/inner.tar"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir, err := ExtractArchiveToTempDir(t.Context(), malcontent.Config{}, writeTemp(t, "outer.tar", tt.outer))
			if err != nil {
				t.Fatalf("ExtractArchiveToTempDir: %v", err)
			}
			t.Cleanup(func() { _ = os.RemoveAll(dir) })

			for rel, want := range tt.want {
				pkgsWantFile(t, filepath.Join(dir, filepath.FromSlash(rel)), want)
			}
			for _, rel := range tt.absent {
				pkgsWantAbsent(t, filepath.Join(dir, filepath.FromSlash(rel)))
			}
		})
	}
}

// TestExtractArchiveToTempDirZlibWithoutExtension verifies that a member
// recognized as a zlib stream by its content is decompressed even though its
// name carries no archive extension.
func TestExtractArchiveToTempDirZlibWithoutExtension(t *testing.T) {
	t.Parallel()

	payload := strings.Repeat("zlib payload without an archive extension\n", 20)
	var zbuf bytes.Buffer
	zw, err := zlib.NewWriterLevel(&zbuf, zlib.DefaultCompression)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := zw.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	src := writeTemp(t, "outer.tar", tarWithEntry(t, "blob", zbuf.String()))

	dir, err := ExtractArchiveToTempDir(t.Context(), malcontent.Config{}, src)
	if err != nil {
		t.Fatalf("ExtractArchiveToTempDir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	// blob itself occupies its stem, so it is extracted into blob_1.
	pkgsWantFile(t, filepath.Join(dir, "blob_1", "blob"), payload)
	pkgsWantAbsent(t, filepath.Join(dir, "blob"))
}

// TestExtractArchiveToTempDirUPXMemberKept verifies that a member recognized
// as UPX-packed by its content is unpacked beside itself and that the packed
// original stays, so findings on the packing are still reported. A stand-in
// named by MALCONTENT_UPX_PATH plays upx, so no real upx is needed; setting
// the environment rules out t.Parallel.
func TestExtractArchiveToTempDirUPXMemberKept(t *testing.T) {
	t.Setenv("MALCONTENT_UPX_PATH", upxStandIn(t, "Unpacked 1 file.", "", 0))

	packed := "\x7fELF\x02\x01\x01\x00UPX!packed payload"
	// Compressing the scanned archive keeps the UPX marker out of its own
	// bytes, so only the member is recognized as UPX-packed.
	src := writeTemp(t, "outer.tar.gz", gzipBytes(t, tarWithEntry(t, "tool", packed)))

	dir, err := ExtractArchiveToTempDir(t.Context(), malcontent.Config{}, src)
	if err != nil {
		t.Fatalf("ExtractArchiveToTempDir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	pkgsWantFile(t, filepath.Join(dir, "tool"), packed)
	// The stand-in leaves its input as it found it, so the unpacked copy
	// holds the same bytes; tool itself occupies its stem.
	pkgsWantFile(t, filepath.Join(dir, "tool_1", "tool"), packed)
}

// TestExtractArchiveToTempDirLeavesOrdinaryFiles verifies that members that
// are not archives, including an empty one named like an archive, are left as
// they are with nothing created beside them.
func TestExtractArchiveToTempDirLeavesOrdinaryFiles(t *testing.T) {
	t.Parallel()

	members := map[string]string{
		"README":    "no extension\n",
		"empty.tar": "",
		"notes.txt": "plain notes\n",
	}
	scanned, err := os.ReadFile(writeTar(t, []tarEntry{
		{name: "README", typeflag: tar.TypeReg, body: members["README"]},
		{name: "empty.tar", typeflag: tar.TypeReg, body: members["empty.tar"]},
		{name: "notes.txt", typeflag: tar.TypeReg, body: members["notes.txt"]},
	}))
	if err != nil {
		t.Fatal(err)
	}

	dir, err := ExtractArchiveToTempDir(t.Context(), malcontent.Config{}, writeTemp(t, "outer.tar", scanned))
	if err != nil {
		t.Fatalf("ExtractArchiveToTempDir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	got := make([]string, 0, len(entries))
	for _, e := range entries {
		got = append(got, e.Name())
	}
	if want := []string{"README", "empty.tar", "notes.txt"}; !slices.Equal(got, want) {
		t.Errorf("extracted entries: got = %v, want = %v", got, want)
	}
	for name, body := range members {
		pkgsWantFile(t, filepath.Join(dir, name), body)
	}
}

// TestExtractArchiveToTempDirZlibContent verifies that a zlib stream is
// recognized by its content and decompressed, both as the scanned archive and
// nested inside another archive.
func TestExtractArchiveToTempDirZlibContent(t *testing.T) {
	t.Parallel()

	payload := strings.Repeat("zlib payload ", 20)
	var zbuf bytes.Buffer
	// Stored blocks guarantee the control bytes that tell a zlib stream from
	// text during content detection.
	zw, err := zlib.NewWriterLevel(&zbuf, zlib.NoCompression)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := zw.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	compressed := zbuf.Bytes()

	tests := []struct {
		name     string
		filename string
		data     []byte
		output   string
		absent   string
	}{
		{
			name:     "zlib stream as the scanned archive",
			filename: "blob.zlib",
			data:     compressed,
			output:   "blob",
		},
		{
			name:     "zlib stream nested in a tar",
			filename: "outer.tar",
			data:     tarWithEntry(t, "inner.zlib", string(compressed)),
			output:   filepath.Join("inner", "inner"),
			absent:   "inner.zlib",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir, err := ExtractArchiveToTempDir(t.Context(), malcontent.Config{}, writeTemp(t, tt.filename, tt.data))
			if err != nil {
				t.Fatalf("ExtractArchiveToTempDir: %v", err)
			}
			t.Cleanup(func() { _ = os.RemoveAll(dir) })

			pkgsWantFile(t, filepath.Join(dir, tt.output), payload)
			if tt.absent != "" {
				pkgsWantAbsent(t, filepath.Join(dir, tt.absent))
			}
		})
	}
}

func TestExtractArchiveToTempDirNestedFailure(t *testing.T) {
	t.Parallel()

	// A full block of non-header bytes fails the tar reader outright.
	bad := strings.Repeat("x", 2*tarBlockSize)
	src := writeTemp(t, "outer.tar", tarWithEntry(t, "bad.tar", bad))

	tests := []struct {
		name           string
		exitExtraction bool
		wantErr        bool
	}{
		{name: "failure is returned when extraction failures are fatal", exitExtraction: true, wantErr: true},
		{name: "failed archive is retained for scanning", exitExtraction: false, wantErr: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir, err := ExtractArchiveToTempDir(t.Context(), malcontent.Config{ExitExtraction: tt.exitExtraction}, src)
			if dir != "" {
				t.Cleanup(func() { _ = os.RemoveAll(dir) })
			}
			if got := err != nil; got != tt.wantErr {
				t.Fatalf("ExtractArchiveToTempDir error: got = %v, want error = %v", err, tt.wantErr)
			}
			if tt.wantErr {
				if dir != "" {
					t.Errorf("returned directory: got = %q, want = empty", dir)
				}
				return
			}
			pkgsWantFile(t, filepath.Join(dir, "bad.tar"), bad)
			// Nothing was extracted, so no empty directory is left beside it.
			pkgsWantAbsent(t, filepath.Join(dir, "bad"))
		})
	}
}

// pkgsSyncBuffer is a bytes.Buffer safe for the concurrent writes a log
// handler may receive.
type pkgsSyncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *pkgsSyncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *pkgsSyncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// TestEffectiveConcurrencyForQuota verifies that a cgroup quota lowers the
// effective concurrency to itself, never below one.
func TestEffectiveConcurrencyForQuota(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		quotaCPUs  int
		gomaxprocs int
		configured int
		want       int
	}{
		{name: "quota of one CPU limits concurrency to one", quotaCPUs: 1, gomaxprocs: 8, configured: 4, want: 1},
		{name: "quota reported as zero still allows one", quotaCPUs: 0, gomaxprocs: 8, configured: 4, want: 1},
		{name: "quota above the configured value leaves it", quotaCPUs: 6, gomaxprocs: 8, configured: 4, want: 4},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := effectiveConcurrencyFor(tt.quotaCPUs, true, tt.gomaxprocs, tt.configured); got != tt.want {
				t.Errorf("effectiveConcurrencyFor(%d, true, %d, %d): got = %d, want = %d", tt.quotaCPUs, tt.gomaxprocs, tt.configured, got, tt.want)
			}
		})
	}
}

// TestValidateResolvedPathMissingDirectory verifies that a target is judged
// against the extraction directory itself even when neither the directory nor
// the target's parent exists yet.
func TestValidateResolvedPathMissingDirectory(t *testing.T) {
	t.Parallel()

	base := t.TempDir()
	dir := filepath.Join(base, "extract")

	tests := []struct {
		name    string
		target  string
		wantErr bool
	}{
		{name: "target beneath the missing directory is accepted", target: filepath.Join(dir, "sub", "x"), wantErr: false},
		{name: "target in a sibling whose name extends the directory name is rejected", target: filepath.Join(base, "extract2", "x"), wantErr: true},
		{name: "target in an unrelated missing directory is rejected", target: filepath.Join(base, "other", "x"), wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateResolvedPath(tt.target, dir, "x")
			if got := err != nil; got != tt.wantErr {
				t.Errorf("ValidateResolvedPath error: got = %v, want error = %v", err, tt.wantErr)
			}
		})
	}
}

// TestHandleSymlinkParentLimit verifies that a link target may climb only as
// many levels as the link's own directory lies beneath the extraction
// directory, including for a dangling target that later checks cannot
// resolve.
func TestHandleSymlinkParentLimit(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		link    string
		target  string
		wantErr bool
	}{
		{name: "link at the top climbing one level is rejected", link: "l", target: "../pkgs-absent-target", wantErr: true},
		{name: "link one level down climbing one level is accepted", link: "sub/l", target: "../pkgs-absent-target", wantErr: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			err := handleSymlink(openTestRoot(t, dir), tt.link, tt.target)
			if got := err != nil; got != tt.wantErr {
				t.Fatalf("handleSymlink error: got = %v, want error = %v", err, tt.wantErr)
			}
			if tt.wantErr {
				pkgsWantAbsent(t, filepath.Join(dir, tt.link))
				return
			}
			pkgsWantSymlink(t, filepath.Join(dir, filepath.FromSlash(tt.link)), tt.target)
		})
	}
}

// TestHandleSymlinkRemovesLinkResolvingOutside verifies that a link whose
// target stays lexically inside the extraction directory, but resolves
// outside it through a link already there, is rejected and removed.
func TestHandleSymlinkRemovesLinkResolvingOutside(t *testing.T) {
	t.Parallel()

	base := t.TempDir()
	outside := filepath.Join(base, "outside")
	dir := filepath.Join(base, "extract")
	for _, d := range []string{outside, dir} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "out")); err != nil {
		t.Fatal(err)
	}

	if err := handleSymlink(openTestRoot(t, dir), "l", "out/secret.txt"); err == nil {
		t.Error("handleSymlink error: got = nil, want = link resolving outside the extraction directory")
	}
	pkgsWantAbsent(t, filepath.Join(dir, "l"))
}

// TestExtractNestedArchiveMissingFile verifies that a candidate no longer on
// disk is passed over without error.
func TestExtractNestedArchiveMissingFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	ctx := t.Context()
	if err := extractNestedArchive(ctx, malcontent.Config{}, dir, "missing.tar", xsync.NewMap[string, bool](), clog.FromContext(ctx), 1); err != nil {
		t.Fatalf("extractNestedArchive error: got = %v, want = nil", err)
	}
	pkgsWantAbsent(t, filepath.Join(dir, "missing"))
}

// TestExtractArchiveToTempDirFatalFailureLeavesNothing verifies that a fatal
// extraction failure removes the temporary directory it would have returned.
// It points TMPDIR at its own directory, so it does not run in parallel.
func TestExtractArchiveToTempDirFatalFailureLeavesNothing(t *testing.T) {
	// Inputs are written before TMPDIR is redirected, because t.TempDir
	// honors TMPDIR and would otherwise leave them in the directory under test.
	inputs := t.TempDir()
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)

	// A full block of non-header bytes fails the tar reader outright.
	bad := strings.Repeat("x", 2*tarBlockSize)
	tests := []struct {
		name string
		data []byte
	}{
		{name: "scanned archive fails to extract", data: append(validTar(t), "trailing payload"...)},
		{name: "nested archive fails to extract", data: tarWithEntry(t, "bad.tar", bad)},
	}

	for i, tt := range tests {
		in := filepath.Join(inputs, fmt.Sprintf("outer%d.tar", i))
		if err := os.WriteFile(in, tt.data, 0o600); err != nil {
			t.Fatal(err)
		}
		t.Run(tt.name, func(t *testing.T) {
			dir, err := ExtractArchiveToTempDir(t.Context(), malcontent.Config{ExitExtraction: true}, in)
			if err == nil {
				_ = os.RemoveAll(dir)
				t.Fatal("ExtractArchiveToTempDir error: got = nil, want = extraction failure")
			}
			entries, err := os.ReadDir(tmp)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 0 {
				t.Errorf("entries left in the temporary directory: got = %d, want = 0", len(entries))
			}
		})
	}
}

// TestExtractArchiveToTempDirRetainedArchiveNotReexamined verifies that a
// scanned archive retained after a failed extraction is not examined again,
// which would report it as an archive containing a copy of itself.
func TestExtractArchiveToTempDirRetainedArchiveNotReexamined(t *testing.T) {
	t.Parallel()

	var logs pkgsSyncBuffer
	logger := clog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelWarn}))
	ctx := clog.WithLogger(t.Context(), logger)
	src := writeTemp(t, "trailing.tar", append(validTar(t), "trailing payload"...))

	dir, err := ExtractArchiveToTempDir(ctx, malcontent.Config{}, src)
	if err != nil {
		t.Fatalf("ExtractArchiveToTempDir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	if _, err := os.Lstat(filepath.Join(dir, "trailing.tar")); err != nil {
		t.Errorf("retained archive: got = %v, want = present", err)
	}
	if got := logs.String(); strings.Contains(got, "identical to an archive containing it") {
		t.Errorf("warnings: got = %q, want = none reporting the retained archive as a copy of itself", got)
	}
}

// TestExtractorsReportUnusableDestination verifies that an extraction
// directory that cannot be created is reported as such rather than surfacing
// as an extractor panic.
func TestExtractorsReportUnusableDestination(t *testing.T) {
	t.Parallel()

	rpmPayload := pkgsCompress(t, pkgsGzip, pkgsCPIO(t, pkgsRPMLayout()))
	tests := []struct {
		name    string
		extract func(context.Context, string, string) error
		src     func(t *testing.T) string
	}{
		{
			name:    "tar",
			extract: ExtractTar,
			src: func(t *testing.T) string {
				t.Helper()
				return writeTemp(t, "pkg.tar", validTar(t))
			},
		},
		{
			name:    "rpm",
			extract: ExtractRPM,
			src: func(t *testing.T) string {
				t.Helper()
				return writeTemp(t, "pkg.rpm", pkgsRPM(pkgsCPIOFormat, pkgsGzip, rpmPayload))
			},
		},
		{
			name:    "deb",
			extract: ExtractDeb,
			src: func(t *testing.T) string {
				t.Helper()
				return pkgsDeb(t, []tarEntry{{name: "./tool", typeflag: tar.TypeReg, body: "tool"}})
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// A directory cannot be created beneath a regular file.
			blocker := writeTemp(t, "blocker", []byte("a regular file"))

			err := tt.extract(t.Context(), filepath.Join(blocker, "out"), tt.src(t))
			if err == nil || !strings.Contains(err.Error(), "failed to create extraction directory") {
				t.Errorf("error: got = %v, want = failure to create the extraction directory", err)
			}
			if errors.Is(err, ErrExtractorPanic) {
				t.Errorf("error: got = %v, want = not an extractor panic", err)
			}
		})
	}
}

// TestExtractArchiveToTempDirGzipByContent verifies that a gzip stream is
// decompressed whether its name or only its content identifies it, and that
// data merely starting with the gzip magic bytes is left as it is.
func TestExtractArchiveToTempDirGzipByContent(t *testing.T) {
	t.Parallel()

	payload := strings.Repeat("gzip payload\n", 20)
	compressed := string(gzipBytes(t, []byte(payload)))
	const invalid = "\x1f\x8bnot really a gzip stream"

	tests := []struct {
		name    string
		scanned string
		data    []byte
		want    map[string]string
		absent  []string
	}{
		{
			// blob itself occupies its stem, so it is extracted into blob_1.
			name:    "extensionless gzip member is decompressed beside itself",
			scanned: "outer.tar",
			data:    tarWithEntry(t, "blob", compressed),
			want:    map[string]string{"blob_1/blob": payload},
			absent:  []string{"blob"},
		},
		{
			name:    "gzip member named .gzip is decompressed",
			scanned: "outer.tar",
			data:    tarWithEntry(t, "notes.gzip", compressed),
			want:    map[string]string{"notes/notes": payload},
			absent:  []string{"notes.gzip"},
		},
		{
			name:    "data starting with the gzip magic but invalid is left alone",
			scanned: "outer.tar",
			data:    tarWithEntry(t, "fake", invalid),
			want:    map[string]string{"fake": invalid},
			absent:  []string{"fake_1"},
		},
		{
			name:    "extensionless gzip file is decompressed when scanned",
			scanned: "blob",
			data:    []byte(compressed),
			want:    map[string]string{"blob": payload},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir, err := ExtractArchiveToTempDir(t.Context(), malcontent.Config{}, writeTemp(t, tt.scanned, tt.data))
			if err != nil {
				t.Fatalf("ExtractArchiveToTempDir: %v", err)
			}
			t.Cleanup(func() { _ = os.RemoveAll(dir) })

			for rel, want := range tt.want {
				pkgsWantFile(t, filepath.Join(dir, filepath.FromSlash(rel)), want)
			}
			for _, rel := range tt.absent {
				pkgsWantAbsent(t, filepath.Join(dir, filepath.FromSlash(rel)))
			}
		})
	}
}
