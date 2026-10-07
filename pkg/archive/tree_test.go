// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"archive/tar"
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/chainguard-dev/malcontent/pkg/file"
	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/chainguard-dev/malcontent/pkg/programkind"
	"github.com/minio/sha256-simd"
)

// treeTestArchive writes a .tar.gz holding a text file, an empty file named
// like an archive, and a zip holding one file. It returns the archive's path
// and the zip.
func treeTestArchive(t *testing.T) (string, []byte) {
	t.Helper()
	inner := decZip(t, decZipEntries([]tarEntry{{name: "x.txt", typeflag: tar.TypeReg, body: "inner"}}))
	return decWrite(t, "outer.tar.gz", decGzip(t, decTar(t, []tarEntry{
		{name: "a.txt", typeflag: tar.TypeReg, body: "hello"},
		{name: "empty.zip", typeflag: tar.TypeReg},
		{name: "inner.zip", typeflag: tar.TypeReg, body: string(inner)},
	}))), inner
}

// openTestTree opens the archive at path as a Tree that the test closes.
func openTestTree(t *testing.T, c malcontent.Config, path string) *Tree {
	t.Helper()
	tree, err := OpenTree(decCtx(t), c, path)
	if err != nil {
		t.Fatalf("OpenTree: %v", err)
	}
	t.Cleanup(func() { _ = tree.Close() })
	return tree
}

// treeKind detects the kind of rel within tree.
func treeKind(t *testing.T, tree *Tree, rel string) *programkind.FileType {
	t.Helper()
	ft, err := programkind.File(decCtx(t), filepath.Join(tree.Dir(), rel))
	if err != nil {
		t.Fatalf("programkind.File(%s): %v", rel, err)
	}
	return ft
}

func TestTreeExtractsNestedArchivesOnRequest(t *testing.T) {
	t.Parallel()
	path, inner := treeTestArchive(t)
	tree := openTestTree(t, malcontent.Config{}, path)

	files, err := tree.Files(tree.Dir())
	if err != nil {
		t.Fatalf("Files: %v", err)
	}
	want := []TreeFile{{Rel: "a.txt", Size: 5}, {Rel: "empty.zip", Size: 0}, {Rel: "inner.zip", Size: int64(len(inner))}}
	if !slices.Equal(files, want) {
		t.Fatalf("Files: got = %v, want = %v", files, want)
	}

	if _, ok := tree.Nested("a.txt", 5, treeKind(t, tree, "a.txt")); ok {
		t.Errorf("Nested(a.txt): got an archive, want none")
	}
	if _, ok := tree.Nested("empty.zip", 0, nil); ok {
		t.Errorf("Nested(empty.zip): got an archive, want none for an empty file")
	}
	n, ok := tree.Nested("inner.zip", int64(len(inner)), treeKind(t, tree, "inner.zip"))
	if !ok || n.Rel() != "inner.zip" {
		t.Fatalf("Nested(inner.zip): got = %q, %t, want = inner.zip, true", n.Rel(), ok)
	}
	if tree.Extracted("inner.zip") {
		t.Fatalf("Extracted(inner.zip) before extraction: got = true, want = false")
	}

	dir, lineage, kept, err := tree.ExtractNested(decCtx(t), n, 1, tree.Root(), sha256.Sum256(inner))
	if err != nil || kept || dir != filepath.Join(tree.Dir(), "inner") {
		t.Fatalf("ExtractNested: got = %q, kept %t, %v, want = %q, not kept, nil", dir, kept, err, filepath.Join(tree.Dir(), "inner"))
	}
	if lineage.a == nil || lineage.a.digest != sha256.Sum256(inner) || lineage.a.parent != tree.Root().a {
		t.Errorf("ExtractNested lineage: got = %+v, want the zip within the root archive", lineage.a)
	}
	nestedFiles, err := tree.Files(dir)
	if err != nil {
		t.Fatalf("Files(%s): %v", dir, err)
	}
	if want := []TreeFile{{Rel: filepath.Join("inner", "x.txt"), Size: 5}}; !slices.Equal(nestedFiles, want) {
		t.Errorf("Files(%s): got = %v, want = %v", dir, nestedFiles, want)
	}
	if !tree.Extracted("inner.zip") {
		t.Errorf("Extracted(inner.zip) after extraction: got = false, want = true")
	}
	if _, ok := tree.Nested("inner.zip", int64(len(inner)), nil); ok {
		t.Errorf("Nested(inner.zip) after extraction: got an archive, want none")
	}
	if _, err := file.StatIn(tree.Dir(), "inner.zip"); !os.IsNotExist(err) {
		t.Errorf("inner.zip after extraction: got stat error %v, want it removed", err)
	}
}

func TestTreeKeepsArchivesItDoesNotExtract(t *testing.T) {
	t.Parallel()
	path, inner := treeTestArchive(t)
	outer, err := file.ReadFileIn(filepath.Dir(path), filepath.Base(path))
	if err != nil {
		t.Fatalf("read archive: %v", err)
	}
	tests := []struct {
		name   string
		c      malcontent.Config
		depth  int
		digest [sha256.Size]byte
	}{
		{name: "an archive identical to the archive containing it", depth: 1, digest: sha256.Sum256(outer)},
		{name: "an archive past the nesting limit", depth: nestingLimit(0) + 1, digest: sha256.Sum256(inner)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tree := openTestTree(t, tt.c, path)
			n, ok := tree.Nested("inner.zip", int64(len(inner)), nil)
			if !ok {
				t.Fatalf("Nested(inner.zip): got none, want an archive")
			}
			dir, _, kept, err := tree.ExtractNested(decCtx(t), n, tt.depth, tree.Root(), tt.digest)
			if err != nil || !kept || dir != "" {
				t.Fatalf("ExtractNested: got = %q, kept %t, %v, want = \"\", kept, nil", dir, kept, err)
			}
			if !tree.Extracted("inner.zip") {
				t.Errorf("Extracted(inner.zip): got = false, want = true")
			}
			if _, err := file.StatIn(tree.Dir(), "inner.zip"); err != nil {
				t.Errorf("inner.zip: got stat error %v, want it kept", err)
			}
		})
	}
}

func TestTreeExtractNestedErrors(t *testing.T) {
	t.Parallel()
	path, inner := treeTestArchive(t)

	t.Run("past the nesting limit when extraction errors exit", func(t *testing.T) {
		t.Parallel()
		tree := openTestTree(t, malcontent.Config{ExitExtraction: true}, path)
		n, _ := tree.Nested("inner.zip", int64(len(inner)), nil)
		if _, _, _, err := tree.ExtractNested(decCtx(t), n, nestingLimit(0)+1, tree.Root(), sha256.Sum256(inner)); err == nil || !strings.Contains(err.Error(), "exceeds limit") {
			t.Errorf("ExtractNested: got = %v, want a nesting limit error", err)
		}
	})
	t.Run("after the tree is closed", func(t *testing.T) {
		t.Parallel()
		tree := openTestTree(t, malcontent.Config{}, path)
		n, _ := tree.Nested("inner.zip", int64(len(inner)), nil)
		if err := tree.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		if _, err := file.StatIn(filepath.Dir(tree.Dir()), filepath.Base(tree.Dir())); !os.IsNotExist(err) {
			t.Fatalf("directory after Close: got stat error %v, want it removed", err)
		}
		if _, _, _, err := tree.ExtractNested(decCtx(t), n, 1, tree.Root(), sha256.Sum256(inner)); err == nil || !strings.Contains(err.Error(), "failed to open extraction directory") {
			t.Errorf("ExtractNested: got = %v, want an error opening the directory", err)
		}
	})
}

func TestTreeFiles(t *testing.T) {
	t.Parallel()
	path, _ := treeTestArchive(t)
	tree := openTestTree(t, malcontent.Config{}, path)
	if err := openTestRoot(t, tree.Dir()).Symlink("a.txt", "link.txt"); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	files, err := tree.Files(tree.Dir())
	if err != nil {
		t.Fatalf("Files: %v", err)
	}
	for _, f := range files {
		if f.Rel == "link.txt" {
			t.Errorf("Files: got %v, want no symbolic links", files)
		}
	}
	if _, err := tree.Files(filepath.Join(tree.Dir(), "missing")); err == nil {
		t.Errorf("Files(missing): got nil error, want one")
	}
}

func TestOpenTree(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		file     string
		data     []byte
		c        malcontent.Config
		wantErr  string
		retained string
	}{
		{name: "a file that is not an archive", file: "notes.txt", data: []byte("plain text\n"), wantErr: "unsupported archive type"},
		{name: "a corrupt archive is retained", file: "broken.tar.gz", data: []byte("\x1f\x8b\x08\x00not gzip data at all"), retained: "broken.tar.gz"},
		{name: "an empty archive extracts to nothing", file: "empty.tar.gz", data: nil},
		{name: "a corrupt archive fails when extraction errors exit", file: "broken.tar.gz", data: []byte("\x1f\x8b\x08\x00not gzip data at all"), c: malcontent.Config{ExitExtraction: true}, wantErr: "failed to extract"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			path := decWrite(t, tt.file, tt.data)
			tree, err := OpenTree(decCtx(t), tt.c, path)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("OpenTree: got = %v, want an error containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("OpenTree: %v", err)
			}
			t.Cleanup(func() { _ = tree.Close() })
			files, err := tree.Files(tree.Dir())
			if err != nil {
				t.Fatalf("Files: %v", err)
			}
			var want []TreeFile
			if tt.retained != "" {
				want = []TreeFile{{Rel: tt.retained, Size: int64(len(tt.data))}}
				if !tree.Extracted(tt.retained) {
					t.Errorf("Extracted(%s): got = false, want = true", tt.retained)
				}
			}
			if !slices.Equal(files, want) {
				t.Errorf("Files: got = %v, want = %v", files, want)
			}
		})
	}
}

func TestOpenTreeLeavesNoDirectoryOnFailure(t *testing.T) {
	// Not parallel: t.Setenv points temporary directories at a private one.
	path := decWrite(t, "broken.tar.gz", []byte("\x1f\x8b\x08\x00not gzip data at all"))
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	if _, err := OpenTree(decCtx(t), malcontent.Config{ExitExtraction: true}, path); err == nil {
		t.Fatalf("OpenTree: got nil error, want one")
	}
	entries, err := fs.ReadDir(openTestRoot(t, tmp).FS(), ".")
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("temporary directory after a failed OpenTree: got %d entries, want none", len(entries))
	}
}

func TestOpenTreeCanceled(t *testing.T) {
	t.Parallel()
	path, _ := treeTestArchive(t)
	ctx, cancel := context.WithCancel(decCtx(t))
	cancel()
	if _, err := OpenTree(ctx, malcontent.Config{}, path); err == nil {
		t.Errorf("OpenTree: got nil error, want the context's")
	}
}
