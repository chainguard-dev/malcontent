// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/malcontent/pkg/file"
	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/chainguard-dev/malcontent/pkg/programkind"
	"github.com/minio/sha256-simd"
	"github.com/puzpuzpuz/xsync/v4"
)

// Tree is a scanned archive extracted into a temporary directory. The
// archives nested inside it are extracted on request, so that a caller can
// detect the kinds of extracted files concurrently and scan each file as soon
// as nothing will replace it.
//
// The files one extraction produces form a batch. A nested archive is
// extracted into a new directory beside it, named after the entries that
// directory already holds, so ExtractNested must be called for the archives
// of a batch that share a directory one at a time, in the batch's order,
// which is what ExtractArchiveToTempDir does. Archives in different
// directories may be extracted concurrently.
type Tree struct {
	tree   *nestedTree
	c      malcontent.Config
	dir    string
	limit  int
	logger *clog.Logger
}

// Lineage is the chain of archives that contain a file in a Tree.
type Lineage struct {
	a *ancestry
}

// TreeFile is a regular file in a Tree: its path relative to the tree's
// directory and its size.
type TreeFile struct {
	Rel  string
	Size int64
}

// Nested is a file in a Tree that holds an archive to extract.
type Nested struct {
	n nested
}

// Rel returns the path of the archive relative to the tree's directory.
func (n Nested) Rel() string {
	return n.n.rel
}

// OpenTree extracts the archive at path into a new temporary directory,
// reading the archive once to detect its kind and digest its content. An
// archive that cannot be extracted is retained in the directory, to be
// scanned as a file, unless c.ExitExtraction is set. Nested archives are left
// for ExtractNested.
func OpenTree(ctx context.Context, c malcontent.Config, path string) (*Tree, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	logger := clog.FromContext(ctx).With("path", path)

	ft, digest, err := sniffArchive(ctx, path)
	if err != nil {
		return nil, err
	}

	var extract func(context.Context, string, string) error
	switch {
	case ft != nil && ft.MIME == "application/zlib":
		extract = ExtractZlib
	case ft != nil && ft.MIME == "application/x-upx":
		extract = ExtractUPX
	default:
		extract = extractorFor(programkind.GetExt(path), ft)
	}

	if extract == nil {
		return nil, fmt.Errorf("unsupported archive type: %s", path)
	}

	// The scanned archive contains every archive in the tree, so a copy of it
	// nested inside itself is scanned as it is rather than extracted again.
	tree := newNestedTree(xsync.NewMap[string, bool]())
	tree.root = &ancestry{digest: digest}

	// The directory is created only once extraction is certain to be
	// attempted, so the early returns above leave nothing behind.
	logger.Debug("creating temp dir")
	tmpDir, err := os.MkdirTemp("", filepath.Base(path))
	if err != nil {
		return nil, fmt.Errorf("failed to create temp dir: %w", err)
	}

	err = func() (extractErr error) {
		defer recoverExtractor(ctx, "top-level", path, &extractErr)
		return extract(ctx, tmpDir, path)
	}()
	if err != nil {
		if c.ExitExtraction {
			cleanupTempDir(ctx, tmpDir)
			return nil, fmt.Errorf("failed to extract %s: %w", path, err)
		}

		// Mirror the nested-archive path: an archive that cannot be fully
		// extracted is retained so that it is scanned as an opaque file. Without
		// this, anything the extractor could not account for leaves the corpus
		// entirely and the scan reports nothing.
		logger.Warnf("extraction failed for %s, retaining archive for scanning: %s", path, err)
		retained, retainErr := retainArchive(tmpDir, path)
		if retainErr != nil {
			cleanupTempDir(ctx, tmpDir)
			return nil, fmt.Errorf("failed to retain unextractable archive %s: %w", path, retainErr)
		}
		// The retained archive must not be fed back into nested extraction.
		tree.extracted.Store(retained, true)
	}

	return &Tree{
		tree:   tree,
		c:      c,
		dir:    tmpDir,
		limit:  nestingLimit(c.MaxDepth),
		logger: logger,
	}, nil
}

// sniffArchive returns the kind of the archive at path, as programkind.File
// detects it, and the SHA-256 digest of its content. A regular, non-empty
// archive is read once for both.
func sniffArchive(ctx context.Context, path string) (*programkind.FileType, [sha256.Size]byte, error) {
	var digest [sha256.Size]byte
	fi, err := file.Stat(path)
	if err != nil || !fi.Mode().IsRegular() || fi.Size() == 0 {
		ft, err := programkind.File(ctx, path)
		if err != nil {
			return nil, digest, fmt.Errorf("failed to determine file type: %w", err)
		}
		f, err := file.Open(path)
		if err != nil {
			return nil, digest, fmt.Errorf("failed to open archive for hashing: %w", err)
		}
		defer f.Close()
		digest, err = contentDigest(f)
		return ft, digest, err
	}

	f, err := file.Open(path)
	if err != nil {
		return nil, digest, fmt.Errorf("failed to determine file type: open: %w", err)
	}
	contents, err := file.ReadContents(f, fi.Size())
	_ = f.Close()
	if err != nil {
		return nil, digest, fmt.Errorf("failed to determine file type: file contents: %w", err)
	}
	defer contents.Close()

	b := contents.Bytes()
	ft := programkind.Detect(ctx, path, b[:min(int64(len(b)), file.MaxBytes)])
	return ft, sha256.Sum256(b), nil
}

// Dir returns the tree's temporary directory.
func (t *Tree) Dir() string {
	return t.dir
}

// Root returns the lineage of the files the top-level extraction produced.
func (t *Tree) Root() Lineage {
	return Lineage{a: t.tree.root}
}

// Close removes the tree's directory.
func (t *Tree) Close() error {
	return file.RemoveAllIn(filepath.Dir(t.dir), filepath.Base(t.dir))
}

// Files returns the regular files beneath dir, the tree's directory or one
// that ExtractNested returned, in lexical order.
func (t *Tree) Files(dir string) ([]TreeFile, error) {
	sub, err := filepath.Rel(t.dir, dir)
	if err != nil {
		return nil, fmt.Errorf("filepath.Rel: %w", err)
	}
	var files []TreeFile
	err = walkTree(t.dir, sub, func(rel string, entry fs.DirEntry) error {
		if !entry.Type().IsRegular() {
			return nil
		}
		fi, err := entry.Info()
		if err != nil {
			return err
		}
		files = append(files, TreeFile{Rel: rel, Size: fi.Size()})
		return nil
	})
	return files, err
}

// Extracted reports whether rel needs no further extraction: it was
// extracted, retained after failing to extract, or kept by the nesting
// limits.
func (t *Tree) Extracted(rel string) bool {
	_, ok := t.tree.extracted.Load(rel)
	return ok
}

// Nested reports whether rel, a regular file of the given size in the tree
// whose detected kind is ft, holds an archive to extract.
func (t *Tree) Nested(rel string, size int64, ft *programkind.FileType) (Nested, bool) {
	if size == 0 || t.Extracted(rel) {
		return Nested{}, false
	}
	n, ok := nestedArchive(rel, ft)
	return Nested{n: n}, ok
}

// ExtractNested extracts n, found depth levels deep within lineage, whose
// content has the SHA-256 digest digest. It returns the directory holding
// what extraction produced, or "" when there is nothing to search, the
// lineage of the files in that directory, and whether n itself stays in the
// tree, to be scanned as a file.
func (t *Tree) ExtractNested(ctx context.Context, n Nested, depth int, lineage Lineage, digest [sha256.Size]byte) (dir string, inner Lineage, kept bool, err error) {
	defer recoverExtractor(ctx, "nested", filepath.Join(t.dir, n.n.rel), &err)

	root, err := os.OpenRoot(t.dir)
	if err != nil {
		return "", Lineage{}, false, fmt.Errorf("failed to open extraction directory: %w", err)
	}
	defer root.Close()

	dir, a, kept, err := t.tree.extractNested(ctx, t.c, root, t.dir, n.n, depth, lineage.a, t.limit, t.logger, func() ([sha256.Size]byte, error) {
		return digest, nil
	})
	return dir, Lineage{a: a}, kept, err
}
