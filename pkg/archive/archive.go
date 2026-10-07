// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"

	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/malcontent/pkg/file"
	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/chainguard-dev/malcontent/pkg/pool"
	"github.com/chainguard-dev/malcontent/pkg/programkind"
	"github.com/minio/sha256-simd"
	"github.com/puzpuzpuz/xsync/v4"
	"golang.org/x/sync/semaphore"
)

// extractPool supplies the copy buffer of every extractor.
var extractPool pool.BufferPool

// effectiveConcurrencyFor returns min(configured, gomaxprocs, quota) with a
// floor of 1. quotaOK=false disables the cgroup arm.
func effectiveConcurrencyFor(quotaCPUs int, quotaOK bool, gomaxprocs, configured int) int {
	n := max(1, configured)
	if g := max(1, gomaxprocs); g < n {
		n = g
	}
	if quotaOK {
		if q := max(1, quotaCPUs); q < n {
			n = q
		}
	}
	return n
}

// EffectiveMaxConcurrency clamps the operator-configured concurrency to the
// minimum of itself, runtime.GOMAXPROCS(0), and the cgroup CPU quota.
func EffectiveMaxConcurrency(configured int) int {
	q, ok := CPUQuota()
	return effectiveConcurrencyFor(q, ok, runtime.GOMAXPROCS(0), configured)
}

var extractionSemaphoreOnce = sync.OnceValue(func() *semaphore.Weighted {
	return semaphore.NewWeighted(int64(EffectiveMaxConcurrency(runtime.GOMAXPROCS(0))))
})

// extractionSemaphore is the process-wide weighted semaphore that bounds the
// number of concurrent extraction goroutines across every archive type.
func extractionSemaphore() *semaphore.Weighted {
	return extractionSemaphoreOnce()
}

// newArchiveCounter resolves the effective byte and ratio caps from the
// context-attached Config and returns a ready-to-use ArchiveCounter seeded
// with inputBytes as the ratio denominator. This centralizes the three-line
// resolve-and-construct pattern shared by every extractor.
func newArchiveCounter(ctx context.Context, inputBytes int64) *file.ArchiveCounter {
	maxBytes, maxRatio := resolveArchiveCaps(ctx)
	return &file.ArchiveCounter{
		MaxBytes:   maxBytes,
		MaxRatio:   maxRatio,
		InputBytes: inputBytes,
	}
}

// ValidateResolvedPath checks that the target path still resides within the extraction directory
// after resolving symlinks in every existing component of its parent directory. Components that
// do not exist yet are created as real directories, so they cannot redirect the path.
func ValidateResolvedPath(target, dir, clean string) error {
	resolvedParent, err := resolveExisting(filepath.Dir(target))
	if err != nil {
		return fmt.Errorf("failed to resolve parent directory of %s: %w", clean, err)
	}
	resolvedDir, err := resolveExisting(dir)
	if err != nil {
		return fmt.Errorf("failed to resolve extraction directory: %w", err)
	}
	resolvedTarget := filepath.Join(resolvedParent, filepath.Base(target))
	if !IsValidPath(resolvedTarget, resolvedDir) {
		return fmt.Errorf("path traversal via symlink in parent directory: %s", clean)
	}
	return nil
}

// resolveExisting resolves symlinks in the longest existing prefix of path and
// appends the remaining, not yet created, elements unchanged.
func resolveExisting(path string) (string, error) {
	suffix := ""
	for p := filepath.Clean(path); ; p = filepath.Dir(p) {
		resolved, err := filepath.EvalSymlinks(p)
		switch {
		case err == nil:
			return filepath.Join(resolved, suffix), nil
		case !errors.Is(err, fs.ErrNotExist) || filepath.Dir(p) == p:
			return "", err
		}
		suffix = filepath.Join(filepath.Base(p), suffix)
	}
}

// depthWithin reports how many directories path lies beneath root, and false
// if path is outside root.
func depthWithin(path, root string) (int, bool) {
	rel, err := filepath.Rel(root, path)
	switch {
	case err != nil, rel == "..", strings.HasPrefix(rel, ".."+string(filepath.Separator)):
		return 0, false
	case rel == ".":
		return 0, true
	default:
		return strings.Count(rel, string(filepath.Separator)) + 1, true
	}
}

// leadingParents counts the ".." elements that begin a cleaned relative path.
// filepath.Clean leaves ".." only at the start of a relative path.
func leadingParents(clean string) int {
	n := 0
	for elem := range strings.SplitSeq(clean, string(filepath.Separator)) {
		if elem != ".." {
			break
		}
		n++
	}
	return n
}

// openRoot opens dir, creating it if needed. Every file operation made through
// the returned Root stays beneath dir, even when it follows a symlink that the
// archive being extracted planted.
func openRoot(dir string) (*os.Root, error) {
	// The directory almost always exists already.
	if root, err := os.OpenRoot(dir); err == nil {
		return root, nil
	}
	if err := file.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("failed to create extraction directory: %w", err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to open extraction directory: %w", err)
	}
	return root, nil
}

// rootRelative joins name to the root directory as filepath.Join does and
// returns the result relative to root, rejecting names that leave it.
func rootRelative(root *os.Root, name string) (string, error) {
	full := filepath.Join(root.Name(), name)
	if !IsValidPath(full, root.Name()) {
		return "", fmt.Errorf("path outside extraction directory: %s", name)
	}
	return filepath.Rel(root.Name(), full)
}

// createFile creates or truncates name beneath root along with its parent
// directories. A symlink at name is replaced rather than followed.
func createFile(root *os.Root, name string) (*os.File, error) {
	// Each Root call walks every path element, so try the common case, a new
	// file in an existing directory, first. An exclusive create never follows
	// a symlink.
	out, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, fs.ErrNotExist) {
		if err := root.MkdirAll(filepath.Dir(name), 0o700); err != nil {
			return nil, fmt.Errorf("failed to create parent directory: %w", err)
		}
		out, err = root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	}
	if errors.Is(err, fs.ErrExist) {
		if err := removeSymlink(root, name); err != nil {
			return nil, err
		}
		out, err = root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to create file: %w", err)
	}
	return out, nil
}

// removeSymlink removes a symlink at name so that a write replaces the link
// rather than following it.
func removeSymlink(root *os.Root, name string) error {
	fi, err := root.Lstat(name)
	if err != nil || fi.Mode()&os.ModeSymlink == 0 {
		return nil //nolint:nilerr // nothing to remove; opening name reports any real failure
	}
	if err := root.Remove(name); err != nil {
		return fmt.Errorf("failed to remove existing symlink: %w", err)
	}
	return nil
}

// lstatPath returns the FileInfo of path without following a final symlink.
// Symlinks on the way to its parent directory are followed to reach it, so a
// parent that leads outside an extraction directory still has its link
// examined.
func lstatPath(path string) (fs.FileInfo, error) {
	return file.LstatIn(filepath.Dir(path), filepath.Base(path))
}

// symlinkEscapesDir checks whether a symlink at target, examined with lstat,
// resolves outside dir.
func symlinkEscapesDir(target, dir string, lstat func(string) (fs.FileInfo, error)) bool {
	fi, err := lstat(target)
	if err != nil || fi.Mode()&os.ModeSymlink == 0 {
		return false
	}

	evalTarget, err := filepath.EvalSymlinks(target)
	if err != nil {
		// Dangling symlinks (target doesn't exist) are not path traversals.
		return !errors.Is(err, fs.ErrNotExist)
	}

	evalDir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return true
	}

	rel, err := filepath.Rel(evalDir, evalTarget)
	if err != nil {
		return false
	}
	return rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// IsValidPath checks if the target file is within the given directory.
func IsValidPath(target, dir string) bool {
	return pathWithin(target, dir, lstatPath)
}

// pathWithin is IsValidPath examining a symlink at target with lstat.
func pathWithin(target, dir string, lstat func(string) (fs.FileInfo, error)) bool {
	if strings.Contains(target, "\x00") || strings.Contains(dir, "\x00") {
		return false
	}

	cleanTarget := filepath.Clean(target)
	cleanDir := filepath.Clean(dir)

	if symlinkEscapesDir(cleanTarget, cleanDir, lstat) {
		return false
	}

	switch {
	case cleanDir == "", cleanTarget == "":
		return false
	case !strings.HasPrefix(cleanTarget, cleanDir):
		return false
	case cleanTarget == cleanDir:
		return true
	case len(cleanTarget) > len(cleanDir):
		nextChar := cleanTarget[len(cleanDir)]
		return nextChar == filepath.Separator || nextChar == '/'
	default:
		return false
	}
}

// maxNestingDepth is the safety bound on nested extraction when
// Config.MaxDepth leaves the depth unlimited (zero or negative). An archive
// that holds a copy of itself is stopped sooner, by content digest; this bound
// stops archives built to nest without end through distinct copies.
const maxNestingDepth = 64

// nestingLimit returns the deepest nesting level extraction may reach: the
// configured MaxDepth, or maxNestingDepth when MaxDepth leaves it unlimited.
func nestingLimit(maxDepth int) int {
	if maxDepth > 0 {
		return maxDepth
	}
	return maxNestingDepth
}

// ancestry is the chain of SHA-256 digests of the archives that contain a
// nested archive, innermost first. A nil *ancestry is an empty chain.
type ancestry struct {
	digest [sha256.Size]byte
	parent *ancestry
}

// contains reports whether digest belongs to any archive in the chain.
func (a *ancestry) contains(digest [sha256.Size]byte) bool {
	for ; a != nil; a = a.parent {
		if a.digest == digest {
			return true
		}
	}
	return false
}

// nestedCandidate is an archive awaiting nested extraction: its path relative
// to the extraction root, its nesting level, and the archives containing it.
type nestedCandidate struct {
	rel       string
	depth     int
	ancestors *ancestry
}

// nestedTree records what one extraction tree has processed: the paths,
// relative to the extraction root, that need no further extraction, and the
// digest of the scanned archive at its root, which contains every archive in
// the tree. root is set before extraction starts, and extracted is safe for
// concurrent use, so archives may be extracted concurrently.
type nestedTree struct {
	extracted *xsync.Map[string, bool]
	root      *ancestry
}

func newNestedTree(extracted *xsync.Map[string, bool]) *nestedTree {
	return &nestedTree{extracted: extracted}
}

// contentDigest returns the SHA-256 digest of everything r yields.
func contentDigest(r io.Reader) ([sha256.Size]byte, error) {
	var sum [sha256.Size]byte
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return sum, fmt.Errorf("failed to hash archive: %w", err)
	}
	copy(sum[:], h.Sum(nil))
	return sum, nil
}

// setRoot records the archive at path, which lies outside the extraction
// directory, as the one containing every archive in the tree.
func (tree *nestedTree) setRoot(path string) error {
	f, err := file.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open archive for hashing: %w", err)
	}
	defer f.Close()

	digest, err := contentDigest(f)
	if err != nil {
		return err
	}
	tree.root = &ancestry{digest: digest}
	return nil
}

// archiveDigest returns the SHA-256 digest of name beneath root.
func archiveDigest(root *os.Root, name string) ([sha256.Size]byte, error) {
	f, err := root.Open(name)
	if err != nil {
		return [sha256.Size]byte{}, fmt.Errorf("failed to open archive for hashing: %w", err)
	}
	defer f.Close()
	return contentDigest(f)
}

// extractNestedArchive extracts f, relative to d, found at nesting level
// depth, and then every archive within what that extraction produced, each one
// level deeper. Only the directories that extraction creates are searched for
// further archives, so each archive is examined once however deeply it nests.
func extractNestedArchive(ctx context.Context, c malcontent.Config, d string, f string, extracted *xsync.Map[string, bool], logger *clog.Logger, depth int) error {
	return newNestedTree(extracted).extract(ctx, c, d, f, logger, depth)
}

// extract is extractNestedArchive within an extraction tree that may already
// hold extracted archives.
func (tree *nestedTree) extract(ctx context.Context, c malcontent.Config, d string, f string, logger *clog.Logger, depth int) (err error) {
	defer recoverExtractor(ctx, "nested", filepath.Join(d, f), &err)

	limit := nestingLimit(c.MaxDepth)
	queue := []nestedCandidate{{rel: f, depth: depth, ancestors: tree.root}}
	for len(queue) > 0 {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		next := queue[0]
		queue = queue[1:]

		dir, lineage, err := tree.extractFile(ctx, c, d, next, limit, logger)
		if err != nil {
			return nestedError(f, next.rel, err)
		}
		if dir == "" {
			continue
		}

		found, err := nestedArchiveCandidates(d, dir)
		if err != nil {
			return fmt.Errorf("failed to read directory after extraction: %w", err)
		}
		for _, rel := range found {
			queue = append(queue, nestedCandidate{rel: rel, depth: next.depth + 1, ancestors: lineage})
		}
	}
	return nil
}

// nestedError names the failing archive rel when it was found inside f rather
// than being f itself. Archives found inside f lie beneath the directory f was
// extracted into, so their paths never equal f.
func nestedError(f, rel string, err error) error {
	if rel == f {
		return err
	}
	return fmt.Errorf("process nested file %s: %w", rel, err)
}

// nestedArchiveCandidates returns the regular files beneath dir, as paths
// relative to root. Every one is a candidate, because UPX binaries and zlib
// streams are recognized by content rather than by name. WalkDir does not
// follow symlinks, so the search stays within dir.
func nestedArchiveCandidates(root, dir string) ([]string, error) {
	sub, err := filepath.Rel(root, dir)
	if err != nil {
		return nil, fmt.Errorf("filepath.Rel: %w", err)
	}
	var found []string
	err = walkTree(root, sub, func(rel string, entry fs.DirEntry) error {
		if entry.Type().IsRegular() {
			found = append(found, rel)
		}
		return nil
	})
	return found, err
}

// extractFile extracts the candidate, relative to d, when it is a non-empty
// regular file holding an archive that lies within the nesting limit and is
// not byte-identical to an archive containing it. It returns the directory it
// extracted into, or "" when it did not attempt extraction, along with the
// chain of archives containing whatever that directory holds. The directory is
// returned even when extraction failed and the archive was retained, because
// whatever was extracted before the failure is still scanned. The Root it
// opens on d is closed before the caller searches that directory, so nesting
// does not hold a descriptor per level.
func (tree *nestedTree) extractFile(ctx context.Context, c malcontent.Config, d string, candidate nestedCandidate, limit int, logger *clog.Logger) (string, *ancestry, error) {
	f := candidate.rel
	root, err := os.OpenRoot(d)
	if err != nil {
		return "", nil, fmt.Errorf("failed to open extraction directory: %w", err)
	}
	defer root.Close()

	fullPath := filepath.Join(d, f)
	fi, err := root.Lstat(f)
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil, nil
	}
	if err != nil {
		return "", nil, fmt.Errorf("failed to stat file: %w", err)
	}

	// Never follow a symlink: its target may lie outside the extraction
	// directory, and a link to an archive inside it is extracted on its own.
	// An empty file holds nothing to extract, so it skips the type check.
	if !fi.Mode().IsRegular() || fi.Size() == 0 {
		return "", nil, nil
	}

	if _, isExtracted := tree.extracted.Load(f); isExtracted {
		return "", nil, nil
	}

	ft, err := programkind.File(ctx, fullPath)
	if err != nil {
		return "", nil, fmt.Errorf("failed to determine file type: %w", err)
	}

	n, ok := nestedArchive(f, ft)
	if !ok {
		return "", nil, nil
	}

	dir, lineage, _, err := tree.extractNested(ctx, c, root, d, n, candidate.depth, candidate.ancestors, limit, logger, func() ([sha256.Size]byte, error) {
		return archiveDigest(root, f)
	})
	return dir, lineage, err
}

// nested is a file holding an archive that nested extraction unpacks.
type nested struct {
	rel     string
	extract func(context.Context, string, string) error
	// keep leaves the archive beside what it unpacks to.
	keep bool
}

// nestedArchive returns how to unpack rel, a file whose detected kind is ft,
// or false when it holds no archive that extraction handles.
func nestedArchive(rel string, ft *programkind.FileType) (nested, bool) {
	isArchive := false
	_, archiveExt := programkind.ArchiveMap[programkind.GetExt(rel)]
	switch {
	case ft != nil && ft.MIME == "application/x-upx":
		isArchive = true
	case ft != nil && ft.MIME == "application/zlib":
		isArchive = true
	case isGzipType(ft):
		isArchive = true
	case archiveExt:
		isArchive = true
	}

	if !isArchive {
		return nested{}, false
	}

	n := nested{rel: rel}
	switch {
	case ft != nil && ft.MIME == "application/x-upx":
		// The packed binary stays beside its unpacked copy, so that findings
		// on the packing itself are still reported.
		n.extract, n.keep = ExtractUPX, true
	case ft != nil && ft.MIME == "application/zlib":
		n.extract = ExtractZlib
	default:
		n.extract = extractorFor(programkind.GetExt(rel), ft)
	}

	if n.extract == nil {
		return nested{}, false
	}
	return n, true
}

// extractNested unpacks n, relative to d, whose Root is root, found at
// nesting level depth within the archives ancestors, when it lies within the
// nesting limit and is not byte-identical to an archive containing it.
// digestOf returns the SHA-256 digest of n's content. extractNested returns
// the directory it extracted into, or "" when there is nothing to search, the
// chain of archives containing whatever that directory holds, and whether n
// itself stays in the tree, to be scanned as a file.
func (tree *nestedTree) extractNested(ctx context.Context, c malcontent.Config, root *os.Root, d string, n nested, depth int, ancestors *ancestry, limit int, logger *clog.Logger, digestOf func() ([sha256.Size]byte, error)) (string, *ancestry, bool, error) {
	f := n.rel
	fullPath := filepath.Join(d, f)

	if depth > limit {
		err := fmt.Errorf("current depth of %d exceeds limit of %d which may be an indicator of compromise", depth, limit)
		if c.ExitExtraction {
			return "", nil, false, err
		}
		// Failing here would discard everything extracted above this
		// archive. Keep it, and leave this archive to be scanned as a file.
		logger.Warnf("not extracting %s, scanning it as it is: %v", f, err)
		tree.extracted.Store(f, true)
		return "", nil, true, nil
	}

	// An archive identical to one that contains it would yield another copy
	// of itself each time it is extracted, without end. It stays in place and
	// is scanned as it is. Identical archives elsewhere in the tree are still
	// extracted, so that findings are reported at each location.
	digest, err := digestOf()
	if err != nil {
		return "", nil, false, err
	}
	if ancestors.contains(digest) {
		logger.Warnf("not extracting %s, scanning it as it is: identical to an archive containing it, which may be an indicator of compromise", f)
		tree.extracted.Store(f, true)
		return "", nil, true, nil
	}
	lineage := &ancestry{digest: digest, parent: ancestors}

	dirName, err := makeExtractionDir(root, strings.TrimSuffix(f, programkind.GetExt(f)))
	if err != nil {
		return "", nil, false, err
	}
	archivePath := filepath.Join(d, dirName)

	err = n.extract(ctx, archivePath, fullPath)
	if err != nil {
		if c.ExitExtraction {
			return "", nil, false, fmt.Errorf("failed to extract archive: %w", err)
		}
		logger.Warnf("extraction failed for %s, retaining archive for scanning: %s", f, err.Error())
		tree.extracted.Store(f, true)
		// Remove succeeds only on an empty directory. When the extractor wrote
		// nothing, the retained archive is all that is left behind, and there
		// is nothing to search for further archives.
		if root.Remove(dirName) == nil {
			return "", nil, true, nil
		}
		return archivePath, lineage, true, nil
	}

	tree.extracted.Store(f, true)

	// any archives which cannot be extracted will be scanned like non-archive files
	if n.keep {
		return archivePath, lineage, true, nil
	}
	if err := root.Remove(f); err != nil {
		return "", nil, false, fmt.Errorf("failed to remove archive file: %w", err)
	}
	return archivePath, lineage, false, nil
}

// isGzipType reports whether ft is a gzip stream detected by content.
func isGzipType(ft *programkind.FileType) bool {
	if ft == nil {
		return false
	}
	_, ok := GzMIME[ft.MIME]
	return ok
}

// extractorFor returns the extractor for a file with extension ext and
// detected type ft. The extension decides when it names an archive, so that a
// gzip-compressed tar is unpacked as a tar; otherwise a gzip stream detected
// by content is decompressed whatever its name.
func extractorFor(ext string, ft *programkind.FileType) func(context.Context, string, string) error {
	known := func() *programkind.FileType { return ft }
	if extract := extractionMethodWithKind(ext, known); extract != nil {
		return extract
	}
	if isGzipType(ft) {
		return func(ctx context.Context, d, f string) error { return extractGzipWithKind(ctx, d, f, known) }
	}
	return nil
}

// makeExtractionDir creates the directory name beneath root and returns the
// name it created. Some packages hold an archive beside a file of the name it
// would extract to, such as demo_page.css.gz beside demo_page.css; when name
// is taken, the first free one of name_1, name_2, and so on is used instead,
// so that extracted paths, and the reports keyed by them, match on every run.
func makeExtractionDir(root *os.Root, name string) (string, error) {
	if _, err := root.Lstat(name); errors.Is(err, fs.ErrNotExist) {
		if err := root.MkdirAll(name, 0o700); err != nil {
			return "", fmt.Errorf("failed to create extraction directory: %w", err)
		}
		return name, nil
	}
	for i := range maxCollisionNames {
		candidate := name + "_" + strconv.Itoa(i+1)
		err := root.Mkdir(candidate, 0o700)
		if err == nil {
			return candidate, nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return "", fmt.Errorf("failed to create extraction directory: %w", err)
		}
	}
	return "", fmt.Errorf("no unused extraction directory name derived from %s", name)
}

// ExtractArchiveToTempDir creates a temporary directory and extracts the
// archive file, and every archive nested within it, for scanning.
func ExtractArchiveToTempDir(ctx context.Context, c malcontent.Config, path string) (string, error) {
	t, err := OpenTree(ctx, c, path)
	if err != nil {
		return "", err
	}

	// WalkDir reads a directory's entries before visiting them, so it never
	// reaches the directories that nested extraction creates beside each
	// archive; the tree searches those itself.
	err = walkTree(t.dir, ".", func(rel string, d fs.DirEntry) error {
		// Every regular file is a candidate, because UPX binaries and zlib
		// streams are recognized by content rather than by name.
		if !d.Type().IsRegular() {
			return nil
		}
		return t.tree.extract(ctx, c, t.dir, rel, t.logger, 1)
	})
	if err != nil {
		cleanupTempDir(ctx, t.dir)
		return "", fmt.Errorf("failed to walk directory: %w", err)
	}

	return t.dir, nil
}

// walkTree calls fn, in lexical order, with every entry beneath sub, a
// directory relative to dir, read through a root on dir, and its path
// relative to dir. Like filepath.WalkDir, it reads a directory's entries
// before visiting them and does not follow symlinks.
func walkTree(dir, sub string, fn func(rel string, d fs.DirEntry) error) error {
	r, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer r.Close()
	return file.WalkDir(r, filepath.ToSlash(sub), func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		return fn(filepath.FromSlash(path), d)
	})
}

// cleanupTempDir removes an extraction directory that will not be returned to
// the caller, which would otherwise have no handle with which to remove it.
func cleanupTempDir(ctx context.Context, dir string) {
	if err := file.RemoveAllIn(filepath.Dir(dir), filepath.Base(dir)); err != nil {
		clog.ErrorContextf(ctx, "remove %s: %v", dir, err)
	}
}

// retainArchive places an archive that could not be fully extracted into the
// extraction directory so that it still reaches the scan corpus, returning its
// name relative to that directory.
func retainArchive(dir, path string) (string, error) {
	name := filepath.Base(path)
	target := filepath.Join(dir, name)
	if !IsValidPath(target, dir) {
		return "", fmt.Errorf("invalid retention path for %s", name)
	}

	root, err := os.OpenRoot(dir)
	if err != nil {
		return "", fmt.Errorf("failed to open extraction directory: %w", err)
	}
	defer root.Close()

	// The archive lies outside dir, so it is copied in rather than linked.
	// Extraction may already have written an entry under this name, in which
	// case the copy takes a new one beside it.
	if _, err := root.Lstat(name); err == nil {
		tmp, tmpName, err := file.CreateTemp(root, name+"_*")
		if err != nil {
			return "", fmt.Errorf("failed to create retention file: %w", err)
		}
		defer tmp.Close()
		if err := copyArchiveContents(tmp, path); err != nil {
			return "", err
		}
		return tmpName, nil
	}

	dst, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", fmt.Errorf("failed to create retention file: %w", err)
	}
	defer dst.Close()

	if err := copyArchiveContents(dst, path); err != nil {
		return "", err
	}
	return name, nil
}

func copyArchiveContents(dst io.Writer, path string) error {
	src, err := file.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open archive for retention: %w", err)
	}
	defer src.Close()

	if _, err := io.Copy(dst, src); err != nil {
		return fmt.Errorf("failed to copy archive for retention: %w", err)
	}
	return nil
}

func ExtractionMethod(ext string) func(context.Context, string, string) error {
	return extractionMethodWithKind(ext, nil)
}

// extractionMethodWithKind is ExtractionMethod for an archive whose detected type,
// when known, fileType reports, so that the extractor does not read the
// archive again to detect it. A nil fileType leaves detection to the
// extractor.
func extractionMethodWithKind(ext string, fileType func() *programkind.FileType) func(context.Context, string, string) error {
	// The ordering of these statements is important, especially for extensions
	// that are substrings of other extensions (e.g., `.gz` and `.tar.gz` or `.tgz`)
	switch ext {
	// New cases should go below this line so that the lengthier tar extensions are evaluated first
	case ".apk", ".gem", ".tar", ".tar.bz2", ".tar.gz", ".tgz", ".tar.xz", ".tbz", ".xz":
		if fileType == nil {
			return ExtractTar
		}
		return func(ctx context.Context, d, f string) error { return extractTarWithKind(ctx, d, f, fileType) }
	case ".gz", ".gzip":
		if fileType == nil {
			return ExtractGzip
		}
		return func(ctx context.Context, d, f string) error { return extractGzipWithKind(ctx, d, f, fileType) }
	case ".ear", ".jar", ".war", ".whl", ".zip":
		if fileType == nil {
			return ExtractZip
		}
		return func(ctx context.Context, d, f string) error { return extractZipWithKind(ctx, d, f, fileType) }
	case ".bz2", ".bzip2":
		return ExtractBz2
	case ".zst", ".zstd":
		return ExtractZstd
	case ".rpm":
		return ExtractRPM
	case ".deb":
		return ExtractDeb
	default:
		return nil
	}
}

// handleDirectory extracts valid directories within .deb or .tar archives.
func handleDirectory(root *os.Root, name string) error {
	if err := root.MkdirAll(name, 0o700); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}
	return nil
}

// handleFile extracts valid files within .deb or .tar archives. A nil
// counter disables byte and ratio accounting.
func handleFile(er *entryRoots, name string, tr *tar.Reader, counter *file.ArchiveCounter) error {
	buf := extractPool.Get()
	defer extractPool.Put(buf)

	out, err := er.createFile(name)
	if err != nil {
		return err
	}
	defer func() { _ = out.Close() }()

	// Bound the read to the remaining archive budget so that a single oversize
	// member cannot exhaust the per-level byte cap. Read one byte past the
	// remaining budget so a member sized exactly at the limit is
	// distinguishable from a truncated oversize member. When the counter is
	// nil (accounting disabled), Remaining returns MaxInt64; cap the limit to
	// avoid int64 overflow on the +1.
	rem := counter.Remaining()
	readLimit := rem + 1
	if rem == math.MaxInt64 {
		readLimit = math.MaxInt64
	}
	// os.File.ReadFrom would ignore buf for a tar source and allocate its own
	// buffer per entry, so out is hidden behind a plain Writer.
	written, err := io.CopyBuffer(struct{ io.Writer }{out}, io.LimitReader(tr, readLimit), buf)
	if err != nil {
		if (errors.Is(err, io.ErrUnexpectedEOF) && written == 0) ||
			!errors.Is(err, io.ErrUnexpectedEOF) {
			return fmt.Errorf("failed to copy file: %w", err)
		}
	}

	// Account for written bytes; chunk through int range in case io.CopyBuffer
	// produced more than fits in a single int on a 32-bit platform.
	for remaining := written; remaining > 0; {
		chunk := remaining
		const maxChunk = int64(1<<31 - 1)
		if chunk > maxChunk {
			chunk = maxChunk
		}
		if capErr := counter.Add(int(chunk)); capErr != nil {
			return fmt.Errorf("tar extraction aborted on %s: %w", name, capErr)
		}
		remaining -= chunk
	}

	return nil
}

// handleSymlink creates valid symlinks when extracting .deb or .tar archives.
// linkPath is where the symlink will be created (relative to root).
// linkTarget is what the symlink points to.
//
// The kernel follows any symlink it meets while resolving a target, so "a/.."
// need not lead back to the directory holding "a", and validating the target
// lexically is unsound. Instead, the link is created with the cleaned target,
// whose only ".." elements lead it, and those may not climb above root from the
// directory that really holds the link. A link created this way resolves within
// root regardless of which other links exist now or are created later, so it
// is safe to follow even for code that does not use os.Root.
func handleSymlink(root *os.Root, linkPath, linkTarget string) error {
	name, err := rootRelative(root, linkPath)
	if err != nil {
		return fmt.Errorf("symlink location outside extraction directory: %w", err)
	}
	if name == "." {
		return fmt.Errorf("symlink location is the extraction directory: %s", linkPath)
	}

	// Skip absolute symlink targets
	if filepath.IsAbs(linkTarget) {
		return nil
	}

	if err := root.MkdirAll(filepath.Dir(name), 0o700); err != nil {
		return fmt.Errorf("failed to create parent directory for symlink: %w", err)
	}

	// Root cannot report where a path really leads, so measure the depth of
	// the link's parent directory from its fully resolved path.
	parentDir, err := filepath.EvalSymlinks(filepath.Join(root.Name(), filepath.Dir(name)))
	if err != nil {
		return fmt.Errorf("failed to resolve symlink parent directory: %w", err)
	}
	resolvedDir, err := filepath.EvalSymlinks(root.Name())
	if err != nil {
		return fmt.Errorf("failed to resolve extraction directory: %w", err)
	}
	depth, ok := depthWithin(parentDir, resolvedDir)
	if !ok {
		return fmt.Errorf("symlink location outside extraction directory: %s", linkPath)
	}

	target := filepath.Clean(linkTarget)
	if leadingParents(target) > depth {
		return fmt.Errorf("symlink target escapes extraction directory: %s -> %s", linkPath, linkTarget)
	}

	// Create the link in the directory whose depth was just measured.
	loc, err := filepath.Rel(resolvedDir, filepath.Join(parentDir, filepath.Base(name)))
	if err != nil {
		return fmt.Errorf("failed to locate symlink: %w", err)
	}

	// Remove existing symlinks
	if _, err := root.Lstat(loc); err == nil {
		if err := root.Remove(loc); err != nil {
			return fmt.Errorf("failed to remove existing symlink: %w", err)
		}
	}

	if err := root.Symlink(target, loc); err != nil {
		return fmt.Errorf("failed to create symlink: %w", err)
	}

	actualTarget, err := root.Readlink(loc)
	if err != nil {
		_ = root.Remove(loc)
		return fmt.Errorf("failed to verify symlink target: %w", err)
	}
	if actualTarget != target {
		_ = root.Remove(loc)
		return fmt.Errorf("symlink target mismatch: expected %s, got %s", target, actualTarget)
	}

	// Post-creation validation resolving every component of the link
	if resolved, err := filepath.EvalSymlinks(filepath.Join(resolvedDir, loc)); err == nil && !IsValidPath(resolved, resolvedDir) {
		_ = root.Remove(loc)
		return fmt.Errorf("symlink target escapes extraction directory after creation: %s -> %s", linkPath, actualTarget)
	}

	return nil
}

// handleHardlink creates valid hardlinks when extracting .deb or .tar archives.
// linkPath is where the hardlink will be created (relative to root).
// linkTarget is the existing file the hardlink points to (relative to root).
func handleHardlink(root *os.Root, linkPath, linkTarget string) error {
	newname, err := rootRelative(root, linkPath)
	if err != nil {
		return fmt.Errorf("hardlink location outside extraction directory: %w", err)
	}
	oldname, err := rootRelative(root, linkTarget)
	if err != nil {
		return fmt.Errorf("hardlink target outside extraction directory: %w", err)
	}
	if newname == oldname {
		return nil
	}

	fi, err := root.Lstat(oldname)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to stat hardlink target: %w", err)
	}

	// A hardlink to a symlink is a second symlink whose target resolves from
	// its own location, so recreate it as one and validate it there.
	if fi.Mode()&os.ModeSymlink != 0 {
		symlinkTarget, err := root.Readlink(oldname)
		if err != nil {
			return fmt.Errorf("failed to read hardlink target: %w", err)
		}
		return handleSymlink(root, newname, symlinkTarget)
	}

	// Each Root call walks every path element, so link first and create the
	// parent or remove an existing entry only when the link fails for that.
	err = root.Link(oldname, newname)
	if errors.Is(err, fs.ErrNotExist) {
		if err := root.MkdirAll(filepath.Dir(newname), 0o700); err != nil {
			return fmt.Errorf("failed to create parent directory for hardlink: %w", err)
		}
		err = root.Link(oldname, newname)
	}
	if errors.Is(err, fs.ErrExist) {
		if err := root.Remove(newname); err != nil {
			return fmt.Errorf("failed to remove existing file for hardlink: %w", err)
		}
		err = root.Link(oldname, newname)
	}
	if err != nil {
		return fmt.Errorf("failed to create hardlink: %w", err)
	}
	return nil
}
