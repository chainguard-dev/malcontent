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
	"strings"
	"sync"

	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/malcontent/pkg/file"
	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/chainguard-dev/malcontent/pkg/pool"
	"github.com/chainguard-dev/malcontent/pkg/programkind"
	"github.com/puzpuzpuz/xsync/v4"
	"golang.org/x/sync/semaphore"
)

var archivePool, tarPool, zipPool *pool.BufferPool

func init() {
	// Initialize pools for direct use in one location
	archivePool = pool.NewBufferPool(runtime.GOMAXPROCS(0))
	tarPool = pool.NewBufferPool(runtime.GOMAXPROCS(0))
	zipPool = pool.NewBufferPool(runtime.GOMAXPROCS(0) * 2)
}

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
	if err := os.MkdirAll(dir, 0o700); err != nil {
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

// symlinkEscapesDir checks whether a symlink at target resolves outside dir.
func symlinkEscapesDir(target, dir string) bool {
	fi, err := os.Lstat(target)
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

// isValidPath checks if the target file is within the given directory.
func IsValidPath(target, dir string) bool {
	if strings.Contains(target, "\x00") || strings.Contains(dir, "\x00") {
		return false
	}

	cleanTarget := filepath.Clean(target)
	cleanDir := filepath.Clean(dir)

	if symlinkEscapesDir(cleanTarget, cleanDir) {
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

func extractNestedArchive(ctx context.Context, c malcontent.Config, d string, f string, extracted *xsync.Map[string, bool], logger *clog.Logger, depth int) (err error) {
	defer recoverExtractor(ctx, "nested", filepath.Join(d, f), &err)
	if ctx.Err() != nil {
		return ctx.Err()
	}

	// Check depth limit (0 or -1 means unlimited, positive values are limits)
	if c.MaxDepth > 0 && depth > c.MaxDepth {
		return fmt.Errorf("current depth of %d exceeds limit of %d which may be an indicator of compromise", depth, c.MaxDepth)
	}

	attempted, err := extractNestedFile(ctx, c, d, f, extracted, logger)
	if err != nil || !attempted {
		return err
	}

	entries, err := os.ReadDir(d)
	if err != nil {
		return fmt.Errorf("failed to read directory after extraction: %w", err)
	}

	for _, entry := range entries {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		rel := entry.Name()
		if _, alreadyProcessed := extracted.Load(rel); !alreadyProcessed {
			if err := extractNestedArchive(ctx, c, d, rel, extracted, logger, depth+1); err != nil {
				return fmt.Errorf("process nested file %s: %w", rel, err)
			}
		}
	}
	return nil
}

// extractNestedFile extracts f, relative to d, when it is a regular file
// holding an archive, and reports whether extraction was attempted. The Root
// it opens on d is closed before the caller recurses, so nesting does not
// hold a descriptor per level.
func extractNestedFile(ctx context.Context, c malcontent.Config, d string, f string, extracted *xsync.Map[string, bool], logger *clog.Logger) (bool, error) {
	root, err := os.OpenRoot(d)
	if err != nil {
		return false, fmt.Errorf("failed to open extraction directory: %w", err)
	}
	defer root.Close()

	fullPath := filepath.Join(d, f)
	fi, err := root.Lstat(f)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("failed to stat file: %w", err)
	}

	// Never follow a symlink: its target may lie outside the extraction
	// directory, and a link to an archive inside it is extracted on its own.
	if !fi.Mode().IsRegular() {
		return false, nil
	}

	if _, isExtracted := extracted.Load(f); isExtracted {
		return false, nil
	}

	isArchive := false
	ft, err := programkind.File(ctx, fullPath)
	if err != nil {
		return false, fmt.Errorf("failed to determine file type: %w", err)
	}

	switch {
	case ft != nil && ft.MIME == "application/x-upx":
		isArchive = true
	case ft != nil && ft.MIME == "application/zlib":
		isArchive = true
	case programkind.ArchiveMap[programkind.GetExt(f)]:
		isArchive = true
	}

	if !isArchive {
		return false, nil
	}

	var extract func(context.Context, string, string) error
	switch {
	case ft != nil && ft.MIME == "application/x-upx":
		extract = ExtractUPX
	case ft != nil && ft.MIME == "application/zlib":
		extract = ExtractZlib
	default:
		extract = ExtractionMethod(programkind.GetExt(fullPath))
	}

	if extract == nil {
		return false, nil
	}

	archiveName := strings.TrimSuffix(f, programkind.GetExt(f))
	archivePath := filepath.Join(d, archiveName)
	// Some packages may have archives and files with colliding names
	// e.g., demo_page.css and demo_page.css.gz
	// the former is the uncompressed version of the latter
	// if we encounter this, use os.MkdirTemp to create a unique directory.
	// Root has no MkdirTemp, but the parent is a directory found by walking d,
	// so no symlink can redirect it.
	if _, err := root.Lstat(archiveName); err == nil {
		logger.Debugf("duplicate file name already exists, modifying directory name for %s", archivePath)
		var mkErr error
		archivePath, mkErr = os.MkdirTemp(filepath.Dir(archivePath), filepath.Base(archivePath)+"_*")
		if mkErr != nil {
			return false, fmt.Errorf("failed to create unique extraction directory: %w", mkErr)
		}
	} else if err := root.MkdirAll(archiveName, 0o700); err != nil {
		return false, fmt.Errorf("failed to create extraction directory: %w", err)
	}

	err = extract(ctx, archivePath, fullPath)
	if err != nil {
		if c.ExitExtraction {
			return false, fmt.Errorf("failed to extract archive: %w", err)
		}
		logger.Warnf("extraction failed for %s, retaining archive for scanning: %s", f, err.Error())
	}

	extracted.Store(f, true)

	// only attempt to remove the archive file if we don't encounter an extraction error
	// any archives which cannot be extracted will be scanned like non-archive files
	if err == nil {
		if err := root.Remove(f); err != nil {
			return false, fmt.Errorf("failed to remove archive file: %w", err)
		}
	}
	return true, nil
}

// extractArchiveToTempDir creates a temporary directory and extracts the archive file for scanning.
func ExtractArchiveToTempDir(ctx context.Context, c malcontent.Config, path string) (string, error) {
	if ctx.Err() != nil {
		return "", ctx.Err()
	}

	logger := clog.FromContext(ctx).With("path", path)
	logger.Debug("creating temp dir")

	tmpDir, err := os.MkdirTemp("", filepath.Base(path))
	if err != nil {
		return "", fmt.Errorf("failed to create temp dir: %w", err)
	}

	var extract func(context.Context, string, string) error
	// Check for zlib-compressed files first and use the zlib-specific function
	ft, err := programkind.File(ctx, path)
	if err != nil {
		return "", fmt.Errorf("failed to determine file type: %w", err)
	}

	switch {
	case ft != nil && ft.MIME == "application/zlib":
		extract = ExtractZlib
	case ft != nil && ft.MIME == "application/x-upx":
		extract = ExtractUPX
	default:
		extract = ExtractionMethod(programkind.GetExt(path))
	}

	if extract == nil {
		return "", fmt.Errorf("unsupported archive type: %s", path)
	}
	extractedFiles := xsync.NewMap[string, bool]()

	err = func() (extractErr error) {
		defer recoverExtractor(ctx, "top-level", path, &extractErr)
		return extract(ctx, tmpDir, path)
	}()
	if err != nil {
		if c.ExitExtraction {
			cleanupTempDir(ctx, tmpDir)
			return "", fmt.Errorf("failed to extract %s: %w", path, err)
		}

		// Mirror the nested-archive path: an archive that cannot be fully
		// extracted is retained so that it is scanned as an opaque file. Without
		// this, anything the extractor could not account for leaves the corpus
		// entirely and the scan reports nothing.
		logger.Warnf("extraction failed for %s, retaining archive for scanning: %s", path, err)
		retained, retainErr := retainArchive(tmpDir, path)
		if retainErr != nil {
			cleanupTempDir(ctx, tmpDir)
			return "", fmt.Errorf("failed to retain unextractable archive %s: %w", path, retainErr)
		}
		// The retained archive must not be fed back into extraction below.
		extractedFiles.Store(retained, true)
	}

	err = filepath.WalkDir(tmpDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		if path == tmpDir {
			return nil
		}

		rel, err := filepath.Rel(tmpDir, path)
		if err != nil {
			return fmt.Errorf("filepath.Rel: %w", err)
		}

		ext := programkind.GetExt(path)
		if _, ok := programkind.ArchiveMap[ext]; ok {
			if err := extractNestedArchive(ctx, c, tmpDir, rel, extractedFiles, logger, 1); err != nil {
				return err
			}
		}

		return nil
	})
	if err != nil {
		cleanupTempDir(ctx, tmpDir)
		return "", fmt.Errorf("failed to walk directory: %w", err)
	}

	return tmpDir, nil
}

// cleanupTempDir removes an extraction directory that will not be returned to
// the caller, which would otherwise have no handle with which to remove it.
func cleanupTempDir(ctx context.Context, dir string) {
	if err := os.RemoveAll(dir); err != nil {
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

	// Extraction may already have written an entry under this name. Root has
	// no CreateTemp or cross-root Link, but name is a single element directly
	// beneath dir, so neither can follow a symlink.
	if _, err := root.Lstat(name); err == nil {
		tmp, err := os.CreateTemp(dir, name+"_*")
		if err != nil {
			return "", fmt.Errorf("failed to create retention file: %w", err)
		}
		defer tmp.Close()
		if err := copyArchiveContents(tmp, path); err != nil {
			return "", err
		}
		return filepath.Base(tmp.Name()), nil
	}

	// A hard link avoids duplicating a potentially large archive on disk.
	// It cannot cross filesystems, so fall back to a copy.
	if err := os.Link(path, target); err == nil {
		return name, nil
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
	src, err := os.Open(path) // #nosec G304 -- archive path supplied by the caller and already opened by the extractor
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
	// The ordering of these statements is important, especially for extensions
	// that are substrings of other extensions (e.g., `.gz` and `.tar.gz` or `.tgz`)
	switch ext {
	// New cases should go below this line so that the lengthier tar extensions are evaluated first
	case ".apk", ".gem", ".tar", ".tar.bz2", ".tar.gz", ".tgz", ".tar.xz", ".tbz", ".xz":
		return ExtractTar
	case ".gz", ".gzip":
		return ExtractGzip
	case ".ear", ".jar", ".war", ".whl", ".zip":
		return ExtractZip
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
func handleFile(root *os.Root, name string, tr *tar.Reader, counter *file.ArchiveCounter) error {
	buf := tarPool.Get(file.ExtractBuffer) //nolint:nilaway // the buffer pool is created above
	defer tarPool.Put(buf)

	out, err := createFile(root, name)
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
	written, err := io.CopyBuffer(out, io.LimitReader(tr, readLimit), buf)
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
