package archive

import (
	"archive/tar"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/malcontent/pkg/file"
	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/chainguard-dev/malcontent/pkg/pool"
	"github.com/chainguard-dev/malcontent/pkg/programkind"
)

var (
	archivePool, tarPool, zipPool *pool.BufferPool
	initializeOnce                sync.Once
)

// isValidPath checks if the target file is within the given directory.
func IsValidPath(target, dir string) bool {
	if strings.Contains(target, "\x00") || strings.Contains(dir, "\x00") {
		return false
	}

	cleanTarget := filepath.Clean(target)
	cleanDir := filepath.Clean(dir)

	// avoid evaluating symlinks if the target is not a symlink
	if fi, err := os.Lstat(cleanTarget); err == nil && fi.Mode()&os.ModeSymlink == os.ModeSymlink {
		var evalTarget, evalDir, rel string

		if evalTarget, err = filepath.EvalSymlinks(cleanTarget); err != nil {
			return false
		}
		if evalDir, err = filepath.EvalSymlinks(cleanDir); err != nil {
			return false
		}
		if rel, err = filepath.Rel(evalDir, evalTarget); err == nil &&
			(rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator))) {
			return false
		}
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

func extractNestedArchive(ctx context.Context, c malcontent.Config, d string, f string, extracted *sync.Map, logger *clog.Logger, depth int) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	// Check depth limit (0 or -1 means unlimited, positive values are limits)
	if c.MaxDepth > 0 && depth > c.MaxDepth {
		return fmt.Errorf("current depth of %d exceeds limit of %d which may be an indicator of compromise", depth, c.MaxDepth)
	}

	fullPath := filepath.Join(d, f)
	fi, err := os.Stat(fullPath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to stat file: %w", err)
	}

	if fi.IsDir() {
		return nil
	}

	if _, isExtracted := extracted.Load(f); isExtracted {
		return nil
	}

	isArchive := false
	ft, err := programkind.File(ctx, fullPath)
	if err != nil {
		return fmt.Errorf("failed to determine file type: %w", err)
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
		return nil
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
		return nil
	}

	archivePath := filepath.Join(d, strings.TrimSuffix(f, programkind.GetExt(f)))
	// Some packages may have archives and files with colliding names
	// e.g., demo_page.css and demo_page.css.gz
	// the former is the uncompressed version of the latter
	// if we encounter this, replace the name with something that won't collide
	if _, err := os.Stat(archivePath); err == nil {
		logger.Debugf("duplicate file name already exists, modifying directory name for %s", archivePath)
		archivePath = fmt.Sprintf("%s%d", archivePath, time.Now().UnixNano())
	}

	if err := os.MkdirAll(archivePath, 0o700); err != nil {
		return fmt.Errorf("failed to create extraction directory: %w", err)
	}

	err = extract(ctx, archivePath, fullPath)
	if err != nil {
		if c.ExitExtraction {
			return fmt.Errorf("failed to extract archive: %w", err)
		}
		logger.Debugf("ignoring extraction error for %s: %s", f, err.Error())
	}

	extracted.Store(f, true)

	if err := os.Remove(fullPath); err != nil {
		return fmt.Errorf("failed to remove archive file: %w", err)
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

	initializeOnce.Do(func() {
		archivePool = pool.NewBufferPool(runtime.GOMAXPROCS(0))
	})

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
	err = extract(ctx, tmpDir, path)
	if err != nil {
		return "", fmt.Errorf("failed to extract %s: %w", path, err)
	}

	var extractedFiles sync.Map

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
			if err := extractNestedArchive(ctx, c, tmpDir, rel, &extractedFiles, logger, 1); err != nil {
				return err
			}
		}

		return nil
	})
	if err != nil {
		return "", fmt.Errorf("failed to walk directory: %w", err)
	}

	return tmpDir, nil
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
	case ".jar", ".zip", ".whl":
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
func handleDirectory(target string) error {
	if err := os.MkdirAll(target, 0o700); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}
	return nil
}

// handleFile extracts valid files within .deb or .tar archives.
func handleFile(target string, tr *tar.Reader) error {
	buf := tarPool.Get(file.ExtractBuffer) //nolint:nilaway // the buffer pool is created above
	defer tarPool.Put(buf)

	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		return fmt.Errorf("failed to create parent directory: %w", err)
	}

	out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer out.Close()

	written, err := io.CopyBuffer(out, io.LimitReader(tr, file.MaxBytes), buf)
	if err != nil {
		if (strings.Contains(err.Error(), "unexpected EOF") && written == 0) ||
			!strings.Contains(err.Error(), "unexpected EOF") {
			return fmt.Errorf("failed to copy file: %w", err)
		}
	}
	if written >= file.MaxBytes {
		return fmt.Errorf("file exceeds maximum allowed size (%d bytes): %s", file.MaxBytes, target)
	}

	return nil
}

// handleSymlink creates valid symlinks when extracting .deb or .tar archives.
// linkPath is where the symlink will be created (relative to dir).
// linkTarget is what the symlink points to.
func handleSymlink(dir, linkPath, linkTarget string) error {
	fullPath := filepath.Join(dir, linkPath)

	// Validate symlink location is within extraction directory
	if !IsValidPath(fullPath, dir) {
		return fmt.Errorf("symlink location outside extraction directory: %s", fullPath)
	}

	// Skip absolute symlink targets
	if filepath.IsAbs(linkTarget) {
		return nil
	}

	// Validate relative symlink target resolves within extraction directory
	resolvedTarget := filepath.Clean(filepath.Join(filepath.Dir(fullPath), linkTarget))
	if !IsValidPath(resolvedTarget, dir) {
		return fmt.Errorf("symlink target escapes extraction directory: %s -> %s", linkPath, linkTarget)
	}

	// Ensure parent directory exists
	if err := os.MkdirAll(filepath.Dir(fullPath), 0o700); err != nil {
		return fmt.Errorf("failed to create parent directory for symlink: %w", err)
	}

	// Remove existing symlinks
	if _, err := os.Lstat(fullPath); err == nil {
		if err := os.Remove(fullPath); err != nil {
			return fmt.Errorf("failed to remove existing symlink: %w", err)
		}
	}

	if err := os.Symlink(linkTarget, fullPath); err != nil {
		return fmt.Errorf("failed to create symlink: %w", err)
	}

	actualTarget, err := os.Readlink(fullPath)
	if err != nil {
		os.Remove(fullPath)
		return fmt.Errorf("failed to verify symlink target: %w", err)
	}
	if actualTarget != linkTarget {
		os.Remove(fullPath)
		return fmt.Errorf("symlink target mismatch: expected %s, got %s", linkTarget, actualTarget)
	}

	actualResolved := filepath.Clean(filepath.Join(filepath.Dir(fullPath), actualTarget))
	if !IsValidPath(actualResolved, dir) {
		os.Remove(fullPath)
		return fmt.Errorf("symlink target escapes extraction directory after creation: %s -> %s", linkPath, actualTarget)
	}

	return nil
}

// handleHardlink creates valid hardlinks when extracting .deb or .tar archives.
// linkPath is where the hardlink will be created (relative to dir).
// linkTarget is the existing file the hardlink points to (relative to dir).
func handleHardlink(dir, linkPath, linkTarget string) error {
	fullPath := filepath.Join(dir, linkPath)
	targetPath := filepath.Join(dir, linkTarget)

	if !IsValidPath(fullPath, dir) {
		return fmt.Errorf("hardlink location outside extraction directory: %s", fullPath)
	}

	if !IsValidPath(targetPath, dir) {
		return fmt.Errorf("hardlink target outside extraction directory: %s", targetPath)
	}

	if err := os.MkdirAll(filepath.Dir(fullPath), 0o700); err != nil {
		return fmt.Errorf("failed to create parent directory for hardlink: %w", err)
	}

	// Remove existing file/link at the path
	if _, err := os.Lstat(fullPath); err == nil {
		if err := os.Remove(fullPath); err != nil {
			return fmt.Errorf("failed to remove existing file for hardlink: %w", err)
		}
	}

	if err := os.Link(targetPath, fullPath); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to create hardlink: %w", err)
	}

	linkInfo, err := os.Stat(fullPath)
	if err != nil {
		os.Remove(fullPath)
		return fmt.Errorf("failed to stat hardlink after creation: %w", err)
	}

	targetInfo, err := os.Stat(targetPath)
	if err != nil {
		os.Remove(fullPath)
		return fmt.Errorf("failed to stat hardlink target after creation: %w", err)
	}

	if !os.SameFile(linkInfo, targetInfo) {
		os.Remove(fullPath)
		return fmt.Errorf("hardlink validation failed: link and target are not the same file")
	}

	return nil
}
