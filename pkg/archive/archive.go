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
	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/chainguard-dev/malcontent/pkg/pool"
	"github.com/chainguard-dev/malcontent/pkg/programkind"
)

const (
	extractBuffer = 64 * 1024 // 64KB
	maxBytes      = 1 << 31   // 2048MB
	zipBuffer     = 2 * 1024  // 2KB
)

var (
	archivePool, tarPool, zipPool *pool.BufferPool
	initializeOnce                sync.Once
)

// isValidPath checks if the target file is within the given directory.
func IsValidPath(target, dir string) bool {
	return strings.HasPrefix(filepath.Clean(target), filepath.Clean(dir))
}

func extractNestedArchive(ctx context.Context, c malcontent.Config, d string, f string, extracted *sync.Map, logger *clog.Logger) error {
	if ctx.Err() != nil {
		return ctx.Err()
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
	ft, err := programkind.File(fullPath)
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

	if err := os.MkdirAll(archivePath, 0o755); err != nil {
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

	files, err := os.ReadDir(d)
	if err != nil {
		return fmt.Errorf("failed to read directory after extraction: %w", err)
	}

	for _, file := range files {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		rel := file.Name()
		if _, alreadyProcessed := extracted.Load(rel); !alreadyProcessed {
			if err := extractNestedArchive(ctx, c, d, rel, extracted, logger); err != nil {
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
	ft, err := programkind.File(path)
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
			if err := extractNestedArchive(ctx, c, tmpDir, rel, &extractedFiles, logger); err != nil {
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
	buf := tarPool.Get(extractBuffer) //nolint:nilaway // the buffer pool is created above
	defer tarPool.Put(buf)

	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		return fmt.Errorf("failed to create parent directory: %w", err)
	}

	out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer out.Close()

	written, err := io.CopyBuffer(out, io.LimitReader(tr, maxBytes), buf)
	if err != nil {
		if (strings.Contains(err.Error(), "unexpected EOF") && written == 0) ||
			!strings.Contains(err.Error(), "unexpected EOF") {
			return fmt.Errorf("failed to copy file: %w", err)
		}
	}
	if written >= maxBytes {
		return fmt.Errorf("file exceeds maximum allowed size (%d bytes): %s", maxBytes, target)
	}

	return nil
}

// handleSymlink creates valid symlinks when extracting .deb or .tar archives.
func handleSymlink(dir, linkName, target string) error {
	// Skip symlinks for targets that do not exist
	_, err := os.Readlink(target)
	if os.IsNotExist(err) {
		return nil
	}

	fullLink := filepath.Join(dir, linkName)

	// Remove existing symlinks
	if _, err := os.Lstat(fullLink); err == nil {
		if err := os.Remove(fullLink); err != nil {
			return fmt.Errorf("failed to remove existing symlink: %w", err)
		}
	}

	if err := os.Symlink(target, fullLink); err != nil {
		return fmt.Errorf("failed to create symlink: %w", err)
	}

	linkReal, err := filepath.EvalSymlinks(fullLink)
	if err != nil {
		os.Remove(fullLink)
		return fmt.Errorf("failed to evaluate symlink: %w", err)
	}
	if !IsValidPath(linkReal, dir) {
		os.Remove(fullLink)
		return fmt.Errorf("symlink points outside temporary directory: %s", linkReal)
	}

	return nil
}
