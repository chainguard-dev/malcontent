package archive

import (
	"archive/tar"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/malcontent/pkg/pool"
	"github.com/chainguard-dev/malcontent/pkg/programkind"
)

const (
	// 1024MB file limit.
	maxBytes = 1 << 30
)

var (
	bufferPool     *pool.SlicePool
	initializeOnce sync.Once
)

// isValidPath checks if the target file is within the given directory.
func IsValidPath(target, dir string) bool {
	return strings.HasPrefix(filepath.Clean(target), filepath.Clean(dir))
}

// ExtractArchiveToTempDir creates a temporary directory and extracts the archive file for scanning.
func ExtractArchiveToTempDir(ctx context.Context, path string) (string, error) {
	logger := clog.FromContext(ctx).With("path", path)
	logger.Debug("creating temp dir")

	tmpDir, err := os.MkdirTemp("", filepath.Base(path))
	if err != nil {
		return "", fmt.Errorf("failed to create temp dir: %w", err)
	}

	initializeOnce.Do(func() {
		bufferPool = pool.NewBufferPool()
	})

	var extract func(context.Context, string, string) error
	ft, err := programkind.File(path)
	defer programkind.Put(ft)
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
		os.RemoveAll(tmpDir)
		return "", fmt.Errorf("failed to extract %s: %w", path, err)
	}

	var extractedFiles sync.Map

	var processDir func(string) error
	processDir = func(dir string) error {
		files, err := os.ReadDir(dir)
		if err != nil {
			return fmt.Errorf("failed to read directory %s: %w", dir, err)
		}

		for _, file := range files {
			fullPath := filepath.Join(dir, file.Name())

			if file.IsDir() {
				if err := processDir(fullPath); err != nil {
					logger.Warn("error processing subdirectory", "path", fullPath, "error", err)
				}
				continue
			}

			if _, processed := extractedFiles.Load(fullPath); processed {
				continue
			}

			// Handle extracted UPX files separately; we keep the original around to show that UPX was used
			if strings.HasSuffix(file.Name(), ".~") || strings.HasSuffix(file.Name(), ".000") {
				extractedFiles.Store(fullPath, true)
				continue
			}

			extractedFiles.Store(fullPath, true)

			ft, err := programkind.File(fullPath)
			if err != nil {
				logger.Warn("error determining file type", "path", fullPath, "error", err)
				continue
			}

			isArchive := false
			var extract func(context.Context, string, string) error

			switch {
			case ft != nil && ft.MIME == "application/x-upx":
				isArchive = true
				extract = ExtractUPX
			case ft != nil && ft.MIME == "application/zlib":
				isArchive = true
				extract = ExtractZlib
			case programkind.ArchiveMap[programkind.GetExt(file.Name())]:
				isArchive = true
				extract = ExtractionMethod(programkind.GetExt(file.Name()))
			}
			programkind.Put(ft)

			if isArchive && extract != nil {
				if err := os.MkdirAll(dir, 0o755); err != nil {
					logger.Warn("failed to create extraction directory", "path", dir, "error", err)
					continue
				}

				if err := extract(ctx, dir, fullPath); err != nil {
					logger.Warn("failed to extract archive", "path", fullPath, "error", err)
					os.RemoveAll(dir)
					continue
				}

				if err := os.Remove(fullPath); err != nil {
					logger.Warn("failed to remove archive after extraction", "path", fullPath, "error", err)
				}

				if err := processDir(dir); err != nil {
					logger.Warn("error processing extracted directory", "path", dir, "error", err)
				}
			}
		}
		return nil
	}

	if err := processDir(tmpDir); err != nil {
		logger.Warn("error during recursive extraction", "error", err)
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
func handleFile(target string, tr *tar.Reader, size int64) error {
	buf := bufferPool.Get(size)
	defer bufferPool.Put(buf)

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
		return fmt.Errorf("failed to copy file: %w", err)
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
