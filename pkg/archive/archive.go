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
	archivePool, tarPool, zipPool *pool.BufferPool
	initializeOnce                sync.Once
)

// isValidPath checks if the target file is within the given directory.
func IsValidPath(target, dir string) bool {
	return strings.HasPrefix(filepath.Clean(target), filepath.Clean(dir))
}

func extractNestedArchive(ctx context.Context, d string, f string, extracted *sync.Map) error {
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

	err = extract(ctx, d, fullPath)
	if err != nil {
		return fmt.Errorf("failed to extract archive: %w", err)
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
			if err := extractNestedArchive(ctx, d, rel, extracted); err != nil {
				return fmt.Errorf("process nested file %s: %w", rel, err)
			}
		}
	}
	return nil
}

// extractArchiveToTempDir creates a temporary directory and extracts the archive file for scanning.
func ExtractArchiveToTempDir(ctx context.Context, path string) (string, error) {
	if ctx.Err() != nil {
		return "", ctx.Err()
	}

	logger := clog.FromContext(ctx).With("path", path)
	logger.Debug("creating temp dir")

	tmpDir, err := os.MkdirTemp("", filepath.Base(path))
	if err != nil {
		return "", fmt.Errorf("failed to create temp dir: %w", err)
	}

	go func() {
		<-ctx.Done()
		logger.Debug("context cancelled, cleaning up temp dir")
		os.RemoveAll(tmpDir)
	}()

	initializeOnce.Do(func() {
		archivePool = pool.NewBufferPool()
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
	files, err := os.ReadDir(tmpDir)
	if err != nil {
		return "", fmt.Errorf("failed to read files in directory %s: %w", tmpDir, err)
	}
	for _, file := range files {
		extractedFiles.Store(filepath.Join(tmpDir, file.Name()), false)
	}

	extractedFiles.Range(func(key, _ any) bool {
		if key == nil {
			return true
		}
		//nolint: nestif // ignoring complexity of 11
		if file, ok := key.(string); ok {
			ext := programkind.GetExt(file)
			info, err := os.Stat(file)
			if err != nil {
				return false
			}
			switch mode := info.Mode(); {
			case mode.IsDir():
				err = filepath.WalkDir(file, func(path string, d os.DirEntry, err error) error {
					if err != nil {
						return err
					}
					rel, err := filepath.Rel(tmpDir, path)
					if err != nil {
						return fmt.Errorf("filepath.Rel: %w", err)
					}
					if !d.IsDir() {
						if err := extractNestedArchive(ctx, tmpDir, rel, &extractedFiles); err != nil {
							return fmt.Errorf("failed to extract nested archive %s: %w", rel, err)
						}
					}

					return nil
				})
				if err != nil {
					return false
				}
				return true
			case mode.IsRegular():
				if _, ok := programkind.ArchiveMap[ext]; ok {
					rel, err := filepath.Rel(tmpDir, file)
					if err != nil {
						return false
					}
					if err := extractNestedArchive(ctx, tmpDir, rel, &extractedFiles); err != nil {
						return false
					}
				}
				return true
			}
		}
		return true
	})

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
	buf := tarPool.Get(size)
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
