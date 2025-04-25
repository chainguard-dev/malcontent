package archive

import (
	"archive/zip"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/malcontent/pkg/pool"
	"golang.org/x/sync/errgroup"
)

var initZipPool sync.Once

// ExtractZip extracts .jar and .zip archives.
func ExtractZip(ctx context.Context, d string, f string) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	logger := clog.FromContext(ctx).With("dir", d, "file", f)
	logger.Debug("extracting zip")

	initZipPool.Do(func() {
		zipPool = pool.NewBufferPool()
	})

	fi, err := os.Stat(f)
	if err != nil {
		return fmt.Errorf("failed to stat file %s: %w", f, err)
	}
	if fi.Size() == 0 {
		return fmt.Errorf("empty zip file: %s", f)
	}

	read, err := zip.OpenReader(f)
	if err != nil {
		return fmt.Errorf("failed to open zip file %s: %w", f, err)
	}
	defer read.Close()

	if err := os.MkdirAll(d, 0o700); err != nil {
		return fmt.Errorf("failed to create extraction directory: %w", err)
	}

	for _, file := range read.File {
		if file.Mode().IsDir() {
			clean := filepath.Clean(filepath.ToSlash(file.Name))
			if strings.Contains(clean, "..") {
				logger.Warnf("skipping potentially unsafe directory path: %s", file.Name)
				continue
			}

			target := filepath.Join(d, clean)
			if !IsValidPath(target, d) {
				logger.Warnf("skipping directory path outside extraction directory: %s", target)
				continue
			}

			if err := os.MkdirAll(target, 0o700); err != nil {
				return fmt.Errorf("failed to create directory structure: %w", err)
			}
		}
	}

	g, gCtx := errgroup.WithContext(ctx)
	g.SetLimit(min(runtime.GOMAXPROCS(0), len(read.File)))

	for _, file := range read.File {
		if file.Mode().IsDir() {
			continue
		}
		g.Go(func() error {
			return extractFile(gCtx, file, d, logger)
		})
	}

	if err := g.Wait(); err != nil {
		return fmt.Errorf("extraction failed: %w", err)
	}
	return nil
}

func extractFile(ctx context.Context, file *zip.File, destDir string, logger *clog.Logger) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	// #nosec G115 // ignore Type conversion which leads to integer overflow
	buf := zipPool.Get(int64(file.UncompressedSize64))
	defer zipPool.Put(buf)

	clean := filepath.Clean(filepath.ToSlash(file.Name))
	if strings.Contains(clean, "..") {
		logger.Warnf("skipping potentially unsafe file path: %s", file.Name)
		return nil
	}

	target := filepath.Join(destDir, clean)
	if !IsValidPath(target, destDir) {
		logger.Warnf("skipping file path outside extraction directory: %s", target)
		return nil
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		return fmt.Errorf("failed to create directory structure: %w", err)
	}

	src, err := file.Open()
	if err != nil {
		return fmt.Errorf("failed to open archived file: %w", err)
	}
	defer src.Close()

	dst, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("failed to create destination file: %w", err)
	}

	var closeErr error
	defer func() {
		if cerr := dst.Close(); cerr != nil && closeErr == nil {
			closeErr = cerr
		}
	}()

	written, err := io.CopyBuffer(dst, io.LimitReader(src, maxBytes), buf)
	if err != nil {
		return fmt.Errorf("failed to copy file contents: %w", err)
	}
	if written >= maxBytes {
		return fmt.Errorf("file exceeds maximum allowed size (%d bytes): %s", maxBytes, target)
	}

	return closeErr
}
