package archive

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/malcontent/pkg/pool"
	"github.com/chainguard-dev/malcontent/pkg/programkind"
	zip "github.com/klauspost/compress/zip"
	"golang.org/x/sync/errgroup"
)

var initZipPool sync.Once

var zipMIME = map[string]struct{}{
	"application/jar":              {},
	"application/java-archive":     {},
	"application/x-wheel+zip":      {},
	"application/x-zip":            {},
	"application/x-zip-compressed": {},
	"application/zip":              {},
}

// ExtractZip extracts .jar and .zip archives.
func ExtractZip(ctx context.Context, d string, f string) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	logger := clog.FromContext(ctx).With("dir", d, "file", f)
	logger.Debug("extracting zip")

	initZipPool.Do(func() {
		zipPool = pool.NewBufferPool(runtime.GOMAXPROCS(0) * 2)
	})

	fi, err := os.Stat(f)
	if err != nil {
		return fmt.Errorf("failed to stat file %s: %w", f, err)
	}
	if fi.Size() == 0 {
		return nil
	}

	var isZip bool
	if ft, err := programkind.File(f); err == nil && ft != nil {
		if _, ok := zipMIME[ft.MIME]; ok {
			isZip = true
		}
	}

	if !isZip {
		return fmt.Errorf("not a valid zip archive: %s", f)
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
	g.SetLimit(runtime.GOMAXPROCS(0))

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

	// macOS will encounter issues with paths like META-INF/LICENSE and META-INF/license/foo
	// this case insensitivity will break scans, so rename files that collide with existing directories
	if runtime.GOOS == "darwin" {
		if _, err := os.Stat(filepath.Join(destDir, file.Name)); err == nil {
			file.Name = fmt.Sprintf("%s%d", file.Name, time.Now().UnixNano())
		}
	}

	buf := zipPool.Get(zipBuffer) //nolint:nilaway // the buffer pool is created in archive.go

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

	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		return fmt.Errorf("failed to create directory structure: %w", err)
	}

	src, err := file.Open()
	if err != nil {
		return fmt.Errorf("failed to open archived file: %w", err)
	}

	dst, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("failed to create destination file: %w", err)
	}

	defer func() {
		src.Close()
		dst.Close()
		zipPool.Put(buf)
	}()

	var written int64
	for {
		if written > 0 && written%zipBuffer == 0 && ctx.Err() != nil {
			return ctx.Err()
		}

		n, err := src.Read(buf)
		if n > 0 {
			written += int64(n)
			if written > maxBytes {
				return fmt.Errorf("file exceeds maximum allowed size (%d bytes): %s", maxBytes, target)
			}

			if _, writeErr := dst.Write(buf[:n]); writeErr != nil {
				return fmt.Errorf("failed to write file contents: %w", writeErr)
			}
		}

		if errors.Is(err, io.EOF) {
			break
		}

		if err != nil {
			return fmt.Errorf("failed to read file contents: %w", err)
		}
	}

	return nil
}
