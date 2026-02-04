// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

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
	"time"

	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/malcontent/pkg/file"
	"github.com/chainguard-dev/malcontent/pkg/programkind"
	zip "github.com/klauspost/compress/zip"
	"golang.org/x/sync/errgroup"
)

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

	fi, err := os.Stat(f)
	if err != nil {
		return fmt.Errorf("failed to stat file %s: %w", f, err)
	}
	if fi.Size() == 0 {
		return nil
	}

	var isZip bool
	if ft, err := programkind.File(ctx, f); err == nil && ft != nil {
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

	for _, zf := range read.File {
		if zf.Mode().IsDir() {
			clean := filepath.Clean(filepath.ToSlash(zf.Name))
			if strings.Contains(clean, "..") {
				logger.Warnf("skipping potentially unsafe directory path: %s", zf.Name)
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

	for _, zf := range read.File {
		if zf.Mode().IsDir() {
			continue
		}
		g.Go(func() error {
			return extractFile(gCtx, zf, d, logger)
		})
	}

	if err := g.Wait(); err != nil {
		return fmt.Errorf("extraction failed: %w", err)
	}
	return nil
}

func extractFile(ctx context.Context, zf *zip.File, destDir string, logger *clog.Logger) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	// macOS will encounter issues with paths like META-INF/LICENSE and META-INF/license/foo
	// this case insensitivity will break scans, so rename files that collide with existing directories
	if runtime.GOOS == "darwin" {
		if _, err := os.Stat(filepath.Join(destDir, zf.Name)); err == nil {
			zf.Name = fmt.Sprintf("%s%d", zf.Name, time.Now().UnixNano())
		}
	}

	clean := filepath.Clean(filepath.ToSlash(zf.Name))
	if strings.Contains(clean, "..") {
		logger.Warnf("skipping potentially unsafe file path: %s", zf.Name)
		return nil
	}

	target := filepath.Join(destDir, clean)
	if !IsValidPath(target, destDir) {
		logger.Warnf("skipping file path outside extraction directory: %s", target)
		return nil
	}

	if zf.Mode()&os.ModeSymlink != 0 {
		src, err := zf.Open()
		if err != nil {
			return fmt.Errorf("failed to open symlink entry: %w", err)
		}
		defer src.Close()

		const maxSymlinkTarget int64 = 4096
		linkTarget, err := io.ReadAll(io.LimitReader(src, maxSymlinkTarget))
		if err != nil {
			return fmt.Errorf("failed to read symlink target: %w", err)
		}

		if err := handleSymlink(destDir, clean, string(linkTarget)); err != nil {
			return fmt.Errorf("failed to create symlink: %w", err)
		}
		return nil
	}

	buf := zipPool.Get(file.ZipBuffer) //nolint:nilaway // the buffer pool is created in archive.go

	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		return fmt.Errorf("failed to create directory structure: %w", err)
	}

	src, err := zf.Open()
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
		if written > 0 && written%file.ZipBuffer == 0 && ctx.Err() != nil {
			return ctx.Err()
		}

		n, err := src.Read(buf)
		if n > 0 {
			written += int64(n)
			if written > file.MaxBytes {
				return fmt.Errorf("file exceeds maximum allowed size (%d bytes): %s", file.MaxBytes, target)
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
