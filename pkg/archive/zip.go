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

	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/malcontent/pkg/file"
	"github.com/chainguard-dev/malcontent/pkg/malcontent"
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

// defaultMaxArchiveBytes seeds ExtractZip's per-archive byte cap. It is a var
// (not a const) so tests can shrink the cap to a synthesizable bound; the
// production value is file.DefaultMaxArchiveBytes (32 GiB).
var defaultMaxArchiveBytes = file.DefaultMaxArchiveBytes

// resolveArchiveCaps returns the effective byte and ratio caps for an archive
// extraction. Caller-supplied Config values take precedence over defaults; a
// zero/unset value falls back to file.DefaultMaxArchiveBytes /
// file.DefaultMaxArchiveRatio.
func resolveArchiveCaps(ctx context.Context) (maxBytes int64, maxRatio float64) {
	maxBytes = defaultMaxArchiveBytes
	maxRatio = file.DefaultMaxArchiveRatio
	if cfg := malcontent.ConfigFromContext(ctx); cfg != nil {
		if cfg.MaxArchiveBytes > 0 {
			maxBytes = cfg.MaxArchiveBytes
		}
		if cfg.MaxArchiveRatio > 0 {
			maxRatio = cfg.MaxArchiveRatio
		}
	}
	return maxBytes, maxRatio
}

// ExtractZip extracts zip-format archives (.ear, .jar, .war, .whl, .zip).
func ExtractZip(ctx context.Context, d string, f string) (err error) {
	defer recoverExtractor(ctx, "zip", f, &err)
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

	root, err := openRoot(d)
	if err != nil {
		return err
	}
	defer root.Close()

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

			if err := root.MkdirAll(clean, 0o700); err != nil {
				return fmt.Errorf("failed to create directory structure: %w", err)
			}
		}
	}

	g, gCtx := errgroup.WithContext(ctx)
	g.SetLimit(EffectiveMaxConcurrency(runtime.GOMAXPROCS(0)))
	sem := extractionSemaphore()

	// Shared counter across all entries enforces a uniform byte and ratio
	// ceiling. InputBytes seeds the ratio denominator from the outer archive
	// size. Caps prefer ctx-attached Config values; absent/zero values fall
	// back to the package defaults so zero-config callers still receive a
	// finite cap.
	counter := newArchiveCounter(ctx, fi.Size())

	var symlinks []*zip.File
	for _, zf := range read.File {
		if zf.Mode().IsDir() {
			continue
		}
		// Symlinks are created one at a time after every other entry so that
		// no concurrent write can change what a link resolves to while it is
		// validated.
		if zf.Mode()&os.ModeSymlink != 0 {
			symlinks = append(symlinks, zf)
			continue
		}
		g.Go(func() (err error) {
			defer recoverExtractor(gCtx, "zip", f, &err)
			if hook := workerPanicHook; hook != nil {
				hook(f)
			}
			if err := sem.Acquire(gCtx, 1); err != nil {
				return err
			}
			defer sem.Release(1)
			return extractFile(gCtx, zf, root, logger, counter)
		})
	}

	if err := g.Wait(); err != nil {
		return fmt.Errorf("extraction failed: %w", err)
	}

	for _, zf := range symlinks {
		if err := extractFile(ctx, zf, root, logger, counter); err != nil {
			return fmt.Errorf("extraction failed: %w", err)
		}
	}

	if err := zipUnaccountedBytes(f, fi.Size()); err != nil {
		return fmt.Errorf("%w in %s: %w", ErrUnaccountedBytes, filepath.Base(f), err)
	}

	return nil
}

func extractFile(ctx context.Context, zf *zip.File, root *os.Root, logger *clog.Logger, counter *file.ArchiveCounter) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	// macOS will encounter issues with paths like META-INF/LICENSE and META-INF/license/foo
	// this case insensitivity will break scans, so rename files that collide with existing directories
	if runtime.GOOS == "darwin" {
		// Root has no MkdirTemp; Stat through it first so that the plain path
		// passed to os.MkdirTemp is known to lie beneath the root.
		if _, err := root.Stat(zf.Name); err == nil {
			uniqueDir, mkErr := os.MkdirTemp(filepath.Join(root.Name(), filepath.Dir(zf.Name)), filepath.Base(zf.Name)+"_*")
			if mkErr == nil {
				rel, relErr := filepath.Rel(root.Name(), uniqueDir)
				if relErr == nil {
					zf.Name = rel
				}
			}
		}
	}

	clean := filepath.Clean(filepath.ToSlash(zf.Name))
	if strings.Contains(clean, "..") {
		logger.Warnf("skipping potentially unsafe file path: %s", zf.Name)
		return nil
	}

	target := filepath.Join(root.Name(), clean)
	if !IsValidPath(target, root.Name()) {
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

		if err := handleSymlink(root, clean, string(linkTarget)); err != nil {
			return fmt.Errorf("failed to create symlink: %w", err)
		}
		return nil
	}

	buf := zipPool.Get(file.ZipBuffer) //nolint:nilaway // the buffer pool is created in archive.go
	defer zipPool.Put(buf)

	src, err := zf.Open()
	if err != nil {
		return fmt.Errorf("failed to open archived file: %w", err)
	}
	defer src.Close()

	dst, err := createFile(root, clean)
	if err != nil {
		return err
	}
	defer dst.Close()

	var written int64
	for {
		if written > 0 && written%file.ZipBuffer == 0 && ctx.Err() != nil {
			return ctx.Err()
		}

		n, err := src.Read(buf)
		if n > 0 {
			written += int64(n)
			if capErr := counter.Add(n); capErr != nil {
				return fmt.Errorf("zip extraction aborted on %s: %w", target, capErr)
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
