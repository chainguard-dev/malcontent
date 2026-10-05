// Copyright 2025 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/malcontent/pkg/file"
	"github.com/klauspost/compress/zstd"
)

// ExtractZstd extracts .zst and .zstd archives.
func ExtractZstd(ctx context.Context, d string, f string) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	logger := clog.FromContext(ctx).With("dir", d, "file", f)
	logger.Debug("extracting zstd")

	fi, err := os.Stat(f)
	if err != nil {
		return fmt.Errorf("failed to stat zstd file %s: %w", f, err)
	}
	if fi.Size() == 0 {
		return nil
	}

	buf := archivePool.Get(file.ExtractBuffer) //nolint:nilaway // the buffer pool is created in archive.go
	defer archivePool.Put(buf)

	// Enforce a byte and ratio ceiling against the single decompressed stream.
	// InputBytes seeds the ratio denominator from the compressed file size.
	counter := newArchiveCounter(ctx, fi.Size())

	uncompressed := strings.TrimSuffix(filepath.Base(f), ".zstd")
	uncompressed = strings.TrimSuffix(uncompressed, ".zst")
	name := filepath.Join(filepath.Base(filepath.Dir(f)), uncompressed)
	target := filepath.Join(d, name)

	if !IsValidPath(target, d) {
		return fmt.Errorf("invalid zstd decompression file path: %s", target)
	}

	root, err := openRoot(d)
	if err != nil {
		return err
	}
	defer root.Close()

	out, err := createFile(root, name)
	if err != nil {
		return fmt.Errorf("failed to create decompressed zstd file: %w", err)
	}
	defer out.Close()

	zstdFile, err := os.Open(f) // #nosec G304 -- archive path resolved and validated by caller before extraction
	if err != nil {
		return fmt.Errorf("failed to open zstd file: %w", err)
	}
	defer zstdFile.Close()

	zr, err := zstd.NewReader(zstdFile)
	if err != nil {
		return fmt.Errorf("failed to open zstd file %s: %w", f, err)
	}
	defer zr.Close()

	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		n, err := zr.Read(buf)
		if n > 0 {
			if capErr := counter.Add(n); capErr != nil {
				return fmt.Errorf("zstd extraction aborted on %s: %w", target, capErr)
			}
			if _, writeErr := out.Write(buf[:n]); writeErr != nil {
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
