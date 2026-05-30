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
	maxBytes, maxRatio := resolveArchiveCaps(ctx)
	counter := &file.ArchiveCounter{
		MaxBytes:   maxBytes,
		MaxRatio:   maxRatio,
		InputBytes: fi.Size(),
	}

	uncompressed := strings.TrimSuffix(filepath.Base(f), ".zstd")
	uncompressed = strings.TrimSuffix(uncompressed, ".zst")
	target := filepath.Join(d, filepath.Base(filepath.Dir(f)), uncompressed)

	if !IsValidPath(target, d) {
		return fmt.Errorf("invalid zstd decompression file path: %s", target)
	}

	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		return fmt.Errorf("failed to create directory for decomrpessed zstd file: %w", err)
	}

	out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600) // #nosec G304 -- target validated by IsValidPath against sandbox dir d
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

	var written int64
	for {
		if written > 0 && written%file.ExtractBuffer == 0 && ctx.Err() != nil {
			return ctx.Err()
		}

		n, err := zr.Read(buf)
		if n > 0 {
			written += int64(n)
			if written > file.MaxBytes {
				return fmt.Errorf("file exceeds maximum allowed size (%d bytes): %s", file.MaxBytes, target)
			}
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
