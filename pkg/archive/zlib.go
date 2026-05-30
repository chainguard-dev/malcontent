// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"compress/zlib"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/malcontent/pkg/file"
)

// extractZlib extracts extension-agnostic zlib-compressed files.
func ExtractZlib(ctx context.Context, d string, f string) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	logger := clog.FromContext(ctx).With("dir", d, "file", f)
	logger.Debugf("extracting zlib")

	// Check if the file is valid
	fi, err := os.Stat(f)
	if err != nil {
		return fmt.Errorf("failed to stat file: %w", err)
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

	zf, err := os.Open(f) // #nosec G304 -- archive path resolved and validated by caller before extraction
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer zf.Close()

	base := filepath.Base(f)
	target := filepath.Join(d, base[:len(base)-len(filepath.Ext(base))])

	if !IsValidPath(target, d) {
		return fmt.Errorf("invalid zlib decompression file path: %s", target)
	}

	zr, err := zlib.NewReader(zf)
	if err != nil {
		return fmt.Errorf("failed to create zlib reader: %w", err)
	}
	defer zr.Close()

	out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600) // #nosec G304 -- target validated by IsValidPath against sandbox dir d
	if err != nil {
		return fmt.Errorf("failed to create extracted file: %w", err)
	}
	defer out.Close()

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
				return fmt.Errorf("zlib extraction aborted on %s: %w", target, capErr)
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
