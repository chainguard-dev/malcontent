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

	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/malcontent/pkg/programkind"
)

var GzMIME = map[string]struct{}{
	"application/gzip":              {},
	"application/gzip-compressed":   {},
	"application/gzipped":           {},
	"application/x-gunzip":          {},
	"application/x-gzip":            {},
	"application/x-gzip-compressed": {},
	"gzip/document":                 {},
}

// ExtractGzip extracts .gz archives.
func ExtractGzip(ctx context.Context, d string, f string) error {
	return extractGzipWithKind(ctx, d, f, detectFileType(ctx, f))
}

// extractGzipWithKind is ExtractGzip with the file's detected type reported by
// fileType, so that a caller which already detected it need not read the file
// again.
func extractGzipWithKind(ctx context.Context, d, f string, fileType func() *programkind.FileType) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	// Check whether the provided file is a valid gzip archive
	if !isGzipType(fileType()) {
		return fmt.Errorf("not a valid gzip archive: %s", f)
	}

	logger := clog.FromContext(ctx).With("dir", d, "file", f)
	logger.Debug("extracting gzip")

	// Check if the file is valid
	fi, err := os.Stat(f)
	if err != nil {
		return fmt.Errorf("failed to stat file: %w", err)
	}
	if fi.Size() == 0 {
		return nil
	}

	buf := extractPool.Get()
	defer extractPool.Put(buf)

	// Enforce a byte and ratio ceiling against the single decompressed stream.
	// InputBytes seeds the ratio denominator from the compressed file size.
	counter := newArchiveCounter(ctx, fi.Size())

	gf, err := os.Open(f) // #nosec G304 -- archive path resolved and validated by caller before extraction
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer gf.Close()

	base := filepath.Base(f)
	name := base[:len(base)-len(filepath.Ext(base))]
	target := filepath.Join(d, name)
	if !IsValidPath(target, d) {
		return fmt.Errorf("invalid file path: %s", target)
	}

	root, err := openRoot(d)
	if err != nil {
		return err
	}
	defer root.Close()

	gr, err := newGzipReader(gf)
	if err != nil {
		return fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gr.Close()

	out, err := createFile(root, name)
	if err != nil {
		return fmt.Errorf("failed to create extracted file: %w", err)
	}
	defer out.Close()

	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		n, err := gr.Read(buf)
		if n > 0 {
			if capErr := counter.Add(n); capErr != nil {
				return fmt.Errorf("gzip extraction aborted on %s: %w", target, capErr)
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
