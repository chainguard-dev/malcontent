// Copyright 2025 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/chainguard-dev/clog"
)

// ExtractZstd extracts .zst and .zstd archives. Its decoder refuses windows
// beyond maxDecoderWindow, and the content of skippable frames, which the
// decoder skips, is written to the metadata sidecar.
func ExtractZstd(ctx context.Context, d string, f string) (err error) {
	defer recoverExtractor(ctx, "zstd", f, &err)
	if ctx.Err() != nil {
		return ctx.Err()
	}

	logger := clog.FromContext(ctx).With("dir", d, "file", f)
	logger.Debug("extracting zstd")

	zstdFile, fi, err := openRegular(f)
	if err != nil {
		return fmt.Errorf("failed to open zstd file %q: %w", f, err)
	}
	defer zstdFile.Close()
	if fi.Size() == 0 {
		return nil
	}

	buf := extractPool.Get()
	defer extractPool.Put(buf)

	// Enforce a byte and ratio ceiling against the single decompressed stream.
	// InputBytes seeds the ratio denominator from the compressed file size.
	counter := newArchiveCounter(ctx, fi.Size())

	uncompressed := strings.TrimSuffix(filepath.Base(f), ".zstd")
	uncompressed = strings.TrimSuffix(uncompressed, ".zst")
	name := filepath.Join(filepath.Base(filepath.Dir(f)), uncompressed)
	target := filepath.Join(d, name)

	if !IsValidPath(target, d) {
		return fmt.Errorf("invalid zstd decompression file path: %q", target)
	}

	root, err := openRoot(d)
	if err != nil {
		return err
	}
	defer root.Close()

	var sc sidecar
	zstdSkippableFrames(zstdFile, fi.Size(), &sc)

	zr, err := newZstdReader(bufferInput(io.NewSectionReader(zstdFile, 0, fi.Size())))
	if err != nil {
		return fmt.Errorf("failed to open zstd file %q: %w", f, err)
	}
	defer zr.Close()

	if err := counter.Entry(); err != nil {
		return fmt.Errorf("zstd extraction aborted on %q: %w", target, err)
	}
	out, err := createFile(root, name)
	if err != nil {
		return fmt.Errorf("failed to create decompressed zstd file: %w", err)
	}
	defer out.Close()

	copyErr := copyCounted(ctx, out, zr, counter, buf, target)
	return errors.Join(copyErr, sc.writeBeside(root, name, counter), sc.err())
}
