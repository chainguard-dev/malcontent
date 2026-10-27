// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"compress/zlib"
	"context"
	"fmt"
	"io"
	"path/filepath"

	"github.com/chainguard-dev/clog"
)

// ExtractZlib extracts extension-agnostic zlib-compressed files. Input left
// after the zlib stream ends is reported as ErrUnaccountedBytes, so that the
// file is retained and scanned as it is.
func ExtractZlib(ctx context.Context, d string, f string) (err error) {
	defer recoverExtractor(ctx, "zlib", f, &err)
	if ctx.Err() != nil {
		return ctx.Err()
	}

	logger := clog.FromContext(ctx).With("dir", d, "file", f)
	logger.Debugf("extracting zlib")

	zf, fi, err := openRegular(f)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer zf.Close()
	if fi.Size() == 0 {
		return nil
	}

	buf := extractPool.Get()
	defer extractPool.Put(buf)

	// Enforce a byte and ratio ceiling against the single decompressed stream.
	// InputBytes seeds the ratio denominator from the compressed file size.
	counter := newArchiveCounter(ctx, fi.Size())

	base := filepath.Base(f)
	name := base[:len(base)-len(filepath.Ext(base))]
	target := filepath.Join(d, name)

	if !IsValidPath(target, d) {
		return fmt.Errorf("invalid zlib decompression file path: %q", target)
	}

	root, err := openRoot(d)
	if err != nil {
		return err
	}
	defer root.Close()

	// compress/flate reads its input a byte at a time through the buffer, so
	// whatever the buffer holds once the stream ends follows the stream.
	input := bufferInput(io.NewSectionReader(zf, 0, fi.Size()))
	zr, err := zlib.NewReader(input)
	if err != nil {
		return fmt.Errorf("failed to create zlib reader: %w", err)
	}
	defer zr.Close()

	if err := counter.Entry(); err != nil {
		return fmt.Errorf("zlib extraction aborted on %q: %w", target, err)
	}
	out, err := createFile(root, name)
	if err != nil {
		return fmt.Errorf("failed to create extracted file: %w", err)
	}
	defer out.Close()

	if err := copyCounted(ctx, out, zr, counter, buf, target); err != nil {
		return err
	}
	if _, err := input.Peek(1); err == nil {
		return fmt.Errorf("%w in %q: data follows the zlib stream", ErrUnaccountedBytes, base)
	}
	return nil
}
