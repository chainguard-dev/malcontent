// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/chainguard-dev/clog"
)

// ExtractBz2 extracts bzip2 files.
func ExtractBz2(ctx context.Context, d, f string) (err error) {
	defer recoverExtractor(ctx, "bz2", f, &err)
	if ctx.Err() != nil {
		return ctx.Err()
	}

	logger := clog.FromContext(ctx).With("dir", d, "file", f)
	logger.Debug("extracting bzip2 file")

	tf, fi, err := openRegular(f)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer tf.Close()
	if fi.Size() == 0 {
		return nil
	}

	buf := extractPool.Get()
	defer extractPool.Put(buf)

	// Enforce a byte and ratio ceiling against the single decompressed stream.
	// InputBytes seeds the ratio denominator from the compressed file size.
	counter := newArchiveCounter(ctx, fi.Size())

	uncompressed := strings.TrimSuffix(filepath.Base(f), ".bz2")
	uncompressed = strings.TrimSuffix(uncompressed, ".bzip2")
	name := filepath.Join(filepath.Base(filepath.Dir(f)), uncompressed)
	target := filepath.Join(d, name)
	if !IsValidPath(target, d) {
		return fmt.Errorf("invalid file path: %q", target)
	}

	root, err := openRoot(d)
	if err != nil {
		return err
	}
	defer root.Close()

	return decompressTo(ctx, root, name, counter, buf, func() (io.Reader, func(), error) {
		br := newBzip2Reader(ctx, io.NewSectionReader(tf, 0, fi.Size()))
		return br, func() { _ = br.Close() }, nil
	})
}
