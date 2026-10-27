// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"

	"github.com/chainguard-dev/clog"
)

// ExtractGzip extracts .gz archives, and any gzip stream detected by content,
// into one file named after the archive without its extension. The extra and
// comment fields of each member's header are written to the metadata
// sidecar.
func ExtractGzip(ctx context.Context, d string, f string) (err error) {
	defer recoverExtractor(ctx, "gzip", f, &err)
	if ctx.Err() != nil {
		return ctx.Err()
	}

	logger := clog.FromContext(ctx).With("dir", d, "file", f)
	logger.Debug("extracting gzip")

	gf, fi, err := openRegular(f)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer gf.Close()
	if fi.Size() == 0 {
		return nil
	}

	// Check whether the provided file is a valid gzip archive
	head := make([]byte, len(gzipMagic))
	if _, err := gf.ReadAt(head, 0); err != nil || !bytes.Equal(head, gzipMagic) {
		return fmt.Errorf("not a valid gzip archive: %q", f)
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
		return fmt.Errorf("invalid file path: %q", target)
	}

	root, err := openRoot(d)
	if err != nil {
		return err
	}
	defer root.Close()

	var sc sidecar
	gr, err := newGzipMembers(io.NewSectionReader(gf, 0, fi.Size()), &sc)
	if err != nil {
		return fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gr.Close()

	if err := counter.Entry(); err != nil {
		return fmt.Errorf("gzip extraction aborted on %q: %w", target, err)
	}
	out, err := createFile(root, name)
	if err != nil {
		return fmt.Errorf("failed to create extracted file: %w", err)
	}
	defer out.Close()

	copyErr := copyCounted(ctx, out, gr, counter, buf, target)
	return errors.Join(copyErr, sc.writeBeside(root, name, counter), sc.err())
}
