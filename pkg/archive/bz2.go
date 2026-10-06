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
	"strings"

	"github.com/chainguard-dev/clog"
	bzip2 "github.com/cosnicolaou/pbzip2"
)

// Extract Bz2 extracts bzip2 files.
func ExtractBz2(ctx context.Context, d, f string) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	logger := clog.FromContext(ctx).With("dir", d, "file", f)
	logger.Debug("extracting bzip2 file")

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

	tf, err := os.Open(f) // #nosec G304 -- archive path resolved and validated by caller before extraction
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer tf.Close()

	// pbzip2 decodes on background goroutines that block on an internal pipe
	// until every decompressed byte has been read. Canceling and reading once
	// more makes the reader close that pipe and wait for them, so returning
	// early (a cap, cancellation, or write error) does not leave them blocked.
	bzCtx, cancel := context.WithCancel(ctx)
	br := bzip2.NewReader(bzCtx, tf)
	defer func() {
		cancel()
		_, _ = br.Read(nil)
	}()

	uncompressed := strings.TrimSuffix(filepath.Base(f), ".bz2")
	uncompressed = strings.TrimSuffix(uncompressed, ".bzip2")
	name := filepath.Join(filepath.Base(filepath.Dir(f)), uncompressed)
	target := filepath.Join(d, name)
	if !IsValidPath(target, d) {
		return fmt.Errorf("invalid file path: %s", target)
	}

	root, err := openRoot(d)
	if err != nil {
		return err
	}
	defer root.Close()

	out, err := createFile(root, name)
	if err != nil {
		return err
	}
	defer out.Close()

	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		n, err := br.Read(buf)
		if n > 0 {
			if capErr := counter.Add(n); capErr != nil {
				return fmt.Errorf("bz2 extraction aborted on %s: %w", target, capErr)
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
