package archive

import (
	"compress/bzip2"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/chainguard-dev/clog"
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

	buf := archivePool.Get(fi.Size())
	defer archivePool.Put(buf)

	tf, err := os.Open(f)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer tf.Close()
	// Set offset to the file origin regardless of type
	_, err = tf.Seek(0, io.SeekStart)
	if err != nil {
		return fmt.Errorf("failed to seek to start: %w", err)
	}

	br := bzip2.NewReader(tf)
	uncompressed := strings.TrimSuffix(filepath.Base(f), ".bz2")
	uncompressed = strings.TrimSuffix(uncompressed, ".bzip2")
	target := filepath.Join(d, uncompressed)
	if !IsValidPath(target, d) {
		return fmt.Errorf("invalid file path: %s", target)
	}
	if err := os.MkdirAll(d, 0o700); err != nil {
		return fmt.Errorf("failed to create directory for file: %w", err)
	}

	// #nosec G115 // ignore Type conversion which leads to integer overflow
	// header.Mode is int64 and FileMode is uint32
	out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer out.Close()

	written, err := io.CopyBuffer(out, io.LimitReader(br, maxBytes), buf)
	if err != nil {
		return fmt.Errorf("failed to copy file: %w", err)
	}
	if written >= maxBytes {
		return fmt.Errorf("file exceeds maximum allowed size (%d bytes): %s", maxBytes, target)
	}

	return nil
}
