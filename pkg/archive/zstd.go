package archive

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/chainguard-dev/clog"
	"github.com/klauspost/compress/zstd"
)

// ExtractZstd extracts .zst and .zstd archives.
func ExtractZstd(ctx context.Context, d string, f string) error {
	logger := clog.FromContext(ctx).With("dir", d, "file", f)
	logger.Debug("extracting zstd")

	buf, ok := bufferPool.Get().(*[]byte)
	if !ok {
		return fmt.Errorf("failed to retrieve buffer for zstd")
	}
	defer bufferPool.Put(buf)

	fi, err := os.Stat(f)
	if err != nil {
		return fmt.Errorf("failed to stat zstd file %s: %w", f, err)
	}
	if fi.Size() == 0 {
		return fmt.Errorf("empty zstd file: %s", f)
	}

	uncompressed := strings.TrimSuffix(filepath.Base(f), ".zstd")
	uncompressed = strings.TrimSuffix(uncompressed, ".zst")
	target := filepath.Join(d, uncompressed)

	if !IsValidPath(target, d) {
		return fmt.Errorf("invalid zstd decompression file path: %s", target)
	}

	if err := os.MkdirAll(d, 0o700); err != nil {
		return fmt.Errorf("failed to create directory for decomrpessed zstd file: %w", err)
	}

	out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("failed to create decompressed zstd file: %w", err)
	}
	defer out.Close()

	zstdFile, err := os.Open(f)
	if err != nil {
		return fmt.Errorf("failed to open zstd file: %w", err)
	}
	defer zstdFile.Close()

	zr, err := zstd.NewReader(zstdFile)
	if err != nil {
		return fmt.Errorf("failed to open zstd file %s: %w", f, err)
	}
	defer zr.Close()

	written, err := io.CopyBuffer(out, io.LimitReader(zr, maxBytes), *buf)
	if err != nil {
		return fmt.Errorf("failed to copy zstd compressed file: %w", err)
	}

	if written >= maxBytes {
		return fmt.Errorf("file exceeds maximum allowed size (%d bytes): %s", maxBytes, target)
	}

	return nil
}
