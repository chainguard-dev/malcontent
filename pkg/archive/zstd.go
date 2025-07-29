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

	buf := archivePool.Get(extractBuffer) //nolint:nilaway // the buffer pool is created in archive.go

	uncompressed := strings.TrimSuffix(filepath.Base(f), ".zstd")
	uncompressed = strings.TrimSuffix(uncompressed, ".zst")
	target := filepath.Join(d, filepath.Base(filepath.Dir(f)), uncompressed)

	if !IsValidPath(target, d) {
		return fmt.Errorf("invalid zstd decompression file path: %s", target)
	}

	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		return fmt.Errorf("failed to create directory for decomrpessed zstd file: %w", err)
	}

	out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("failed to create decompressed zstd file: %w", err)
	}

	zstdFile, err := os.Open(f)
	if err != nil {
		return fmt.Errorf("failed to open zstd file: %w", err)
	}

	zr, err := zstd.NewReader(zstdFile)
	if err != nil {
		return fmt.Errorf("failed to open zstd file %s: %w", f, err)
	}

	defer func() {
		archivePool.Put(buf)
		zstdFile.Close()
		zr.Close()
		out.Close()
	}()

	var written int64
	for {
		if written > 0 && written%extractBuffer == 0 && ctx.Err() != nil {
			return ctx.Err()
		}

		n, err := zr.Read(buf)
		if n > 0 {
			written += int64(n)
			if written > maxBytes {
				return fmt.Errorf("file exceeds maximum allowed size (%d bytes): %s", maxBytes, target)
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
