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

	buf := archivePool.Get(extractBuffer) //nolint:nilaway // the buffer pool is created in archive.go

	tf, err := os.Open(f)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	// Set offset to the file origin regardless of type
	_, err = tf.Seek(0, io.SeekStart)
	if err != nil {
		return fmt.Errorf("failed to seek to start: %w", err)
	}

	br := bzip2.NewReader(ctx, tf)
	uncompressed := strings.TrimSuffix(filepath.Base(f), ".bz2")
	uncompressed = strings.TrimSuffix(uncompressed, ".bzip2")
	target := filepath.Join(d, filepath.Base(filepath.Dir(f)), uncompressed)
	if !IsValidPath(target, d) {
		return fmt.Errorf("invalid file path: %s", target)
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		return fmt.Errorf("failed to create directory for file: %w", err)
	}

	// #nosec G115 // ignore Type conversion which leads to integer overflow
	// header.Mode is int64 and FileMode is uint32
	out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}

	defer func() {
		archivePool.Put(buf)
		tf.Close()
		out.Close()
	}()

	var written int64
	for {
		if written > 0 && written%extractBuffer == 0 && ctx.Err() != nil {
			return ctx.Err()
		}

		n, err := br.Read(buf)
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
