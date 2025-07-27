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
	gzip "github.com/klauspost/pgzip"
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

// extractGzip extracts .gz archives.
func ExtractGzip(ctx context.Context, d string, f string) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	// Check whether the provided file is a valid gzip archive
	var isGzip bool
	if ft, err := programkind.File(f); err == nil && ft != nil {
		if _, ok := GzMIME[ft.MIME]; ok {
			isGzip = true
		}
	}

	if !isGzip {
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

	buf := archivePool.Get(extractBuffer) //nolint:nilaway // the buffer pool is created in archive.go

	gf, err := os.Open(f)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}

	base := filepath.Base(f)
	target := filepath.Join(d, base[:len(base)-len(filepath.Ext(base))])
	if !IsValidPath(target, d) {
		return fmt.Errorf("invalid file path: %s", target)
	}

	gr, err := gzip.NewReader(gf)
	if err != nil {
		return fmt.Errorf("failed to create gzip reader: %w", err)
	}

	out, err := os.Create(target)
	if err != nil {
		return fmt.Errorf("failed to create extracted file: %w", err)
	}

	defer func() {
		archivePool.Put(buf)
		gf.Close()
		gr.Close()
		out.Close()
	}()

	var written int64
	for {
		if written > 0 && written%extractBuffer == 0 && ctx.Err() != nil {
			return ctx.Err()
		}

		n, err := gr.Read(buf)
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
