package archive

import (
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/malcontent/pkg/programkind"
)

// extractGzip extracts .gz archives.
func ExtractGzip(ctx context.Context, d string, f string) error {
	// Check whether the provided file is a valid gzip archive
	var isGzip bool
	if ft, err := programkind.File(f); err == nil && ft != nil {
		if ft.MIME == "application/gzip" {
			isGzip = true
		}
	}

	if !isGzip {
		return fmt.Errorf("not a valid gzip archive")
	}

	logger := clog.FromContext(ctx).With("dir", d, "file", f)
	logger.Debug("extracting gzip")

	// Check if the file is valid
	fi, err := os.Stat(f)
	if err != nil {
		return fmt.Errorf("failed to stat file: %w", err)
	}

	buf := archivePool.Get(fi.Size())
	defer archivePool.Put(buf)

	gf, err := os.Open(f)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer gf.Close()

	base := filepath.Base(f)
	target := filepath.Join(d, base[:len(base)-len(filepath.Ext(base))])
	if !IsValidPath(target, d) {
		return fmt.Errorf("invalid file path: %s", target)
	}

	gr, err := gzip.NewReader(gf)
	if err != nil {
		return fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gr.Close()

	out, err := os.Create(target)
	if err != nil {
		return fmt.Errorf("failed to create extracted file: %w", err)
	}
	defer out.Close()

	written, err := io.CopyBuffer(out, io.LimitReader(gr, maxBytes), buf)
	if err != nil {
		return fmt.Errorf("failed to copy file: %w", err)
	}
	if written >= maxBytes {
		return fmt.Errorf("file exceeds maximum allowed size (%d bytes): %s", maxBytes, target)
	}

	return nil
}
