package archive

import (
	"compress/zlib"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/chainguard-dev/clog"
)

// extractZlib extracts extension-agnostic zlib-compressed files.
func ExtractZlib(ctx context.Context, d string, f string) error {
	logger := clog.FromContext(ctx).With("dir", d, "file", f)
	logger.Debugf("extracting zlib")

	// Check if the file is valid
	_, err := os.Stat(f)
	if err != nil {
		return fmt.Errorf("failed to stat file: %w", err)
	}

	gf, err := os.Open(f)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer gf.Close()

	base := filepath.Base(f)
	target := filepath.Join(d, base[:len(base)-len(filepath.Ext(base))])

	zr, err := zlib.NewReader(gf)
	if err != nil {
		return fmt.Errorf("failed to create zlib reader: %w", err)
	}
	defer zr.Close()

	ef, err := os.Create(target)
	if err != nil {
		return fmt.Errorf("failed to create extracted file: %w", err)
	}
	defer ef.Close()

	if _, err := io.Copy(ef, io.LimitReader(zr, maxBytes)); err != nil {
		return fmt.Errorf("failed to copy file: %w", err)
	}

	return nil
}
