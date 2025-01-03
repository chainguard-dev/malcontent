package archive

import (
	"archive/zip"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/chainguard-dev/clog"
)

// extractZip extracts .jar and .zip archives.
func ExtractZip(ctx context.Context, d string, f string) error {
	logger := clog.FromContext(ctx).With("dir", d, "file", f)
	logger.Debug("extracting zip")

	// Check if the file is valid
	_, err := os.Stat(f)
	if err != nil {
		return fmt.Errorf("failed to stat file %s: %w", f, err)
	}

	read, err := zip.OpenReader(f)
	if err != nil {
		return fmt.Errorf("failed to open zip file %s: %w", f, err)
	}
	defer read.Close()

	for _, file := range read.File {
		clean := filepath.Clean(filepath.ToSlash(file.Name))
		if strings.Contains(clean, "..") {
			logger.Warnf("skipping potentially unsafe file path: %s", file.Name)
			continue
		}

		target := filepath.Join(d, clean)
		if !IsValidPath(target, d) {
			logger.Warnf("skipping file path outside extraction directory: %s", target)
			continue
		}

		// Check if a directory with the same name exists
		if info, err := os.Stat(target); err == nil && info.IsDir() {
			continue
		}

		if file.Mode().IsDir() {
			err := os.MkdirAll(target, 0o700)
			if err != nil {
				return fmt.Errorf("failed to create directory: %w", err)
			}
			continue
		}

		zf, err := file.Open()
		if err != nil {
			return fmt.Errorf("failed to open file in zip: %w", err)
		}

		err = os.MkdirAll(filepath.Dir(target), 0o700)
		if err != nil {
			zf.Close()
			return fmt.Errorf("failed to create directory: %w", err)
		}

		out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			out.Close()
			return fmt.Errorf("failed to create file: %w", err)
		}

		written, err := io.Copy(out, io.LimitReader(zf, maxBytes))
		if err != nil {
			return fmt.Errorf("failed to copy file: %w", err)
		}
		if written >= maxBytes {
			return fmt.Errorf("file exceeds maximum allowed size (%d bytes): %s", maxBytes, target)
		}

		if err := out.Close(); err != nil {
			return fmt.Errorf("failed to close file: %w", err)
		}

		if err := zf.Close(); err != nil {
			return fmt.Errorf("failed to close file: %w", err)
		}
	}
	return nil
}
