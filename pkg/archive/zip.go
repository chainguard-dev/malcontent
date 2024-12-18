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

		name := filepath.Join(d, clean)
		if !IsValidPath(name, d) {
			logger.Warnf("skipping file path outside extraction directory: %s", name)
			continue
		}

		// Check if a directory with the same name exists
		if info, err := os.Stat(name); err == nil && info.IsDir() {
			continue
		}

		if file.Mode().IsDir() {
			mode := file.Mode() | 0o700
			err := os.MkdirAll(name, mode)
			if err != nil {
				return fmt.Errorf("failed to create directory: %w", err)
			}
			continue
		}

		open, err := file.Open()
		if err != nil {
			return fmt.Errorf("failed to open file in zip: %w", err)
		}

		err = os.MkdirAll(filepath.Dir(name), 0o700)
		if err != nil {
			open.Close()
			return fmt.Errorf("failed to create directory: %w", err)
		}

		mode := file.Mode() | 0o200
		create, err := os.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_TRUNC, mode)
		if err != nil {
			open.Close()
			return fmt.Errorf("failed to create file: %w", err)
		}

		if _, err = io.Copy(create, io.LimitReader(open, maxBytes)); err != nil {
			open.Close()
			create.Close()
			return fmt.Errorf("failed to copy file: %w", err)
		}

		open.Close()
		create.Close()
	}
	return nil
}
