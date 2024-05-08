package action

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/chainguard-dev/clog"
	"github.com/ulikunitz/xz"
)

const maxBytes = 1 << 29 // 512MB

// extractTar extracts .apk and .tar* archives.
func extractTar(ctx context.Context, d string, f string) error {
	logger := clog.FromContext(ctx).With("dir", d, "file", f)
	logger.Info("extracting tar")

	// Check if the file is valid
	_, err := os.Stat(f)
	if err != nil {
		return fmt.Errorf("failed to stat file: %w", err)
	}

	tf, err := os.Open(f)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer tf.Close()

	tr := tar.NewReader(tf)

	if strings.Contains(f, ".apk") || strings.Contains(f, ".tar.gz") || strings.Contains(f, ".tgz") {
		gzStream, err := gzip.NewReader(tf)
		if err != nil {
			return fmt.Errorf("failed to create gzip reader: %w", err)
		}
		defer gzStream.Close()
		tr = tar.NewReader(gzStream)
	}
	if strings.Contains(f, ".tar.xz") {
		xzStream, err := xz.NewReader(tf)
		if err != nil {
			return fmt.Errorf("failed to create xz reader: %w", err)
		}
		tr = tar.NewReader(xzStream)
	}

	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read tar header: %w", err)
		}
		clean := filepath.Clean(header.Name)
		if filepath.IsAbs(clean) || strings.HasPrefix(clean, "..") {
			return fmt.Errorf("invalid file path: %s", header.Name)
		}
		target := filepath.Join(d, clean)
		if header.FileInfo().IsDir() {
			if err := os.MkdirAll(target, os.FileMode(header.Mode)); err != nil {
				return fmt.Errorf("failed to create directory: %w", err)
			}
			continue
		}

		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return fmt.Errorf("failed to create directory for file: %w", err)
		}

		f, err := os.OpenFile(target, os.O_RDWR|os.O_CREATE|os.O_TRUNC, os.FileMode(header.Mode))
		if err != nil {
			return fmt.Errorf("failed to create file: %w", err)
		}

		if _, err := io.Copy(f, io.LimitReader(tr, maxBytes)); err != nil {
			return fmt.Errorf("failed to copy file: %w", err)
		}

		if err := f.Close(); err != nil {
			return fmt.Errorf("failed to close file: %w", err)
		}
	}
	return nil
}

// extractZip extracts .jar and .zip archives.
func extractZip(ctx context.Context, d string, f string) error {
	logger := clog.FromContext(ctx).With("dir", d, "file", f)
	logger.Info("extracting zip")

	// Check if the file is valid
	_, err := os.Stat(f)
	if err != nil {
		return fmt.Errorf("failed to stat file: %w", err)
	}

	read, err := zip.OpenReader(f)
	if err != nil {
		return fmt.Errorf("failed to open zip file: %w", err)
	}
	defer read.Close()

	for _, file := range read.File {
		name := filepath.Join(d, filepath.Clean(filepath.ToSlash(file.Name)))

		// Check if a directory with the same name exists
		if info, err := os.Stat(name); err == nil && info.IsDir() {
			continue
		}

		if file.Mode().IsDir() {
			mode := file.Mode() | 0o755
			err := os.MkdirAll(name, mode)
			if err != nil {
				return fmt.Errorf("failed to create directory: %w", err)
			}
			continue
		}

		open, err := file.Open()
		if err != nil {
			open.Close()
			return fmt.Errorf("failed to open file in zip: %w", err)
		}

		err = os.MkdirAll(filepath.Dir(name), 0o755)
		if err != nil {
			return fmt.Errorf("failed to create directory: %w", err)
		}

		mode := file.Mode() | 0o200
		create, err := os.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_TRUNC, mode)
		if err != nil {
			create.Close()
			return fmt.Errorf("failed to create file: %w", err)
		}

		if _, err = io.Copy(create, io.LimitReader(open, maxBytes)); err != nil {
			return fmt.Errorf("failed to copy file: %w", err)
		}

		open.Close()
		create.Close()
	}
	return nil
}

// extractArchive specifies which extraction method to use based on the archive type.
func extractArchive(ctx context.Context, d string, f string) error {
	switch {
	// .jar and .zip files can be extracted using the same method
	case strings.Contains(f, ".jar") || strings.Contains(f, ".zip"):
		if err := extractZip(ctx, d, f); err != nil {
			return fmt.Errorf("extract zip: %w", err)
		}
	// .apk and .tar* files can be extracted using the same method
	case strings.Contains(f, ".apk") || strings.Contains(f, ".tar") || strings.Contains(f, ".tgz"):
		if err := extractTar(ctx, d, f); err != nil {
			return fmt.Errorf("extract tar: %w", err)
		}
	// Unsupported archive type
	default:
		return fmt.Errorf("unsupported archive type: %s", f)
	}
	return nil
}

// extractArchiveToTempDir creates a temporary directory and extracts the archive file for scanning.
func extractArchiveToTempDir(ctx context.Context, path string) (string, error) {
	logger := clog.FromContext(ctx).With("path", path)
	logger.Info("creating temp dir")

	tmpDir, err := os.MkdirTemp("", filepath.Base(path))
	if err != nil {
		return "", fmt.Errorf("failed to create temp dir: %w", err)
	}

	if err := extractArchive(ctx, tmpDir, path); err != nil {
		return "", fmt.Errorf("extract: %w", err)
	}

	return tmpDir, nil
}
