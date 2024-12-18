package archive

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/chainguard-dev/clog"
	"github.com/egibs/go-debian/deb"
)

// ExtractDeb extracts .deb packages.
func ExtractDeb(ctx context.Context, d, f string) error {
	logger := clog.FromContext(ctx).With("dir", d, "file", f)
	logger.Debug("extracting deb")

	fd, err := os.Open(f)
	if err != nil {
		panic(err)
	}
	defer fd.Close()

	df, err := deb.Load(fd, f)
	if err != nil {
		panic(err)
	}
	defer df.Close()

	for {
		header, err := df.Data.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read tar header: %w", err)
		}

		clean := filepath.Clean(header.Name)
		if filepath.IsAbs(clean) || strings.Contains(clean, "../") {
			return fmt.Errorf("path is absolute or contains a relative path traversal: %s", clean)
		}

		target := filepath.Join(d, clean)

		switch header.Typeflag {
		case tar.TypeDir:
			// #nosec G115 // ignore Type conversion which leads to integer overflow
			// header.Mode is int64 and FileMode is uint32
			if err := os.MkdirAll(target, os.FileMode(header.Mode)); err != nil {
				return fmt.Errorf("failed to create directory: %w", err)
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
				return fmt.Errorf("failed to create parent directory: %w", err)
			}

			// #nosec G115
			out, err := os.OpenFile(target, os.O_RDWR|os.O_CREATE|os.O_TRUNC, os.FileMode(header.Mode))
			if err != nil {
				return fmt.Errorf("failed to create file: %w", err)
			}

			if _, err := io.Copy(out, io.LimitReader(df.Data, maxBytes)); err != nil {
				out.Close()
				return fmt.Errorf("failed to copy file: %w", err)
			}

			if err := out.Close(); err != nil {
				return fmt.Errorf("failed to close file: %w", err)
			}
		case tar.TypeSymlink:
			// Skip symlinks for targets that do not exist
			_, err = os.Readlink(target)
			if os.IsNotExist(err) {
				continue
			}
			// Ensure that symlinks are not relative path traversals
			// #nosec G305 // L208 handles the check
			linkReal, err := filepath.EvalSymlinks(filepath.Join(d, header.Linkname))
			if err != nil {
				return fmt.Errorf("failed to evaluate symlink: %w", err)
			}
			if !IsValidPath(linkReal, d) {
				return fmt.Errorf("symlink points outside temporary directory: %s", linkReal)
			}
			if err := os.Symlink(linkReal, target); err != nil {
				return fmt.Errorf("failed to create symlink: %w", err)
			}
		}
	}

	return nil
}
