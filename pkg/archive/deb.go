package archive

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/malcontent/pkg/pool"
	"github.com/egibs/go-debian/deb"
)

// ExtractDeb extracts .deb packages.
func ExtractDeb(ctx context.Context, d, f string) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	logger := clog.FromContext(ctx).With("dir", d, "file", f)
	logger.Debug("extracting deb")

	initTarPool.Do(func() {
		tarPool = pool.NewBufferPool(runtime.GOMAXPROCS(0))
	})

	fd, err := os.Open(f)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}

	df, err := deb.Load(fd, f)
	if err != nil {
		return fmt.Errorf("failed to load file: %w", err)
	}

	defer func() {
		fd.Close()
		df.Close()
	}()

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
		if !IsValidPath(target, d) {
			return fmt.Errorf("invalid file path: %s", target)
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := handleDirectory(target); err != nil {
				return fmt.Errorf("failed to extract directory: %w", err)
			}
		case tar.TypeReg:
			if err := handleFile(target, df.Data); err != nil {
				return fmt.Errorf("failed to extract file: %w", err)
			}
		case tar.TypeSymlink:
			if err := handleSymlink(d, header.Linkname, target); err != nil {
				return fmt.Errorf("failed to create symlink: %w", err)
			}
		}
	}

	return nil
}
