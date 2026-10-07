// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/malcontent/pkg/file"
	"github.com/egibs/go-debian/deb"
)

// ExtractDeb extracts .deb packages.
func ExtractDeb(ctx context.Context, d, f string) (retErr error) {
	defer recoverExtractor(ctx, "deb", f, &retErr)
	if ctx.Err() != nil {
		return ctx.Err()
	}

	logger := clog.FromContext(ctx).With("dir", d, "file", f)
	logger.Debug("extracting deb")

	fd, err := file.Open(f)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer fd.Close()

	fi, err := fd.Stat()
	if err != nil {
		return fmt.Errorf("failed to stat file: %w", err)
	}

	df, err := deb.Load(newReadAheadReaderAt(fd), f)
	if err != nil {
		return fmt.Errorf("failed to load file: %w", err)
	}
	defer df.Close()

	// Shared counter across every tar member of the deb data archive enforces a
	// uniform byte and ratio ceiling. InputBytes seeds the ratio denominator
	// from the deb file size.
	counter := newArchiveCounter(ctx, fi.Size())

	root, err := openRoot(d)
	if err != nil {
		return err
	}
	defer root.Close()
	er := newEntryRoots(root)
	defer er.close()

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
		if !er.validPath(target, d) {
			return fmt.Errorf("invalid file path: %s", target)
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := handleDirectory(root, clean); err != nil {
				return fmt.Errorf("failed to extract directory: %w", err)
			}
		case tar.TypeReg:
			if err := handleFile(er, clean, df.Data, counter); err != nil {
				return fmt.Errorf("failed to extract file: %w", err)
			}
		case tar.TypeSymlink:
			// Links may replace an entry that other names led through.
			err := handleSymlink(root, clean, header.Linkname)
			er.close()
			if err != nil {
				return fmt.Errorf("failed to create symlink: %w", err)
			}
		case tar.TypeLink:
			err := handleHardlink(root, clean, header.Linkname)
			er.close()
			if err != nil {
				return fmt.Errorf("failed to create hardlink: %w", err)
			}
		}
	}

	return nil
}
