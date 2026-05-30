// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

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
	"github.com/chainguard-dev/malcontent/pkg/file"
	"github.com/chainguard-dev/malcontent/pkg/programkind"
	bzip2 "github.com/cosnicolaou/pbzip2"
	gzip "github.com/klauspost/pgzip"
	"github.com/ulikunitz/xz"
)

// extractTar extracts .apk and .tar* archives.
//
//nolint:cyclop,gocognit // ignore complexity of 42, 99 respectively
func ExtractTar(ctx context.Context, d string, f string) (err error) {
	defer recoverExtractor(ctx, "tar", f, &err)
	if ctx.Err() != nil {
		return ctx.Err()
	}

	logger := clog.FromContext(ctx).With("dir", d, "file", f)
	logger.Debug("extracting tar")

	// Check if the file is valid
	fi, err := os.Stat(f)
	if err != nil {
		return fmt.Errorf("failed to stat file: %w", err)
	}

	if fi.Size() == 0 {
		return nil
	}

	buf := tarPool.Get(file.ExtractBuffer) //nolint:nilaway // the buffer pool is created in archive.go
	defer tarPool.Put(buf)

	// Shared counter across every member of the tar enforces a uniform byte
	// and ratio ceiling. InputBytes seeds the ratio denominator. Caps prefer
	// ctx-attached Config values; absent/zero values fall back to the
	// package defaults so zero-config callers still receive a finite cap.
	maxBytes, maxRatio := resolveArchiveCaps(ctx)
	counter := &file.ArchiveCounter{
		MaxBytes:   maxBytes,
		MaxRatio:   maxRatio,
		InputBytes: fi.Size(),
	}

	filename := filepath.Base(f)
	tf, err := os.Open(f) // #nosec G304 -- archive path resolved and validated by caller before extraction
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer tf.Close()

	isTGZ := strings.Contains(f, ".tar.gz") || strings.Contains(f, ".tgz")
	var isGzip bool
	if ft, err := programkind.File(ctx, f); err == nil && ft != nil {
		if _, ok := GzMIME[ft.MIME]; ok {
			isGzip = true
		}
	}

	// Set offset to the file origin regardless of type
	_, err = tf.Seek(0, io.SeekStart)
	if err != nil {
		return fmt.Errorf("failed to seek to start: %w", err)
	}

	var tr *tar.Reader
	switch {
	case strings.Contains(f, ".apk") || (isTGZ && isGzip):
		gzStream, err := gzip.NewReader(tf)
		if err != nil {
			return fmt.Errorf("failed to create gzip reader: %w", err)
		}
		defer gzStream.Close()
		tr = tar.NewReader(gzStream)
	case strings.Contains(filename, ".tar.xz"):
		xzStream, err := xz.NewReader(tf)
		if err != nil {
			return fmt.Errorf("failed to create xz reader: %w", err)
		}
		tr = tar.NewReader(xzStream)
	case strings.Contains(filename, ".xz"):
		xzStream, err := xz.NewReader(tf)
		if err != nil {
			return fmt.Errorf("failed to create xz reader: %w", err)
		}
		uncompressed := strings.TrimSuffix(filepath.Base(f), ".xz")
		target := filepath.Join(d, filepath.Base(filepath.Dir(f)), uncompressed)
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return fmt.Errorf("failed to create directory for file: %w", err)
		}

		out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600) // #nosec G304 -- target path computed under sandbox dir d, parent dir created with 0700
		if err != nil {
			return fmt.Errorf("failed to create file: %w", err)
		}
		defer out.Close()

		var written int64
		for {
			if written > 0 && written%file.ExtractBuffer == 0 && ctx.Err() != nil {
				return ctx.Err()
			}

			n, err := xzStream.Read(buf)
			if n > 0 {
				written += int64(n)
				if written > file.MaxBytes {
					return fmt.Errorf("file exceeds maximum allowed size (%d bytes): %s", file.MaxBytes, target)
				}
				if capErr := counter.Add(n); capErr != nil {
					return fmt.Errorf("xz extraction aborted on %s: %w", target, capErr)
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
	case strings.Contains(filename, ".tar.bz2") || strings.Contains(filename, ".tbz"):
		br := bzip2.NewReader(ctx, tf)
		uncompressed := strings.TrimSuffix(filepath.Base(f), programkind.GetExt(filename))
		target := filepath.Join(d, filepath.Base(filepath.Dir(f)), uncompressed)
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return fmt.Errorf("failed to create directory for file: %w", err)
		}
		out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600) // #nosec G304 -- target path computed under sandbox dir d, parent dir created with 0700
		if err != nil {
			return fmt.Errorf("failed to create file: %w", err)
		}
		defer out.Close()

		var written int64
		for {
			if written > 0 && written%file.ExtractBuffer == 0 && ctx.Err() != nil {
				return ctx.Err()
			}

			n, err := br.Read(buf)
			if n > 0 {
				written += int64(n)
				if written > file.MaxBytes {
					return fmt.Errorf("file exceeds maximum allowed size (%d bytes): %s", file.MaxBytes, target)
				}

				if capErr := counter.Add(n); capErr != nil {
					return fmt.Errorf("bz2 extraction aborted on %s: %w", target, capErr)
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
	default:
		tr = tar.NewReader(tf)
	}

	sem := extractionSemaphore()
	for {
		header, err := tr.Next()

		if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
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

		if err := ValidateResolvedPath(target, d, clean); err != nil {
			return err
		}

		if err := func() error {
			if err := sem.Acquire(ctx, 1); err != nil {
				return err
			}
			defer sem.Release(1)
			switch header.Typeflag {
			case tar.TypeDir:
				if err := handleDirectory(target); err != nil {
					return fmt.Errorf("failed to extract directory: %w", err)
				}
			case tar.TypeReg:
				if err := handleFile(target, tr, counter); err != nil {
					return fmt.Errorf("failed to extract file: %w", err)
				}
			case tar.TypeSymlink:
				if err := handleSymlink(d, clean, header.Linkname); err != nil {
					return fmt.Errorf("failed to create symlink: %w", err)
				}
			case tar.TypeLink:
				if err := handleHardlink(d, clean, header.Linkname); err != nil {
					return fmt.Errorf("failed to create hardlink: %w", err)
				}
			}
			return nil
		}(); err != nil {
			return err
		}
	}
	return nil
}
