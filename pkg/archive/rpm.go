// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/cavaliergopher/cpio"
	"github.com/cavaliergopher/rpm"
	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/malcontent/pkg/file"
	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"
)

// extractFileFromCPIO extracts a single file from a CPIO archive. The counter
// accumulates uncompressed bytes across every member so the aggregate byte and
// ratio caps span the whole payload; a nil counter disables accounting.
func extractFileFromCPIO(ctx context.Context, cr *cpio.Reader, target string, buf []byte, counter *file.ArchiveCounter) error {
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		return fmt.Errorf("failed to create parent directory: %w", err)
	}

	out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600) // #nosec G304 -- target validated by IsValidPath + ValidateResolvedPath against sandbox dir before reaching this helper
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer out.Close()

	var written int64
	for {
		if written > 0 && written%file.ExtractBuffer == 0 && ctx.Err() != nil {
			return ctx.Err()
		}

		n, err := cr.Read(buf)
		if n > 0 {
			written += int64(n)
			if written > file.MaxBytes {
				return fmt.Errorf("file exceeds maximum allowed size (%d bytes): %s", file.MaxBytes, target)
			}
			if capErr := counter.Add(n); capErr != nil {
				return fmt.Errorf("rpm extraction aborted on %s: %w", target, capErr)
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

// extractRPM extracts .rpm packages.
func ExtractRPM(ctx context.Context, d, f string) (retErr error) {
	defer recoverExtractor(ctx, "rpm", f, &retErr)
	if ctx.Err() != nil {
		return ctx.Err()
	}

	logger := clog.FromContext(ctx).With("dir", d, "file", f)
	logger.Debug("extracting rpm")

	rpmFile, err := os.Open(f) // #nosec G304 -- archive path resolved and validated by caller before extraction
	if err != nil {
		return fmt.Errorf("failed to open RPM file: %w", err)
	}
	defer rpmFile.Close()

	fi, err := rpmFile.Stat()
	if err != nil {
		return fmt.Errorf("failed to stat RPM file: %w", err)
	}
	if fi.Size() == 0 {
		return nil
	}

	buf := archivePool.Get(file.ExtractBuffer) //nolint:nilaway // the buffer pool is created in archive.go
	defer archivePool.Put(buf)

	// Shared counter across every CPIO member enforces a uniform byte and ratio
	// ceiling. InputBytes seeds the ratio denominator from the RPM file size.
	maxBytes, maxRatio := resolveArchiveCaps(ctx)
	counter := &file.ArchiveCounter{
		MaxBytes:   maxBytes,
		MaxRatio:   maxRatio,
		InputBytes: fi.Size(),
	}

	pkg, err := rpm.Read(rpmFile)
	if err != nil {
		return fmt.Errorf("failed to read RPM package headers: %w", err)
	}

	if format := pkg.PayloadFormat(); format != "cpio" {
		return fmt.Errorf("unsupported payload format: %s", format)
	}

	payloadOffset, err := rpmFile.Seek(0, io.SeekCurrent)
	if err != nil {
		return fmt.Errorf("failed to get payload offset: %w", err)
	}

	if _, err := rpmFile.Seek(payloadOffset, io.SeekStart); err != nil {
		return fmt.Errorf("failed to seek to payload: %w", err)
	}

	var cr *cpio.Reader
	switch compression := pkg.PayloadCompression(); compression {
	case "gzip":
		gzStream, err := gzip.NewReader(rpmFile)
		if err != nil {
			return fmt.Errorf("failed to create gzip reader: %w", err)
		}
		defer gzStream.Close()
		cr = cpio.NewReader(gzStream)
	case "xz":
		xzStream, err := xz.NewReader(rpmFile)
		if err != nil {
			return fmt.Errorf("failed to create xz reader: %w", err)
		}
		cr = cpio.NewReader(xzStream)
	case "zstd":
		zstdStream, err := zstd.NewReader(rpmFile)
		if err != nil {
			return fmt.Errorf("failed to create zstd reader: %w", err)
		}
		defer zstdStream.Close()
		cr = cpio.NewReader(zstdStream)
	default:
		return fmt.Errorf("unsupported compression format: %s", compression)
	}

	inodeMap := make(map[int64]string)

	for {
		header, err := cr.Next()
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read cpio header: %w", err)
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

		// https://github.com/cavaliergopher/cpio/blob/main/header.go#L24
		const modeTypeMask = 0o170000
		fileType := header.Mode & modeTypeMask

		switch fileType {
		case cpio.TypeDir:
			if err := os.MkdirAll(target, 0o700); err != nil {
				return fmt.Errorf("failed to create directory: %w", err)
			}
			continue
		case cpio.TypeSymlink:
			if err := handleSymlink(d, clean, header.Linkname); err != nil {
				return fmt.Errorf("failed to create symlink: %w", err)
			}
			continue
		case cpio.TypeReg:
			if header.Links > 1 {
				if existingPath, ok := inodeMap[header.Inode]; ok {
					if err := handleHardlink(d, clean, existingPath); err != nil {
						return fmt.Errorf("failed to create hardlink: %w", err)
					}
					continue
				}
				inodeMap[header.Inode] = clean
			}
		default:
			continue
		}

		if err := extractFileFromCPIO(ctx, cr, target, buf, counter); err != nil {
			return err
		}
	}

	return nil
}
