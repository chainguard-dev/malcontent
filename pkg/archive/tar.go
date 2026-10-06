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
	"github.com/ulikunitz/xz"
	"golang.org/x/sync/semaphore"
)

// ExtractTar extracts .apk and .tar* archives.
func ExtractTar(ctx context.Context, d string, f string) error {
	return extractTarWithKind(ctx, d, f, detectFileType(ctx, f))
}

// extractTarWithKind is ExtractTar with the archive's detected type reported by
// fileType, which it calls only when the type decides how to read the archive.
//
//nolint:cyclop // one branch per compression format and per read or write failure
func extractTarWithKind(ctx context.Context, d, f string, fileType func() *programkind.FileType) (err error) {
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

	buf := extractPool.Get()
	defer extractPool.Put(buf)

	// Shared counter across every member of the tar enforces a uniform byte
	// and ratio ceiling. InputBytes seeds the ratio denominator. Caps prefer
	// ctx-attached Config values; absent/zero values fall back to the
	// package defaults so zero-config callers still receive a finite cap.
	counter := newArchiveCounter(ctx, fi.Size())

	root, err := openRoot(d)
	if err != nil {
		return err
	}
	defer root.Close()

	filename := filepath.Base(f)
	tf, err := os.Open(f) // #nosec G304 -- archive path resolved and validated by caller before extraction
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer tf.Close()

	// Only the archive's own name selects its compression. Directories on its
	// path may carry archive names too, such as the temporary directory named
	// after the scanned archive, so testing the full path would read a plain
	// tar nested in an .apk as gzip.
	isTGZ := strings.Contains(filename, ".tar.gz") || strings.Contains(filename, ".tgz")
	isApk := strings.Contains(filename, ".apk")
	// The detected type decides only whether a .tar.gz or .tgz name that is
	// not an .apk is read as gzip, so detection, which reads the whole file,
	// runs only for those names.
	isGzip := isTGZ && !isApk && isGzipType(fileType())

	// Set offset to the file origin regardless of type
	_, err = tf.Seek(0, io.SeekStart)
	if err != nil {
		return fmt.Errorf("failed to seek to start: %w", err)
	}

	// stream is the byte stream the tar reader consumes, retained so that the
	// region past the end-of-archive marker can be audited once extraction ends.
	// The decompressors read the archive through one buffer, and so does the
	// tar reader when nothing decompresses it.
	var stream io.Reader
	switch {
	case isApk || isGzip:
		gzStream, err := newGzipReader(tf)
		if err != nil {
			return fmt.Errorf("failed to create gzip reader: %w", err)
		}
		defer gzStream.Close()
		stream = gzStream
	case strings.Contains(filename, ".tar.xz"):
		xzStream, err := xz.NewReader(bufferInput(tf))
		if err != nil {
			return fmt.Errorf("failed to create xz reader: %w", err)
		}
		stream = xzStream
	case strings.Contains(filename, ".xz"):
		xzStream, err := xz.NewReader(bufferInput(tf))
		if err != nil {
			return fmt.Errorf("failed to create xz reader: %w", err)
		}
		uncompressed := strings.TrimSuffix(filepath.Base(f), ".xz")
		target := filepath.Join(filepath.Base(filepath.Dir(f)), uncompressed)
		out, err := createFile(root, target)
		if err != nil {
			return err
		}
		defer out.Close()

		for {
			if err := ctx.Err(); err != nil {
				return err
			}

			n, err := xzStream.Read(buf)
			if n > 0 {
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
		// pbzip2 decodes on background goroutines that block on an internal
		// pipe until every decompressed byte has been read. Canceling and
		// reading once more makes the reader close that pipe and wait for
		// them, so returning early does not leave them blocked. It buffers
		// its input itself, a whole bzip2 block at a time.
		bzCtx, cancel := context.WithCancel(ctx)
		br := bzip2.NewReader(bzCtx, tf)
		defer func() {
			cancel()
			_, _ = br.Read(nil)
		}()
		// The decompressed stream is a tar, so name it as one: nested
		// extraction recognizes a tar by its name, and would otherwise leave
		// its members unextracted.
		ext := programkind.GetExt(filename)
		uncompressed := strings.TrimSuffix(filepath.Base(f), ext)
		if ext == ".tar.bz2" || strings.HasPrefix(ext, ".tbz") {
			uncompressed += ".tar"
		}
		target := filepath.Join(filepath.Base(filepath.Dir(f)), uncompressed)
		out, err := createFile(root, target)
		if err != nil {
			return err
		}
		defer out.Close()

		// Check before every read, since a pbzip2 read returns at most the
		// rest of one decoded block and need not fill the buffer.
		for {
			if err := ctx.Err(); err != nil {
				return err
			}

			n, err := br.Read(buf)
			if n > 0 {
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
		stream = bufferInput(tf)
	}

	// The auditor observes exactly the bytes the tar reader consumes, so it can
	// account for the regions archive/tar discards without re-reading the file.
	// Wrapping in a TeeReader also hides the underlying io.Seeker, which forces
	// archive/tar to read over skipped entry data and padding rather than seek
	// past it, so those bytes reach the auditor too.
	auditor := newTarAuditor()
	tr := tar.NewReader(io.TeeReader(stream, auditor))

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

		if err := extractTarEntry(ctx, sem, root, tr, header, clean, counter); err != nil {
			return err
		}
	}

	// archive/tar stops at the end-of-archive marker, so bytes appended past it
	// are never read. Drain them through the auditor: a payload hidden there
	// would otherwise be discarded along with the archive.
	if err := auditTarTrailer(stream, auditor, buf); err != nil {
		return fmt.Errorf("%w in %s: %w", ErrUnaccountedBytes, filename, err)
	}

	if err := auditor.err(); err != nil {
		return fmt.Errorf("%w in %s: %w", ErrUnaccountedBytes, filename, err)
	}

	return nil
}

// extractTarEntry writes the entry that header describes beneath root as
// clean, its cleaned name, reading any content from tr. It holds one slot of
// sem while it writes.
func extractTarEntry(ctx context.Context, sem *semaphore.Weighted, root *os.Root, tr *tar.Reader, header *tar.Header, clean string, counter *file.ArchiveCounter) error {
	if err := sem.Acquire(ctx, 1); err != nil {
		return err
	}
	defer sem.Release(1)
	switch header.Typeflag {
	case tar.TypeDir:
		if err := handleDirectory(root, clean); err != nil {
			return fmt.Errorf("failed to extract directory: %w", err)
		}
	case tar.TypeReg:
		if err := handleFile(root, clean, tr, counter); err != nil {
			return fmt.Errorf("failed to extract file: %w", err)
		}
	case tar.TypeSymlink:
		if err := handleSymlink(root, clean, header.Linkname); err != nil {
			return fmt.Errorf("failed to create symlink: %w", err)
		}
	case tar.TypeLink:
		if err := handleHardlink(root, clean, header.Linkname); err != nil {
			return fmt.Errorf("failed to create hardlink: %w", err)
		}
	default:
		// Entries carrying data under a typeflag this switch does not name
		// (tar.TypeCont and unrecognized flags among them) would otherwise be
		// skipped, leaving their content out of the scan corpus while the
		// archive is deleted as fully extracted.
		if header.Size > 0 && !isTarHeaderOnlyType(header.Typeflag) {
			if err := handleFile(root, clean, tr, counter); err != nil {
				return fmt.Errorf("failed to extract file: %w", err)
			}
		}
	}
	return nil
}

// auditTarTrailer feeds everything past the end-of-archive marker to the
// auditor, copying through buf.
func auditTarTrailer(stream io.Reader, auditor *tarAuditor, buf []byte) error {
	n, err := io.CopyBuffer(auditor, io.LimitReader(stream, maxTrailerAudit+1), buf)
	if err != nil {
		// A decompressor rejecting what follows its stream is itself evidence of
		// content that no entry accounted for.
		return fmt.Errorf("reading past end-of-archive marker: %w", err)
	}
	if n > maxTrailerAudit {
		return fmt.Errorf("trailing region exceeds the %d byte audit limit", maxTrailerAudit)
	}
	return nil
}
