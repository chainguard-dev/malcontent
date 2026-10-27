// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/malcontent/pkg/programkind"
)

// ExtractTar extracts .apk and .tar* archives. The content decides how the
// archive is decompressed, so a tar compressed other than its name says is
// still read, and a zip named .apk, as Android packages are, is extracted as
// a zip. A file named .xz rather than .tar.xz is decompressed to one file.
func ExtractTar(ctx context.Context, d string, f string) (err error) {
	defer recoverExtractor(ctx, "tar", f, &err)
	if ctx.Err() != nil {
		return ctx.Err()
	}

	logger := clog.FromContext(ctx).With("dir", d, "file", f)
	logger.Debug("extracting tar")

	tf, fi, err := openRegular(f)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer tf.Close()

	if fi.Size() == 0 {
		return nil
	}

	kind := sniffKind(tf, fi.Size())
	if kind == kindZip {
		return ExtractZip(ctx, d, f)
	}

	buf := extractPool.Get()
	defer extractPool.Put(buf)

	// One counter across every member of the tar enforces a uniform ratio
	// ceiling; InputBytes seeds the ratio denominator. Bytes are charged to
	// the cap shared by the whole nested tree.
	counter := newArchiveCounter(ctx, fi.Size())

	root, err := openRoot(d)
	if err != nil {
		return err
	}
	defer root.Close()

	// Only the archive's own name decides how a decompressed stream is
	// written out. Directories on its path may carry archive names too, such
	// as the temporary directory named after the scanned archive.
	filename := filepath.Base(f)
	ext := programkind.GetExt(filename)
	switch {
	case kind == kindXZ && ext == ".xz":
		return decompressTo(ctx, root, singleFileName(f, ".xz"), counter, buf, func() (io.Reader, func(), error) {
			r, err := newXZReader(tf, fi.Size())
			return r, func() {}, err
		})
	case kind == kindBzip2 && (ext == ".tar.bz2" || strings.HasPrefix(ext, ".tbz")):
		// The decompressed stream is a tar, so name it as one: nested
		// extraction then extracts it.
		uncompressed := strings.TrimSuffix(filename, ext) + ".tar"
		target := filepath.Join(filepath.Base(filepath.Dir(f)), uncompressed)
		return decompressTo(ctx, root, target, counter, buf, func() (io.Reader, func(), error) {
			br := newBzip2Reader(ctx, io.NewSectionReader(tf, 0, fi.Size()))
			return br, func() { _ = br.Close() }, nil
		})
	}

	x := newTarExtraction(ctx, root, counter, buf)
	defer x.close()

	stream, done, err := tarStream(ctx, kind, tf, fi.Size(), &x.sc)
	if err != nil {
		return err
	}
	defer done()

	return errors.Join(x.extract(stream, ".", filename), x.finish("."))
}

// tarStream returns the tar stream in the archive r, of size bytes, whose
// content is of the given kind, decompressed as that kind requires, and the
// function that releases its decoder. Metadata a gzip stream carries is
// recorded in sc.
func tarStream(ctx context.Context, kind archiveKind, r *os.File, size int64, sc *sidecar) (io.Reader, func(), error) {
	section := io.NewSectionReader(r, 0, size)
	switch kind {
	case kindGzip:
		gz, err := newGzipMembers(section, sc)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create gzip reader: %w", err)
		}
		return gz, func() { _ = gz.Close() }, nil
	case kindXZ:
		xzr, err := newXZReader(r, size)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create xz reader: %w", err)
		}
		return xzr, func() {}, nil
	case kindBzip2:
		br := newBzip2Reader(ctx, section)
		return br, func() { _ = br.Close() }, nil
	case kindZstd:
		zr, err := newZstdReader(bufferInput(section))
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create zstd reader: %w", err)
		}
		return zr, zr.Close, nil
	default:
		// The tar reader reads the archive through one buffer.
		return bufferInput(section), func() {}, nil
	}
}

// singleFileName returns where the decompressed copy of f, named with suffix
// ext, is written beneath the extraction directory: in a directory named
// after the one holding f.
func singleFileName(f, ext string) string {
	return filepath.Join(filepath.Base(filepath.Dir(f)), strings.TrimSuffix(filepath.Base(f), ext))
}

// decompressTo writes the stream open returns to target beneath root,
// charging counter, and releases the stream's decoder.
func decompressTo(ctx context.Context, root *os.Root, target string, counter *budget, buf []byte, open func() (io.Reader, func(), error)) error {
	r, done, err := open()
	if err != nil {
		return err
	}
	defer done()
	if err := counter.Entry(); err != nil {
		return fmt.Errorf("extraction aborted on %q: %w", target, err)
	}
	out, err := createFile(root, target)
	if err != nil {
		return err
	}
	defer out.Close()
	return copyCounted(ctx, out, r, counter, buf, target)
}

// copyCounted copies r to out through buf, charging counter for every byte
// and checking for cancellation before every read, since a decompressor read
// returns whatever it decoded and need not fill buf.
func copyCounted(ctx context.Context, out io.Writer, r io.Reader, counter *budget, buf []byte, target string) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		n, err := r.Read(buf)
		if n > 0 {
			if capErr := counter.Add(n); capErr != nil {
				return fmt.Errorf("extraction aborted on %q: %w", target, capErr)
			}
			if _, writeErr := out.Write(buf[:n]); writeErr != nil {
				return fmt.Errorf("failed to write file contents: %w", writeErr)
			}
		}

		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("failed to read file contents: %w", err)
		}
	}
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
