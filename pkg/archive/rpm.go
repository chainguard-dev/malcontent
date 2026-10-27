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

	"github.com/cavaliergopher/cpio"
	"github.com/cavaliergopher/rpm"
	"github.com/chainguard-dev/clog"
)

// extractFileFromCPIO writes the content of the current cpio member as a new
// file for name, at the path p assigns it. The counter accumulates
// uncompressed bytes across every member so the aggregate byte and ratio caps
// span the whole payload; a nil counter disables accounting.
func extractFileFromCPIO(ctx context.Context, cr *cpio.Reader, p *entryPaths, name string, buf []byte, counter *budget) error {
	out, _, err := p.createFile(name)
	if err != nil {
		return err
	}
	defer out.Close()
	return copyCounted(ctx, out, cr, counter, buf, name)
}

// rpmLink identifies a hard link set in an RPM payload: the device and inode
// numbers its members share.
type rpmLink struct {
	dev   int
	inode int64
}

// ExtractRPM extracts .rpm packages.
func ExtractRPM(ctx context.Context, d, f string) (retErr error) {
	defer recoverExtractor(ctx, "rpm", f, &retErr)
	if ctx.Err() != nil {
		return ctx.Err()
	}

	logger := clog.FromContext(ctx).With("dir", d, "file", f)
	logger.Debug("extracting rpm")

	rpmFile, fi, err := openRegular(f)
	if err != nil {
		return fmt.Errorf("failed to open RPM file: %w", err)
	}
	defer rpmFile.Close()

	if fi.Size() == 0 {
		return nil
	}

	buf := extractPool.Get()
	defer extractPool.Put(buf)

	// Shared counter across every CPIO member enforces a uniform byte and ratio
	// ceiling. InputBytes seeds the ratio denominator from the RPM file size.
	counter := newArchiveCounter(ctx, fi.Size())

	root, err := openRoot(d)
	if err != nil {
		return err
	}
	defer root.Close()
	x := newTarExtraction(ctx, root, counter, buf)
	defer x.close()

	pkg, err := rpm.Read(rpmFile)
	if err != nil {
		return fmt.Errorf("failed to read RPM package headers: %w", err)
	}

	// rpm(8) reads a payload whose format tag is absent as cpio.
	if format := pkg.PayloadFormat(); format != "cpio" && format != "" {
		return fmt.Errorf("unsupported payload format: %q", format)
	}

	payloadOffset, err := rpmFile.Seek(0, io.SeekCurrent)
	if err != nil {
		return fmt.Errorf("failed to get payload offset: %w", err)
	}

	payload, done, err := rpmPayload(ctx, pkg.PayloadCompression(), rpmFile, payloadOffset, fi.Size()-payloadOffset)
	if err != nil {
		return err
	}
	defer done()

	err = extractCPIO(x, cpio.NewReader(payload))
	return errors.Join(err, x.finish("."))
}

// rpmPayload returns the decompressed payload that starts at offset in
// rpmFile and runs for size bytes, decompressed as the compressor tag says,
// and the function that releases its decoder. As rpm(8) does, it reads a
// payload whose compressor tag is empty as gzip.
func rpmPayload(ctx context.Context, compression string, rpmFile *os.File, offset, size int64) (io.Reader, func(), error) {
	section := io.NewSectionReader(rpmFile, offset, size)
	// rpm.Read stays unbuffered: it assumes each read of a header field
	// returns the whole field. Only the payload decompressor reads from here,
	// so its input is buffered.
	switch compression {
	case "gzip", "":
		gzStream, err := gzip.NewReader(bufferInput(section))
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create gzip reader: %w", err)
		}
		return gzStream, func() { _ = gzStream.Close() }, nil
	case "xz":
		xzStream, err := newXZReader(section, size)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create xz reader: %w", err)
		}
		return xzStream, func() {}, nil
	case "zstd":
		zstdStream, err := newZstdReader(bufferInput(section))
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create zstd reader: %w", err)
		}
		return zstdStream, zstdStream.Close, nil
	case "bzip2":
		br := newBzip2Reader(ctx, section)
		return br, func() { _ = br.Close() }, nil
	case "lzma":
		lzmaStream, err := newLZMAReader(section)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create lzma reader: %w", err)
		}
		return lzmaStream, func() {}, nil
	default:
		return nil, nil, fmt.Errorf("unsupported compression format: %q", compression)
	}
}

// extractCPIO writes the members of the cpio archive cr beneath x's root. A
// member that cannot be written is logged and skipped, as tar entries are.
func extractCPIO(x *tarExtraction, cr *cpio.Reader) error {
	links := map[rpmLink]string{}
	for {
		if err := x.ctx.Err(); err != nil {
			return err
		}
		header, err := cr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			// A payload that ends inside a header is truncated, and is never
			// treated as a clean end.
			return fmt.Errorf("failed to read cpio header: %w", err)
		}
		if err := x.budget.Entry(); err != nil {
			return fmt.Errorf("rpm extraction aborted on %q: %w", header.Name, err)
		}
		content, err := extractCPIOMember(x, cr, header, links)
		if err == nil {
			continue
		}
		if fatalExtractionError(x.ctx, err) {
			return err
		}
		x.logger.Warnf("skipping cpio member %q: %v", header.Name, err)
		if content {
			x.lost = append(x.lost, fmt.Errorf("cpio member %q: %w", header.Name, err))
		}
	}
}

// extractCPIOMember writes one cpio member, reporting whether it carried
// content.
func extractCPIOMember(x *tarExtraction, cr *cpio.Reader, header *cpio.Header, links map[rpmLink]string) (bool, error) {
	// https://github.com/cavaliergopher/cpio/blob/main/header.go#L24
	const modeTypeMask = 0o170000
	fileType := header.Mode & modeTypeMask

	clean, changed := fileEntryName(header.Name)
	if fileType == cpio.TypeDir {
		clean, changed = entryName(header.Name)
	}
	if changed {
		x.logger.Warnf("extracting cpio member %q as %q", header.Name, clean)
	}

	switch fileType {
	case cpio.TypeDir:
		_, err := x.paths.dir(clean)
		return false, err
	case cpio.TypeSymlink:
		_, err := x.paths.symlink(clean, header.Linkname)
		// A new link can change where names beneath it lead.
		x.paths.er.close()
		return false, err
	case cpio.TypeReg:
		if header.Links > 1 {
			return true, extractCPIOLink(x, cr, header, clean, links)
		}
	default:
		// A member of any other type that carries data, as a member whose
		// mode names no type might, is written as a file.
		if header.Size == 0 {
			return false, nil
		}
	}
	return true, extractFileFromCPIO(x.ctx, cr, x.paths, clean, x.buf, x.budget)
}

// extractCPIOLink writes a member of a hard link set. newc writers store a
// set's content with its last member and leave the earlier members empty, so
// a member links to the earlier one and writes any content it carries through
// the link, reaching them all, but only while the earlier member is empty. A
// member whose set already has content, as when two unrelated members claim
// one inode, is written as a file of its own, so that neither content
// replaces the other.
func extractCPIOLink(x *tarExtraction, cr *cpio.Reader, header *cpio.Header, name string, links map[rpmLink]string) error {
	key := rpmLink{dev: header.DeviceID, inode: header.Inode}
	existing, ok := links[key]
	if !ok {
		out, assigned, err := x.paths.createFile(name)
		if err != nil {
			return err
		}
		defer out.Close()
		links[key] = assigned
		return copyCounted(x.ctx, out, cr, x.budget, x.buf, name)
	}

	fi, err := x.paths.er.root.Lstat(existing)
	if err != nil || (header.Size > 0 && fi.Size() > 0) {
		return extractFileFromCPIO(x.ctx, cr, x.paths, name, x.buf, x.budget)
	}
	assigned, err := x.paths.link(name, existing)
	x.paths.er.close()
	if err != nil {
		return err
	}
	if header.Size == 0 {
		return nil
	}
	// The set's files are empty, so the content goes through the link to
	// every member.
	out, err := x.paths.er.root.OpenFile(assigned, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		return fmt.Errorf("failed to open hard link %q: %w", filepath.Base(assigned), err)
	}
	defer out.Close()
	return copyCounted(x.ctx, out, cr, x.budget, x.buf, name)
}
