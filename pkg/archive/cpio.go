// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/cavaliergopher/cpio"
	"github.com/chainguard-dev/clog"
)

// cpioTrailingName is the file ExtractCPIO writes whatever follows the last
// cpio archive in a file to, beside the extracted members, so that it is
// scanned, and extracted when it holds an archive, rather than dropped. A
// Linux initramfs may carry such a segment: the kernel reads cpio archives
// back to back, each compressed on its own or not at all, as an uncompressed
// early microcode archive followed by a compressed one. When a member has
// the same name, the member keeps it and this file takes a sibling name. The
// .bin extension makes the scanner examine it whatever it holds.
const cpioTrailingName = "malcontent-cpio-trailing.bin"

// cpioHeaderSize is the length of a newc header before the member name: the
// six byte magic and thirteen fields of eight hexadecimal digits.
const cpioHeaderSize = 110

// cpioMagic is the start of the magic of every cpio ASCII format: newc
// (070701), newc with checksums (070702), and the old portable format
// (070707), which the cpio reader does not read.
var cpioMagic = []byte("07070")

// isNewcHeader reports whether b begins with a cpio header in the SVR4 newc
// format, with or without checksums: the magic, then thirteen fields of
// eight hexadecimal digits. Checking the fields as well as the magic keeps a
// text file that happens to begin with the digits from being taken for one.
func isNewcHeader(b []byte) bool {
	if len(b) < cpioHeaderSize || !bytes.HasPrefix(b, cpioMagic) || (b[5] != '1' && b[5] != '2') {
		return false
	}
	for _, c := range b[len(cpioMagic)+1 : cpioHeaderSize] {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

// ExtractCPIO extracts cpio archives in the SVR4 newc format, with or without
// checksums, such as a Linux initramfs once decompressed. Each member is
// written as a file of its own, so that it is scanned on its own. Several
// archives back to back are each extracted, and data that follows them is
// written to cpioTrailingName.
func ExtractCPIO(ctx context.Context, d, f string) (retErr error) {
	defer recoverExtractor(ctx, "cpio", f, &retErr)
	if ctx.Err() != nil {
		return ctx.Err()
	}

	logger := clog.FromContext(ctx).With("dir", d, "file", f)
	logger.Debug("extracting cpio")

	in, fi, err := openRegular(f)
	if err != nil {
		return fmt.Errorf("failed to open cpio file: %w", err)
	}
	defer in.Close()

	if fi.Size() == 0 {
		return nil
	}

	buf := extractPool.Get()
	defer extractPool.Put(buf)

	// One counter spans every member of every archive in the file.
	counter := newArchiveCounter(ctx, fi.Size())

	root, err := openRoot(d)
	if err != nil {
		return err
	}
	defer root.Close()
	x := newTarExtraction(ctx, root, counter, buf)
	defer x.close()

	err = extractCPIOArchives(x, bufferInput(io.NewSectionReader(in, 0, fi.Size())))
	return errors.Join(err, x.finish())
}

// extractCPIOArchives extracts the cpio archives r holds back to back, as the
// kernel reads an initramfs. The cpio reader reads exactly the bytes of each
// header and member from r, and stops just past the name of the trailer, so r
// is left where the archive ends, before the trailer's padding. The NUL bytes
// that pad an archive are skipped; another archive that follows is extracted
// in turn, and anything else is written to cpioTrailingName.
func extractCPIOArchives(x *tarExtraction, r *bufio.Reader) error {
	for {
		// The reader is never reused past a trailer: Next would discard the
		// padding of the member before it once more. Each archive gets its
		// own reader, and hard links do not span archives, as in the kernel.
		if err := extractCPIOEntries(x, cpio.NewReader(r)); err != nil {
			return err
		}
		err := skipNUL(r)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("failed to read past cpio trailer: %w", err)
		}
		// A short peek at the end of the input is no header, and is written
		// out with the rest.
		head, _ := r.Peek(cpioHeaderSize)
		if !isNewcHeader(head) {
			return writeCPIOTrailing(x, r)
		}
		// Each further archive costs an entry, so that a file of empty
		// archives back to back is bounded as a file of empty members is.
		if err := x.budget.Entry(); err != nil {
			return fmt.Errorf("cpio extraction aborted on a further archive: %w", err)
		}
	}
}

// skipNUL discards the NUL bytes at the start of r. It returns io.EOF when
// nothing else follows them.
func skipNUL(r *bufio.Reader) error {
	for {
		if _, err := r.Peek(1); err != nil {
			return err
		}
		b, _ := r.Peek(r.Buffered())
		n := 0
		for n < len(b) && b[n] == 0 {
			n++
		}
		if _, err := r.Discard(n); err != nil {
			return err
		}
		if n < len(b) {
			return nil
		}
	}
}

// writeCPIOTrailing writes the rest of r, which follows the last cpio archive
// and is no archive the cpio reader reads, to cpioTrailingName, charging the
// budget for it as for a member.
func writeCPIOTrailing(x *tarExtraction, r io.Reader) error {
	if err := x.budget.Entry(); err != nil {
		return fmt.Errorf("cpio extraction aborted on trailing data: %w", err)
	}
	out, assigned, err := x.paths.createFile(cpioTrailingName)
	if err != nil {
		return fmt.Errorf("failed to write data following the cpio archive: %w", err)
	}
	defer out.Close()
	x.logger.Infof("writing data that follows the cpio archive to %q", assigned)
	return copyCounted(x.ctx, out, r, x.budget, x.buf, assigned)
}
