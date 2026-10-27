// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/malcontent/pkg/file"
	"golang.org/x/sync/semaphore"
)

// tarExtraction writes the entries of one or more tar streams beneath one
// root. An entry that cannot be written as it is named is written under a
// cleaned or sibling name; one that cannot be written at all is logged and
// skipped, and, when it carried content, reported once extraction ends, so
// that the archive is retained and scanned as it is. Only cancellation and
// the byte and ratio caps stop an extraction early.
type tarExtraction struct {
	ctx    context.Context
	logger *clog.Logger
	paths  *entryPaths
	budget *budget
	sem    *semaphore.Weighted
	buf    []byte
	sc     sidecar
	// lost holds the content-bearing entries that could not be written.
	lost []error
}

func newTarExtraction(ctx context.Context, root *os.Root, b *budget, buf []byte) *tarExtraction {
	return &tarExtraction{
		ctx:    ctx,
		logger: clog.FromContext(ctx),
		paths:  newEntryPaths(newEntryRoots(root)),
		budget: b,
		sem:    extractionSemaphore(),
		buf:    buf,
	}
}

// close closes the directory roots the extraction kept open.
func (x *tarExtraction) close() {
	x.paths.er.close()
}

// extract writes the entries of the tar stream read from stream beneath
// prefix, a directory as entries name it. archiveName names the archive in
// errors. A header that does not parse is skipped, and extraction resumes at
// the next block that holds a valid header, as tar(1) does.
func (x *tarExtraction) extract(stream io.Reader, prefix, archiveName string) error {
	tail := &tailReader{r: stream}
	// The auditor observes exactly the bytes the tar reader consumes, so it can
	// account for the regions archive/tar discards without re-reading the file.
	// Wrapping in a TeeReader also hides any underlying io.Seeker, which forces
	// archive/tar to read over skipped entry data and padding rather than seek
	// past it, so those bytes reach the auditor too.
	auditor := newTarAuditor()
	tr := tar.NewReader(io.TeeReader(tail, auditor))
	for {
		if err := x.ctx.Err(); err != nil {
			return err
		}
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if errors.Is(err, tar.ErrHeader) {
			next, skipped, rerr := resyncTar(tail, x.budget)
			x.logger.Warnf("skipped %d bytes of malformed tar data in %q", skipped, archiveName)
			auditor.fail(fmt.Sprintf("skipped %d bytes of malformed tar data", skipped))
			if rerr != nil {
				if fatalExtractionError(x.ctx, rerr) {
					return rerr
				}
				break
			}
			tr = tar.NewReader(next)
			continue
		}
		if err != nil {
			// A stream that ends inside a header block is no tar, or a
			// truncated one, and is never treated as a clean end.
			return fmt.Errorf("failed to read tar header in %q: %w", archiveName, err)
		}
		if err := x.entry(tr, header, prefix); err != nil {
			return err
		}
	}

	// archive/tar stops at the end-of-archive marker, so bytes appended past it
	// are never read. Drain them through the auditor: a payload hidden there
	// would otherwise be discarded along with the archive.
	if err := auditTarTrailer(tail, auditor, x.buf); err != nil {
		return fmt.Errorf("%w in %q: %w", ErrUnaccountedBytes, archiveName, err)
	}
	if err := auditor.err(); err != nil {
		return fmt.Errorf("%w in %q: %w", ErrUnaccountedBytes, archiveName, err)
	}
	return nil
}

// entry writes the entry header describes, reading any content from tr. It
// returns only the errors that stop the extraction.
func (x *tarExtraction) entry(tr *tar.Reader, header *tar.Header, prefix string) error {
	if comment, ok := header.PAXRecords["comment"]; ok {
		x.sc.add(fmt.Sprintf("tar entry %q comment", header.Name), []byte(comment))
	}
	if header.Typeflag == tar.TypeXGlobalHeader {
		return nil
	}
	if err := x.budget.Entry(); err != nil {
		return fmt.Errorf("tar extraction aborted on %q: %w", header.Name, err)
	}

	clean, changed := fileEntryName(header.Name)
	if header.Typeflag == tar.TypeDir {
		clean, changed = entryName(header.Name)
	}
	name := filepath.Join(prefix, clean)
	if changed {
		x.logger.Warnf("extracting tar entry %q as %q", header.Name, name)
	}

	if err := x.sem.Acquire(x.ctx, 1); err != nil {
		return err
	}
	defer x.sem.Release(1)

	var err error
	content := false
	switch header.Typeflag {
	case tar.TypeDir:
		_, err = x.paths.dir(name)
	case tar.TypeReg:
		content = true
		err = handleFile(x.paths, name, tr, x.budget)
	case tar.TypeSymlink:
		_, err = x.paths.symlink(name, header.Linkname)
		// A new link can change where names beneath it lead.
		x.paths.er.close()
	case tar.TypeLink:
		target, _ := fileEntryName(header.Linkname)
		_, err = x.paths.link(name, x.paths.lookup(filepath.Join(prefix, target)))
		x.paths.er.close()
	default:
		// Entries carrying data under a typeflag this switch does not name
		// (tar.TypeCont and unrecognized flags among them) would otherwise be
		// skipped, leaving their content out of the scan corpus.
		if header.Size > 0 && !isTarHeaderOnlyType(header.Typeflag) {
			content = true
			err = handleFile(x.paths, name, tr, x.budget)
		}
	}
	if err == nil {
		return nil
	}
	if fatalExtractionError(x.ctx, err) {
		return err
	}
	x.logger.Warnf("skipping tar entry %q: %v", header.Name, err)
	if content {
		x.lost = append(x.lost, fmt.Errorf("tar entry %q: %w", header.Name, err))
	}
	return nil
}

// finish writes the metadata sidecar into dir, a directory as entries name
// it, and reports the content that could not be extracted.
func (x *tarExtraction) finish(dir string) error {
	errs := []error{x.sc.writeIn(x.paths, dir, x.budget), x.sc.err()}
	if len(x.lost) > 0 {
		errs = append(errs, fmt.Errorf("%w: %w", ErrUnaccountedBytes, errors.Join(x.lost...)))
	}
	return errors.Join(errs...)
}

// fatalExtractionError reports whether err stops an extraction rather than
// one entry: cancellation and the byte and ratio caps.
func fatalExtractionError(ctx context.Context, err error) bool {
	return ctx.Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, file.ErrArchiveBytesCap) || errors.Is(err, file.ErrArchiveRatioCap)
}

// tailReader remembers the last block it read, so that a header archive/tar
// rejected can be examined again.
type tailReader struct {
	r   io.Reader
	buf [tarBlockSize]byte
	n   int
	// total counts the bytes read; resumedAt is the count at the block
	// extraction last resumed from, which is never resumed from again.
	total, resumedAt int64
}

func (t *tailReader) Read(p []byte) (int, error) {
	n, err := t.r.Read(p)
	t.remember(p[:n])
	t.total += int64(n)
	return n, err
}

func (t *tailReader) remember(p []byte) {
	if len(p) >= tarBlockSize {
		t.n = copy(t.buf[:], p[len(p)-tarBlockSize:])
		return
	}
	keep := min(t.n, tarBlockSize-len(p))
	copy(t.buf[:], t.buf[t.n-keep:t.n])
	copy(t.buf[keep:], p)
	t.n = keep + len(p)
}

// resyncTar finds where a tar stream continues after a header archive/tar
// rejected: the block it last read, when that holds a valid header, as after
// a lone zero block, or the next block read from t that does. It returns the
// stream from that block on and how many bytes it skipped, each charged to b.
func resyncTar(t *tailReader, b *budget) (io.Reader, int64, error) {
	// A block archive/tar rejects even though its checksum matches is never
	// resumed from twice, so a stream of such blocks still ends.
	if t.n == tarBlockSize && t.total != t.resumedAt && validTarHeader(t.buf[:]) {
		t.resumedAt = t.total
		return io.MultiReader(bytes.NewReader(bytes.Clone(t.buf[:])), t), 0, nil
	}
	skipped := int64(t.n)
	blk := make([]byte, tarBlockSize)
	for {
		if _, err := io.ReadFull(t, blk); err != nil {
			return nil, skipped, err
		}
		if validTarHeader(blk) {
			t.resumedAt = t.total
			return io.MultiReader(bytes.NewReader(blk), t), skipped, nil
		}
		if err := b.Add(tarBlockSize); err != nil {
			return nil, skipped, err
		}
		skipped += tarBlockSize
	}
}

// validTarHeader reports whether blk, one block, holds a tar header whose
// checksum matches, computed as archive/tar computes it.
func validTarHeader(blk []byte) bool {
	if len(blk) != tarBlockSize || isZeroBlock(blk) {
		return false
	}
	want, ok := parseTarSize(blk[148:156])
	if !ok {
		return false
	}
	var unsigned, signed int64
	for i, c := range blk {
		if i >= 148 && i < 156 {
			c = ' '
		}
		unsigned += int64(c)
		signed += int64(int8(c))
	}
	return want == unsigned || want == signed
}
