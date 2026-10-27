// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"bytes"
	"cmp"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"slices"
	"strings"

	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/malcontent/pkg/file"
	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	zip "github.com/klauspost/compress/zip"
	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz/lzma"
	"golang.org/x/sync/errgroup"
)

// Compression methods beyond store and deflate that zip writers such as
// 7-Zip, WinZip, and Python's zipfile use.
const (
	zipMethodBzip2 uint16 = 12
	zipMethodLZMA  uint16 = 14
	zipMethodXZ    uint16 = 95
)

// defaultMaxArchiveBytes seeds the byte cap. It is a var (not a const) so
// tests can shrink the cap to a synthesizable bound; the production value is
// file.DefaultMaxArchiveBytes (32 GiB).
var defaultMaxArchiveBytes = file.DefaultMaxArchiveBytes

// resolveArchiveCaps returns the effective byte and ratio caps for an archive
// extraction. Caller-supplied Config values take precedence over defaults; a
// zero/unset value falls back to file.DefaultMaxArchiveBytes /
// file.DefaultMaxArchiveRatio.
func resolveArchiveCaps(ctx context.Context) (maxBytes int64, maxRatio float64) {
	maxBytes = defaultMaxArchiveBytes
	maxRatio = file.DefaultMaxArchiveRatio
	if cfg := malcontent.ConfigFromContext(ctx); cfg != nil {
		if cfg.MaxArchiveBytes > 0 {
			maxBytes = cfg.MaxArchiveBytes
		}
		if cfg.MaxArchiveRatio > 0 {
			maxRatio = cfg.MaxArchiveRatio
		}
	}
	return maxBytes, maxRatio
}

// zipEntry is a file entry of a zip archive and the path reserved for it.
type zipEntry struct {
	zf   *zip.File
	name string // the cleaned name
	path string
}

// zipExtraction writes the entries of one zip archive beneath one root.
type zipExtraction struct {
	ctx    context.Context
	logger *clog.Logger
	src    *os.File // the archive
	paths  *entryPaths
	budget *budget
}

// ExtractZip extracts zip-format archives (.ear, .jar, .war, .whl, .zip, and
// any file whose content is a zip, including one with data such as a launcher
// script prepended). Every entry is written as a file, under a cleaned name
// when its own would leave the extraction directory, and under a sibling name
// when another entry took its path, as on a filesystem that folds case. An
// entry is a directory only when its name ends in "/"; a symlink entry is
// written as a file holding its bytes, as Python's zipfile writes it. Entries
// the central directory omits are extracted from their local headers, and
// archive and entry comments are written to the metadata sidecar.
func ExtractZip(ctx context.Context, d string, f string) (err error) {
	defer recoverExtractor(ctx, "zip", f, &err)
	if ctx.Err() != nil {
		return ctx.Err()
	}

	logger := clog.FromContext(ctx).With("dir", d, "file", f)
	logger.Debug("extracting zip")

	zfh, fi, err := openRegular(f)
	if err != nil {
		return fmt.Errorf("failed to open zip file %q: %w", f, err)
	}
	defer zfh.Close()
	if fi.Size() == 0 {
		return nil
	}

	read, err := zip.NewReader(zfh, fi.Size())
	if err != nil {
		return fmt.Errorf("not a valid zip archive: %q: %w", f, err)
	}
	read.RegisterDecompressor(zip.Deflate, newZipInflater)
	read.RegisterDecompressor(zipMethodBzip2, func(r io.Reader) io.ReadCloser { return newBzip2Reader(ctx, r) })
	read.RegisterDecompressor(zstd.ZipMethodWinZip, zstd.ZipDecompressor(zstdOptions()...))
	read.RegisterDecompressor(zstd.ZipMethodPKWare, zstd.ZipDecompressor(zstdOptions()...))

	root, err := openRoot(d)
	if err != nil {
		return err
	}
	defer root.Close()
	er := newEntryRoots(root)
	defer er.close()

	x := &zipExtraction{
		ctx:    ctx,
		logger: logger,
		src:    zfh,
		paths:  newEntryPaths(er),
		// Shared counter across all entries enforces a uniform ratio ceiling;
		// InputBytes seeds the ratio denominator from the archive size.
		budget: newArchiveCounter(ctx, fi.Size()),
	}

	// Directories are created and every file's path reserved in archive
	// order, so that the paths entries are written to, sibling names among
	// them, are the same however the concurrent writes interleave.
	entries, err := x.plan(read.File)
	if err != nil {
		return err
	}

	// An extraction that fails is scanned as far as it got, so what it leaves
	// behind must not depend on timing. The entries that fit within the caps
	// together are extracted concurrently, and a failed entry does not stop
	// the others. The rest are extracted one at a time, smallest first, until
	// the caps stop them.
	fit, over := splitByCaps(entries, x.budget.Available())
	errs := extractEntries(ctx, fit, f, x)
	for _, e := range over {
		err := x.extractFile(e)
		errs = append(errs, err)
		if err != nil && fatalExtractionError(ctx, err) {
			break
		}
	}
	var lost []error
	for _, err := range errs {
		switch {
		case err == nil:
		case fatalExtractionError(ctx, err):
			return fmt.Errorf("extraction failed: %w", err)
		default:
			lost = append(lost, err)
		}
	}

	var sc sidecar
	sc.add("zip comment", []byte(read.Comment))
	for _, zf := range read.File {
		sc.add(fmt.Sprintf("zip entry %q comment", zf.Name), []byte(zf.Comment))
	}

	auditErr := x.auditRegions(fi.Size())
	results := []error{auditErr, sc.writeIn(x.paths, ".", x.budget), sc.err()}
	if len(lost) > 0 {
		results = append(results, fmt.Errorf("%w: extraction failed: %w", ErrUnaccountedBytes, errors.Join(lost...)))
	}
	return errors.Join(results...)
}

// plan creates the directories that entries name and reserves the path of
// every file entry, in archive order, charging each entry's fixed cost.
func (x *zipExtraction) plan(files []*zip.File) ([]zipEntry, error) {
	var entries []zipEntry
	for _, zf := range files {
		if err := x.budget.Entry(); err != nil {
			return nil, fmt.Errorf("zip extraction aborted on %q: %w", zf.Name, err)
		}
		if strings.HasSuffix(zf.Name, "/") && zf.UncompressedSize64 == 0 {
			clean, changed := entryName(zf.Name)
			if changed {
				x.logger.Warnf("extracting zip directory %q as %q", zf.Name, clean)
			}
			if _, err := x.paths.dir(clean); err != nil {
				x.logger.Warnf("skipping zip directory %q: %v", zf.Name, err)
			}
			continue
		}
		// A directory entry carrying data, or any other entry, is written as
		// a file, so that its content is scanned.
		clean, changed := fileEntryName(strings.TrimSuffix(zf.Name, "/"))
		path, err := x.paths.reserve(clean, kindFile)
		if err != nil {
			return nil, fmt.Errorf("failed to reserve a path for %q: %w", zf.Name, err)
		}
		switch {
		case path != clean:
			x.logger.Warnf("extracting zip entry %q as %q because the path is already taken", zf.Name, path)
		case changed:
			x.logger.Warnf("extracting zip entry %q as %q", zf.Name, path)
		}
		entries = append(entries, zipEntry{zf: zf, name: clean, path: path})
	}
	return entries, nil
}

// splitByCaps divides entries into those that fit within budget bytes
// together and the rest, both smallest first, with ties in archive order. The
// zip reader returns no more of an entry than its declared size, so however
// the extraction of the entries that fit interleaves, they cannot exceed the
// caps.
func splitByCaps(entries []zipEntry, budget int64) (fit, over []zipEntry) {
	bySize := slices.Clone(entries)
	slices.SortStableFunc(bySize, func(a, b zipEntry) int {
		return cmp.Compare(a.zf.UncompressedSize64, b.zf.UncompressedSize64)
	})
	left := uint64(max(budget, 0))
	n := 0
	for ; n < len(bySize) && bySize[n].zf.UncompressedSize64 <= left; n++ {
		left -= bySize[n].zf.UncompressedSize64
	}
	return bySize[:n], bySize[n:]
}

// extractEntries extracts entries of the archive f concurrently and returns
// each entry's error, in the order of entries. A failed entry does not stop
// the others.
func extractEntries(ctx context.Context, entries []zipEntry, f string, x *zipExtraction) []error {
	var g errgroup.Group
	g.SetLimit(EffectiveMaxConcurrency(runtime.GOMAXPROCS(0)))
	sem := extractionSemaphore()
	errs := make([]error, len(entries))
	for i, e := range entries {
		g.Go(func() error {
			errs[i] = func() (err error) {
				defer recoverExtractor(ctx, "zip", f, &err)
				if hook := workerPanicHook; hook != nil {
					hook(f)
				}
				if err := sem.Acquire(ctx, 1); err != nil {
					return err
				}
				defer sem.Release(1)
				return x.extractFile(e)
			}()
			return nil
		})
	}
	_ = g.Wait()
	return errs
}

// extractFile writes one file entry to the path reserved for it.
func (x *zipExtraction) extractFile(e zipEntry) error {
	if err := x.ctx.Err(); err != nil {
		return err
	}

	src, err := x.openEntry(e.zf)
	if err != nil {
		return fmt.Errorf("failed to open archived file %q: %w", e.zf.Name, err)
	}
	defer src.Close()

	dst, _, err := x.paths.createAt(e.name, e.path)
	if err != nil {
		return fmt.Errorf("zip entry %q: %w", e.zf.Name, err)
	}
	defer dst.Close()

	buf := extractPool.Get()
	defer extractPool.Put(buf)
	if err := copyCounted(x.ctx, dst, src, x.budget, buf, e.path); err != nil {
		return fmt.Errorf("zip entry %q: %w", e.zf.Name, err)
	}
	return nil
}

// openEntry returns the decompressed content of zf. LZMA and xz entries are
// decoded from their raw bytes after their declared dictionary is checked;
// every other method is decoded by the zip reader.
func (x *zipExtraction) openEntry(zf *zip.File) (io.ReadCloser, error) {
	switch zf.Method {
	case zipMethodLZMA:
		raw, err := zf.OpenRaw()
		if err != nil {
			return nil, err
		}
		r, err := newZipLZMAReader(raw, zf.UncompressedSize64)
		if err != nil {
			return nil, err
		}
		return io.NopCloser(io.LimitReader(r, clampInt64(zf.UncompressedSize64))), nil
	case zipMethodXZ:
		offset, err := zf.DataOffset()
		if err != nil {
			return nil, err
		}
		size := clampInt64(zf.CompressedSize64)
		r, err := newXZReader(io.NewSectionReader(x.src, offset, size), size)
		if err != nil {
			return nil, err
		}
		return io.NopCloser(io.LimitReader(r, clampInt64(zf.UncompressedSize64))), nil
	default:
		return zf.Open()
	}
}

// newZipLZMAReader returns a decoder of the LZMA data of a zip entry: a
// version, a properties size, and the properties, then the stream. It checks
// the declared dictionary and hands the decoder the classic header it
// expects, holding the entry's uncompressed size.
func newZipLZMAReader(raw io.Reader, size uint64) (io.Reader, error) {
	var hdr [9]byte
	if _, err := io.ReadFull(raw, hdr[:]); err != nil {
		return nil, fmt.Errorf("lzma header: %w", err)
	}
	if binary.LittleEndian.Uint16(hdr[2:4]) != 5 {
		return nil, errors.New("lzma header: unexpected properties size")
	}
	if err := checkLZMADict(binary.LittleEndian.Uint32(hdr[5:9])); err != nil {
		return nil, err
	}
	classic := make([]byte, 13)
	copy(classic, hdr[4:9])
	binary.LittleEndian.PutUint64(classic[5:], size)
	return lzma.NewReader(io.MultiReader(bytes.NewReader(classic), raw))
}
