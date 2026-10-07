// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"iter"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/malcontent/pkg/file"
	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/chainguard-dev/malcontent/pkg/programkind"
	zip "github.com/klauspost/compress/zip"
	"golang.org/x/sync/errgroup"
)

var zipMIME = map[string]struct{}{
	"application/jar":              {},
	"application/java-archive":     {},
	"application/x-wheel+zip":      {},
	"application/x-zip":            {},
	"application/x-zip-compressed": {},
	"application/zip":              {},
}

// defaultMaxArchiveBytes seeds ExtractZip's per-archive byte cap. It is a var
// (not a const) so tests can shrink the cap to a synthesizable bound; the
// production value is file.DefaultMaxArchiveBytes (32 GiB).
var defaultMaxArchiveBytes = file.DefaultMaxArchiveBytes

// caseInsensitiveFS reports whether the extraction filesystem may fold case,
// as macOS volumes do by default. There, entries such as META-INF/LICENSE and
// META-INF/license/ name the same path, so ExtractZip assigns sibling names
// to entries and directories whose path is already taken (see
// zipFoldedPaths). It is a var so tests can enable the handling on any
// platform.
var caseInsensitiveFS = runtime.GOOS == "darwin"

// maxCollisionNames bounds the sibling names tried for one entry.
const maxCollisionNames = 1024

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

// ExtractZip extracts zip-format archives (.ear, .jar, .war, .whl, .zip).
func ExtractZip(ctx context.Context, d string, f string) error {
	return extractZipWithKind(ctx, d, f, detectFileType(ctx, f))
}

// extractZipWithKind is ExtractZip with the archive's detected type reported by
// fileType, so that a caller which already detected it need not read the
// archive again.
func extractZipWithKind(ctx context.Context, d, f string, fileType func() *programkind.FileType) (err error) {
	defer recoverExtractor(ctx, "zip", f, &err)
	if ctx.Err() != nil {
		return ctx.Err()
	}

	logger := clog.FromContext(ctx).With("dir", d, "file", f)
	logger.Debug("extracting zip")

	fi, err := file.Stat(f)
	if err != nil {
		return fmt.Errorf("failed to stat file %s: %w", f, err)
	}
	if fi.Size() == 0 {
		return nil
	}

	var isZip bool
	if ft := fileType(); ft != nil {
		_, isZip = zipMIME[ft.MIME]
	}

	if !isZip {
		return fmt.Errorf("not a valid zip archive: %s", f)
	}

	zfh, err := file.Open(f)
	if err != nil {
		return fmt.Errorf("failed to open zip file %s: %w", f, err)
	}
	defer zfh.Close()
	zfi, err := zfh.Stat()
	if err != nil {
		return fmt.Errorf("failed to open zip file %s: %w", f, err)
	}
	read, err := zip.NewReader(zfh, zfi.Size())
	if err != nil {
		return fmt.Errorf("failed to open zip file %s: %w", f, err)
	}
	read.RegisterDecompressor(zip.Deflate, newZipInflater)

	root, err := openRoot(d)
	if err != nil {
		return err
	}
	defer root.Close()
	er := newEntryRoots(root)
	defer er.close()

	// folded stays nil on case-sensitive filesystems, where every entry is
	// written at the path it names.
	var folded *zipFoldedPaths
	if caseInsensitiveFS {
		folded = newZipFoldedPaths(root)
	}

	for _, zf := range read.File {
		if zf.Mode().IsDir() {
			clean := filepath.Clean(filepath.ToSlash(zf.Name))
			if strings.Contains(clean, "..") {
				logger.Warnf("skipping potentially unsafe directory path: %s", zf.Name)
				continue
			}

			target := filepath.Join(d, clean)
			if !er.validPath(target, d) {
				logger.Warnf("skipping directory path outside extraction directory: %s", target)
				continue
			}

			if folded != nil {
				if _, err := folded.dir(clean); err != nil {
					return fmt.Errorf("failed to create directory structure: %w", err)
				}
				continue
			}
			if err := root.MkdirAll(clean, 0o700); err != nil {
				return fmt.Errorf("failed to create directory structure: %w", err)
			}
		}
	}

	// Shared counter across all entries enforces a uniform byte and ratio
	// ceiling. InputBytes seeds the ratio denominator from the outer archive
	// size. Caps prefer ctx-attached Config values; absent/zero values fall
	// back to the package defaults so zero-config callers still receive a
	// finite cap.
	counter := newArchiveCounter(ctx, fi.Size())

	var entries, symlinks []*zip.File
	for _, zf := range read.File {
		switch {
		case zf.Mode().IsDir():
		case zf.Mode()&os.ModeSymlink != 0:
			// Symlinks are created one at a time after every other entry so
			// that no concurrent write can change what a link resolves to
			// while it is validated.
			symlinks = append(symlinks, zf)
		default:
			entries = append(entries, zf)
		}
	}

	// An extraction that fails is scanned as far as it got, so what it leaves
	// behind must not depend on timing. The entries that fit within the caps
	// together are extracted concurrently, and a failed entry does not stop
	// the others. The rest are extracted one at a time, smallest first, until
	// the caps stop them.
	fit, over := splitByCaps(entries, counter.Available())
	if err := extractEntries(ctx, fit, f, er, logger, counter, folded); err != nil {
		return fmt.Errorf("extraction failed: %w", err)
	}
	for _, zf := range over {
		if err := extractFile(ctx, zf, er, logger, counter, folded); err != nil {
			return fmt.Errorf("extraction failed: %w", err)
		}
	}

	for _, zf := range symlinks {
		if err := extractFile(ctx, zf, er, logger, counter, folded); err != nil {
			return fmt.Errorf("extraction failed: %w", err)
		}
	}

	if err := zipUnaccountedBytes(f, fi.Size()); err != nil {
		return fmt.Errorf("%w in %s: %w", ErrUnaccountedBytes, filepath.Base(f), err)
	}

	return nil
}

// splitByCaps divides entries into those that fit within budget bytes
// together and the rest, both smallest first, with ties in archive order. The
// zip reader returns no more of an entry than its declared size, so however
// the extraction of the entries that fit interleaves, they cannot exceed the
// caps.
func splitByCaps(entries []*zip.File, budget int64) (fit, over []*zip.File) {
	bySize := slices.Clone(entries)
	slices.SortStableFunc(bySize, func(a, b *zip.File) int {
		return cmp.Compare(a.UncompressedSize64, b.UncompressedSize64)
	})
	left := uint64(max(budget, 0))
	n := 0
	for ; n < len(bySize) && bySize[n].UncompressedSize64 <= left; n++ {
		left -= bySize[n].UncompressedSize64
	}
	return bySize[:n], bySize[n:]
}

// extractEntries extracts entries of the archive f concurrently. A failed
// entry does not stop the others; the error returned is that of the first
// failed entry in entries.
func extractEntries(ctx context.Context, entries []*zip.File, f string, er *entryRoots, logger *clog.Logger, counter *file.ArchiveCounter, folded *zipFoldedPaths) error {
	var g errgroup.Group
	g.SetLimit(EffectiveMaxConcurrency(runtime.GOMAXPROCS(0)))
	sem := extractionSemaphore()
	errs := make([]error, len(entries))
	for i, zf := range entries {
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
				return extractFile(ctx, zf, er, logger, counter, folded)
			}()
			return nil
		})
	}
	_ = g.Wait()
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

// extractFile writes one file or symlink entry beneath er's root. A nil
// folded writes the entry at the path it names; otherwise folded assigns the
// path.
func extractFile(ctx context.Context, zf *zip.File, er *entryRoots, logger *clog.Logger, counter *file.ArchiveCounter, folded *zipFoldedPaths) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	clean := filepath.Clean(filepath.ToSlash(zf.Name))
	if strings.Contains(clean, "..") {
		logger.Warnf("skipping potentially unsafe file path: %s", zf.Name)
		return nil
	}

	target := filepath.Join(er.root.Name(), clean)
	if !er.validPath(target, er.root.Name()) {
		logger.Warnf("skipping file path outside extraction directory: %s", target)
		return nil
	}

	if zf.Mode()&os.ModeSymlink != 0 {
		src, err := zf.Open()
		if err != nil {
			return fmt.Errorf("failed to open symlink entry: %w", err)
		}
		defer src.Close()

		const maxSymlinkTarget int64 = 4096
		linkTarget, err := io.ReadAll(io.LimitReader(src, maxSymlinkTarget))
		if err != nil {
			return fmt.Errorf("failed to read symlink target: %w", err)
		}

		name := clean
		if folded != nil {
			if name, err = folded.symlinkName(clean); err != nil {
				return fmt.Errorf("failed to create symlink: %w", err)
			}
		}

		// The link may replace an entry that other names led through.
		defer er.close()
		if err := handleSymlink(er.root, name, string(linkTarget)); err != nil {
			return fmt.Errorf("failed to create symlink: %w", err)
		}
		return nil
	}

	buf := extractPool.Get()
	defer extractPool.Put(buf)

	src, err := zf.Open()
	if err != nil {
		return fmt.Errorf("failed to open archived file: %w", err)
	}
	defer src.Close()

	var dst *os.File
	name := clean
	if folded != nil {
		dst, name, err = folded.createFile(clean)
	} else {
		dst, err = er.createFile(clean)
	}
	if err != nil {
		return err
	}
	defer dst.Close()
	if name != clean {
		logger.Debugf("writing %s as %s because the path is already taken", clean, name)
	}

	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		n, err := src.Read(buf)
		if n > 0 {
			if capErr := counter.Add(n); capErr != nil {
				return fmt.Errorf("zip extraction aborted on %s: %w", target, capErr)
			}

			if _, writeErr := dst.Write(buf[:n]); writeErr != nil {
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

// zipFoldedPaths assigns output paths beneath root on a filesystem that folds
// case, where differently cased entry names can claim the same path. A file
// or symlink whose path is taken gets a sibling name. A directory whose path
// holds anything other than a directory gets a new sibling directory, which
// every entry beneath it then shares. All operations go through root.
type zipFoldedPaths struct {
	root *os.Root
	mu   sync.Mutex
	// dirs maps each directory, as entries name it and folded to lower case,
	// to the directory created for it. Guarded by mu.
	dirs map[string]string
}

func newZipFoldedPaths(root *os.Root) *zipFoldedPaths {
	return &zipFoldedPaths{root: root, dirs: map[string]string{}}
}

// dir returns the directory created for name, a cleaned relative path,
// creating it and any missing parents. Like root, it rejects absolute names,
// which also guarantees that walking up the parents ends at ".".
func (p *zipFoldedPaths) dir(name string) (string, error) {
	if name == "." {
		return name, nil
	}
	if !filepath.IsLocal(name) {
		return "", fmt.Errorf("failed to create directory: path outside extraction directory: %s", name)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.dirLocked(name)
}

func (p *zipFoldedPaths) dirLocked(name string) (string, error) {
	if name == "." {
		return name, nil
	}
	key := strings.ToLower(name)
	if got, ok := p.dirs[key]; ok {
		return got, nil
	}
	parent, err := p.dirLocked(filepath.Dir(name))
	if err != nil {
		return "", err
	}
	want := filepath.Join(parent, filepath.Base(name))
	for candidate := range zipCollisionNames(want) {
		err := p.root.Mkdir(candidate, 0o700)
		if errors.Is(err, fs.ErrExist) {
			// Only the wanted name may be reused, and only when it is a real
			// directory; a sibling must be new so renamed contents stay apart.
			if candidate != want || !p.isDir(candidate) {
				continue
			}
			err = nil
		}
		if err != nil {
			return "", fmt.Errorf("failed to create directory: %w", err)
		}
		p.dirs[key] = candidate
		return candidate, nil
	}
	return "", fmt.Errorf("failed to create directory: no unused name derived from %s", want)
}

func (p *zipFoldedPaths) isDir(name string) bool {
	fi, err := p.root.Lstat(name)
	return err == nil && fi.IsDir()
}

// createFile creates the file for name, a cleaned relative path, in the
// directory created for its parent, under the first free name derived from
// it, and returns the file and the name used. Exclusive creation keeps
// concurrent workers from sharing a file and never follows a symlink.
func (p *zipFoldedPaths) createFile(name string) (*os.File, string, error) {
	parent, err := p.dir(filepath.Dir(name))
	if err != nil {
		return nil, "", err
	}
	for candidate := range zipCollisionNames(filepath.Join(parent, filepath.Base(name))) {
		out, err := p.root.OpenFile(candidate, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err == nil {
			return out, candidate, nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return nil, "", fmt.Errorf("failed to create file: %w", err)
		}
	}
	return nil, "", fmt.Errorf("failed to create file: no unused name derived from %s", name)
}

// symlinkName returns the first free name derived from name, a cleaned
// relative path, in the directory created for its parent. ExtractZip creates
// symlinks one at a time after every other entry, so the name stays free
// until the link is made.
func (p *zipFoldedPaths) symlinkName(name string) (string, error) {
	parent, err := p.dir(filepath.Dir(name))
	if err != nil {
		return "", err
	}
	for candidate := range zipCollisionNames(filepath.Join(parent, filepath.Base(name))) {
		_, err := p.root.Lstat(candidate)
		if errors.Is(err, fs.ErrNotExist) {
			return candidate, nil
		}
		if err != nil {
			return "", fmt.Errorf("failed to inspect %s: %w", candidate, err)
		}
	}
	return "", fmt.Errorf("no unused name derived from %s", name)
}

// zipCollisionNames yields name and then up to maxCollisionNames sibling names
// derived from it. Each suffix goes before the extension programkind reports,
// so a renamed nested archive is still recognized by its name.
func zipCollisionNames(name string) iter.Seq[string] {
	return func(yield func(string) bool) {
		if !yield(name) {
			return
		}
		dir, base := filepath.Split(name)
		ext := programkind.GetExt(base)
		if len(ext) >= len(base) || !strings.HasSuffix(base, ext) {
			ext = ""
		}
		stem := strings.TrimSuffix(base, ext)
		for i := range maxCollisionNames {
			if !yield(dir + stem + "_" + strconv.Itoa(i+1) + ext) {
				return
			}
		}
	}
}
