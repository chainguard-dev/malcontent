package archive

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/malcontent/pkg/pool"
	"github.com/chainguard-dev/malcontent/pkg/programkind"
	bzip2 "github.com/cosnicolaou/pbzip2"
	gzip "github.com/klauspost/pgzip"
	"github.com/ulikunitz/xz"
)

var initTarPool sync.Once

// extractTar extracts .apk and .tar* archives.
//
//nolint:cyclop // ignore complexity of 42
func ExtractTar(ctx context.Context, d string, f string) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	logger := clog.FromContext(ctx).With("dir", d, "file", f)
	logger.Debug("extracting tar")

	// Initialize the tar sync pool here since OCI preparation bypasses the main extraction method
	initTarPool.Do(func() {
		tarPool = pool.NewBufferPool(runtime.GOMAXPROCS(0))
	})

	// Check if the file is valid
	fi, err := os.Stat(f)
	if err != nil {
		return fmt.Errorf("failed to stat file: %w", err)
	}

	if fi.Size() == 0 {
		return nil
	}

	buf := tarPool.Get(extractBuffer) //nolint:nilaway // the buffer pool is created in archive.go

	filename := filepath.Base(f)
	tf, err := os.Open(f)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}

	defer func() {
		tarPool.Put(buf)
		tf.Close()
	}()

	isTGZ := strings.Contains(f, ".tar.gz") || strings.Contains(f, ".tgz")
	var isGzip bool
	if ft, err := programkind.File(f); err == nil && ft != nil {
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
		uncompressed := strings.Trim(filepath.Base(f), ".xz")
		target := filepath.Join(d, filepath.Base(filepath.Dir(f)), uncompressed)
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return fmt.Errorf("failed to create directory for file: %w", err)
		}

		out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			return fmt.Errorf("failed to create file: %w", err)
		}
		defer out.Close()

		var written int64
		for {
			if written > 0 && written%extractBuffer == 0 && ctx.Err() != nil {
				return ctx.Err()
			}

			n, err := xzStream.Read(buf)
			if n > 0 {
				written += int64(n)
				if written > maxBytes {
					return fmt.Errorf("file exceeds maximum allowed size (%d bytes): %s", maxBytes, target)
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
		uncompressed := strings.Trim(filepath.Base(f), programkind.GetExt(filename))
		target := filepath.Join(d, filepath.Base(filepath.Dir(f)), uncompressed)
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return fmt.Errorf("failed to create directory for file: %w", err)
		}
		out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			return fmt.Errorf("failed to create file: %w", err)
		}
		var written int64
		for {
			if written > 0 && written%extractBuffer == 0 && ctx.Err() != nil {
				return ctx.Err()
			}

			n, err := br.Read(buf)
			if n > 0 {
				written += int64(n)
				if written > maxBytes {
					return fmt.Errorf("file exceeds maximum allowed size (%d bytes): %s", maxBytes, target)
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

		switch header.Typeflag {
		case tar.TypeDir:
			if err := handleDirectory(target); err != nil {
				return fmt.Errorf("failed to extract directory: %w", err)
			}
		case tar.TypeReg:
			if err := handleFile(target, tr); err != nil {
				return fmt.Errorf("failed to extract file: %w", err)
			}
		case tar.TypeSymlink:
			if err := handleSymlink(d, header.Linkname, target); err != nil {
				return fmt.Errorf("failed to create symlink: %w", err)
			}
		}
	}
	return nil
}
