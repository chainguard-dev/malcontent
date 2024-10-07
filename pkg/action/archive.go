package action

import (
	"archive/tar"
	"archive/zip"
	"compress/bzip2"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/chainguard-dev/clog"
	"github.com/ulikunitz/xz"
)

const maxBytes = 1 << 29 // 512MB

// extractTar extracts .apk and .tar* archives.
func extractTar(ctx context.Context, d string, f string) error {
	logger := clog.FromContext(ctx).With("dir", d, "file", f)
	logger.Info("extracting tar")

	// Check if the file is valid
	_, err := os.Stat(f)
	if err != nil {
		return fmt.Errorf("failed to stat file: %w", err)
	}

	filename := filepath.Base(f)
	tf, err := os.Open(f)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer tf.Close()
	// Set offset to the file origin regardless of type
	_, err = tf.Seek(0, io.SeekStart)
	if err != nil {
		return fmt.Errorf("failed to seek to start: %w", err)
	}

	var tr *tar.Reader

	switch {
	case strings.Contains(f, ".apk") || strings.Contains(f, ".tar.gz") || strings.Contains(f, ".tgz"):
		gzStream, err := gzip.NewReader(tf)
		if err != nil {
			return fmt.Errorf("failed to create gzip reader: %w", err)
		}
		defer gzStream.Close()
		tr = tar.NewReader(gzStream)
	case strings.Contains(filename, ".xz"):
		xzStream, err := xz.NewReader(tf)
		if err != nil {
			return fmt.Errorf("failed to create xz reader: %w", err)
		}
		tr = tar.NewReader(xzStream)
	case strings.Contains(filename, ".bz2") || strings.Contains(filename, ".bzip2"):
		br := bzip2.NewReader(tf)
		tr = tar.NewReader(br)
	default:
		if err != nil {
			return fmt.Errorf("failed to seek to start: %w", err)
		}
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
		if filepath.IsAbs(clean) || strings.HasPrefix(clean, "..") {
			return fmt.Errorf("invalid file path: %s", header.Name)
		}
		target := filepath.Join(d, clean)
		if header.FileInfo().IsDir() {
			// #nosec G115
			if err := os.MkdirAll(target, os.FileMode(header.Mode)); err != nil {
				return fmt.Errorf("failed to create directory: %w", err)
			}
			continue
		}

		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return fmt.Errorf("failed to create directory for file: %w", err)
		}

		// #nosec G115
		f, err := os.OpenFile(target, os.O_RDWR|os.O_CREATE|os.O_TRUNC, os.FileMode(header.Mode))
		if err != nil {
			return fmt.Errorf("failed to create file: %w", err)
		}

		if _, err := io.Copy(f, io.LimitReader(tr, maxBytes)); err != nil {
			f.Close()
			return fmt.Errorf("failed to copy file: %w", err)
		}

		if err := f.Close(); err != nil {
			return fmt.Errorf("failed to close file: %w", err)
		}
	}
	return nil
}

// extractGzip extracts .gz archives.
func extractGzip(ctx context.Context, d string, f string) error {
	logger := clog.FromContext(ctx).With("dir", d, "file", f)
	logger.Info("extracting gzip")

	// Check if the file is valid
	_, err := os.Stat(f)
	if err != nil {
		return fmt.Errorf("failed to stat file: %w", err)
	}

	gf, err := os.Open(f)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer gf.Close()

	gr, err := gzip.NewReader(gf)
	if err != nil {
		return fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gr.Close()

	base := filepath.Base(f)
	target := filepath.Join(d, base[:len(base)-len(filepath.Ext(base))])

	ef, err := os.Create(target)
	if err != nil {
		return fmt.Errorf("failed to create extracted file: %w", err)
	}
	defer ef.Close()

	if _, err := io.Copy(ef, io.LimitReader(gr, maxBytes)); err != nil {
		return fmt.Errorf("failed to copy file: %w", err)
	}

	return nil
}

// extractZip extracts .jar and .zip archives.
func extractZip(ctx context.Context, d string, f string) error {
	logger := clog.FromContext(ctx).With("dir", d, "file", f)
	logger.Info("extracting zip")

	// Check if the file is valid
	_, err := os.Stat(f)
	if err != nil {
		return fmt.Errorf("failed to stat file %s: %w", f, err)
	}

	read, err := zip.OpenReader(f)
	if err != nil {
		return fmt.Errorf("failed to open zip file %s: %w", f, err)
	}
	defer read.Close()

	for _, file := range read.File {
		name := filepath.Join(d, filepath.Clean(filepath.ToSlash(file.Name)))

		// Check if a directory with the same name exists
		if info, err := os.Stat(name); err == nil && info.IsDir() {
			continue
		}

		if file.Mode().IsDir() {
			mode := file.Mode() | 0o755
			err := os.MkdirAll(name, mode)
			if err != nil {
				return fmt.Errorf("failed to create directory: %w", err)
			}
			continue
		}

		open, err := file.Open()
		if err != nil {
			return fmt.Errorf("failed to open file in zip: %w", err)
		}

		err = os.MkdirAll(filepath.Dir(name), 0o755)
		if err != nil {
			open.Close()
			return fmt.Errorf("failed to create directory: %w", err)
		}

		mode := file.Mode() | 0o200
		create, err := os.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_TRUNC, mode)
		if err != nil {
			open.Close()
			return fmt.Errorf("failed to create file: %w", err)
		}

		if _, err = io.Copy(create, io.LimitReader(open, maxBytes)); err != nil {
			open.Close()
			create.Close()
			return fmt.Errorf("failed to copy file: %w", err)
		}

		open.Close()
		create.Close()
	}
	return nil
}

func extractNestedArchive(
	ctx context.Context,
	d string,
	f string,
	extracted *sync.Map,
) error {
	isArchive := false
	ext := getExt(f)
	if _, ok := archiveMap[ext]; ok {
		isArchive = true
	}
	//nolint:nestif // ignore complexity of 8
	if isArchive {
		// Ensure the file was extracted and exists
		fullPath := filepath.Join(d, f)
		if _, err := os.Stat(fullPath); os.IsNotExist(err) {
			return fmt.Errorf("file does not exist: %w", err)
		}
		extract := extractionMethod(ext)
		if extract == nil {
			return fmt.Errorf("unsupported archive type: %s", ext)
		}

		err := extract(ctx, d, fullPath)
		if err != nil {
			return fmt.Errorf("extract nested archive: %w", err)
		}
		// Mark the file as extracted
		extracted.Store(f, true)

		// Remove the nested archive file
		// This is done to prevent the file from being scanned
		if err := os.Remove(fullPath); err != nil {
			return fmt.Errorf("failed to remove file: %w", err)
		}

		// Check if there are any newly extracted files that are also archives
		files, err := os.ReadDir(d)
		if err != nil {
			return fmt.Errorf("failed to read directory after extraction: %w", err)
		}
		for _, file := range files {
			relPath := filepath.Join(d, file.Name())
			if _, isExtracted := extracted.Load(relPath); !isExtracted {
				if err := extractNestedArchive(ctx, d, file.Name(), extracted); err != nil {
					return fmt.Errorf("failed to extract nested archive %s: %w", file.Name(), err)
				}
			}
		}
	}
	return nil
}

// extractArchiveToTempDir creates a temporary directory and extracts the archive file for scanning.
func extractArchiveToTempDir(ctx context.Context, path string) (string, error) {
	logger := clog.FromContext(ctx).With("path", path)
	logger.Info("creating temp dir")

	tmpDir, err := os.MkdirTemp("", filepath.Base(path))
	if err != nil {
		return "", fmt.Errorf("failed to create temp dir: %w", err)
	}

	ext := getExt(path)
	extract := extractionMethod(ext)
	if extract == nil {
		return "", fmt.Errorf("unsupported archive type: %s", path)
	}
	err = extract(ctx, tmpDir, path)
	if err != nil {
		return "", fmt.Errorf("failed to extract %s: %w", path, err)
	}

	var extractedFiles sync.Map
	files, err := os.ReadDir(tmpDir)
	if err != nil {
		return "", fmt.Errorf("failed to read files in directory %s: %w", tmpDir, err)
	}
	for _, file := range files {
		extractedFiles.Store(filepath.Join(tmpDir, file.Name()), false)
	}

	extractedFiles.Range(func(key, _ any) bool {
		if key == nil {
			return true
		}
		//nolint: nestif // ignoring complexity of 11
		if file, ok := key.(string); ok {
			ext := getExt(file)
			info, err := os.Stat(file)
			if err != nil {
				return false
			}
			switch mode := info.Mode(); {
			case mode.IsDir():
				err = filepath.WalkDir(file, func(path string, d fs.DirEntry, err error) error {
					if err != nil {
						return err
					}
					rel, err := filepath.Rel(tmpDir, path)
					if err != nil {
						return fmt.Errorf("filepath.Rel: %w", err)
					}
					if !d.IsDir() {
						if err := extractNestedArchive(ctx, tmpDir, rel, &extractedFiles); err != nil {
							return fmt.Errorf("failed to extract nested archive %s: %w", rel, err)
						}
					}

					return nil
				})
				if err != nil {
					return false
				}
				return true
			case mode.IsRegular():
				if _, ok := archiveMap[ext]; ok {
					rel, err := filepath.Rel(tmpDir, file)
					if err != nil {
						return false
					}
					if err := extractNestedArchive(ctx, tmpDir, rel, &extractedFiles); err != nil {
						return false
					}
				}
				return true
			}
		}
		return true
	})

	return tmpDir, nil
}

func extractionMethod(ext string) func(context.Context, string, string) error {
	switch ext {
	case ".jar", ".zip":
		return extractZip
	case ".gz":
		return extractGzip
	case ".apk", ".bz2", ".bzip2", ".gem", ".tar", ".tar.gz", ".tgz", ".tar.xz", ".xz":
		return extractTar
	default:
		return nil
	}
}
