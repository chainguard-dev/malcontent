package action

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/ulikunitz/xz"
)

const maxBytes = 1 << 29 // 512MB

// copyArchive copies the source archive file to the temporary directory.
func copyArchive(src string, dst string) error {
	r, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("failed to open source file: %w", err)
	}
	defer r.Close()

	w, err := os.CreateTemp(dst, fmt.Sprintf("%s.*", filepath.Base(src)))
	if err != nil {
		return fmt.Errorf("failed to create temporary file: %w", err)
	}

	defer func() {
		if cerr := w.Close(); cerr != nil {
			log.Printf("failed to close file: %v", cerr)
		}
	}()

	if _, err = io.Copy(w, r); err != nil {
		return fmt.Errorf("failed to copy data: %w", err)
	}

	return nil
}

// tempDir creates a temporary directory.
func tempDir(p string) (string, error) {
	tmpDir, err := os.MkdirTemp("", fmt.Sprintf("bincapz-%s", filepath.Base(p)))
	if err != nil {
		return "", fmt.Errorf("failed to create temp dir: %w", err)
	}

	if err := copyArchive(p, tmpDir); err != nil {
		os.RemoveAll(tmpDir)
		return "", fmt.Errorf("failed to copy archive: %w", err)
	}

	return tmpDir, nil
}

// extractTar extracts .apk and .tar* archives.
func extractTar(d string, f string) error {
	// Check if the file is valid
	_, err := os.Stat(f)
	if err != nil {
		return fmt.Errorf("failed to stat file: %w", err)
	}

	tf, err := os.Open(f)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer tf.Close()

	tr := tar.NewReader(tf)

	if strings.Contains(f, ".apk") || strings.Contains(f, ".tar.gz") {
		gzStream, err := gzip.NewReader(tf)
		if err != nil {
			return fmt.Errorf("failed to create gzip reader: %w", err)
		}
		defer gzStream.Close()
		tr = tar.NewReader(gzStream)
	}
	if strings.Contains(f, ".tar.xz") {
		xzStream, err := xz.NewReader(tf)
		if err != nil {
			return fmt.Errorf("failed to create xz reader: %w", err)
		}
		tr = tar.NewReader(xzStream)
	}

	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
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
			if err := os.MkdirAll(target, os.FileMode(header.Mode)); err != nil {
				return fmt.Errorf("failed to create directory: %w", err)
			}
			continue
		}

		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return fmt.Errorf("failed to create directory for file: %w", err)
		}

		f, err := os.OpenFile(target, os.O_RDWR|os.O_CREATE|os.O_TRUNC, os.FileMode(header.Mode))
		if err != nil {
			return fmt.Errorf("failed to create file: %w", err)
		}

		if _, err := io.Copy(f, io.LimitReader(tr, maxBytes)); err != nil {
			return fmt.Errorf("failed to copy file: %w", err)
		}

		if err := f.Close(); err != nil {
			return fmt.Errorf("failed to close file: %w", err)
		}
	}
	return nil
}

// extractZip extracts .jar and .zip archives.
func extractZip(d string, f string) error {
	// Check if the file is valid
	_, err := os.Stat(f)
	if err != nil {
		return fmt.Errorf("failed to stat file: %w", err)
	}

	read, err := zip.OpenReader(f)
	if err != nil {
		return fmt.Errorf("failed to open zip file: %w", err)
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
			open.Close()
			return fmt.Errorf("failed to open file in zip: %w", err)
		}

		err = os.MkdirAll(path.Dir(name), 0o755)
		if err != nil {
			return fmt.Errorf("failed to create directory: %w", err)
		}

		mode := file.Mode() | 0o200
		create, err := os.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_TRUNC, mode)
		if err != nil {
			create.Close()
			return fmt.Errorf("failed to create file: %w", err)
		}

		if _, err = io.Copy(create, io.LimitReader(open, maxBytes)); err != nil {
			return fmt.Errorf("failed to copy file: %w", err)
		}

		open.Close()
		create.Close()
	}
	return nil
}

// extractArchive specifies which extraction method to use based on the archive type.
func extractArchive(d string, f string) error {
	switch {
	// .jar and .zip files can be extracted using the same method
	case strings.Contains(f, ".jar") || strings.Contains(f, ".zip"):
		if err := extractZip(d, f); err != nil {
			return fmt.Errorf("failed to extract zip-based file: %w", err)
		}
	// .apk and .tar* files can be extracted using the same method
	case strings.Contains(f, ".apk") || strings.Contains(f, ".tar"):
		if err := extractTar(d, f); err != nil {
			return fmt.Errorf("failed to extract tar-based file: %w", err)
		}
	// Unsupported archive type
	default:
		return fmt.Errorf("unsupported archive type: %s", f)
	}
	return nil
}

// archive creates a temporary directory and extracts the archive file for scanning.
func archive(sp string) (string, error) {
	tmpDir, err := tempDir(sp)
	if err != nil {
		return "", fmt.Errorf("failed to create temp dir: %w", err)
	}

	if err := extractArchive(tmpDir, sp); err != nil {
		return "", fmt.Errorf("failed to extract archive: %w", err)
	}

	return tmpDir, nil
}
