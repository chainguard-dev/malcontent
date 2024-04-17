package action

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/go-containerregistry/pkg/crane"
	v1 "github.com/google/go-containerregistry/pkg/v1"
)

const maxBytes = 1 << 26

func prepare(d string) (string, *os.File, error) {
	tmpDir, err := os.MkdirTemp("", fmt.Sprintf("bincapz-%s", filepath.Base(d)))
	if err != nil {
		return "", nil, fmt.Errorf("failed to create temp dir: %w", err)
	}

	tmpFile, err := os.CreateTemp(tmpDir, fmt.Sprintf("%s.tar", filepath.Base(d)))
	if err != nil {
		return "", nil, fmt.Errorf("failed to create temp file: %w", err)
	}

	var image v1.Image
	if image, err = crane.Pull(d, crane.WithContext(context.Background())); err != nil {
		return "", nil, fmt.Errorf("failed to pull image: %w", err)
	}
	if err := crane.Export(image, tmpFile); err != nil {
		return "", nil, fmt.Errorf("failed to export image: %w", err)
	}
	_, err = tmpFile.Seek(0, io.SeekStart)
	if err != nil {
		return "", nil, fmt.Errorf("failed to seek to start of temp file: %w", err)
	}
	return tmpDir, tmpFile, nil
}

func extract(d string, f *os.File) error {
	tr := tar.NewReader(f)
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

// return a directory with the extracted image directories/files in it.
func oci(path string) (string, error) {
	tmpDir, tmpFile, err := prepare(path)
	if err != nil {
		return "", fmt.Errorf("failed to prepare image: %w", err)
	}

	err = extract(tmpDir, tmpFile)
	if err != nil {
		return "", fmt.Errorf("failed to extract image: %w", err)
	}

	return tmpDir, nil
}
