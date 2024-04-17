package action

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/google/go-containerregistry/pkg/crane"
	v1 "github.com/google/go-containerregistry/pkg/v1"
)

func prepareImage(d string) (string, *os.File, error) {
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

// return a directory with the extracted image directories/files in it.
func oci(path string) (string, error) {
	tmpDir, tmpFile, err := prepareImage(path)
	if err != nil {
		return "", fmt.Errorf("failed to prepare image: %w", err)
	}

	err = extractTar(tmpDir, tmpFile.Name())
	if err != nil {
		return "", fmt.Errorf("failed to extract image: %w", err)
	}

	return tmpDir, nil
}
