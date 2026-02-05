// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/chainguard-dev/clog"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/crane"
	v1 "github.com/google/go-containerregistry/pkg/v1"
)

// limitedWriter wraps a writer and returns an error if the total bytes written exceeds a limit.
type limitedWriter struct {
	w         io.Writer
	remaining int64
}

func (lw *limitedWriter) Write(p []byte) (int, error) {
	if int64(len(p)) > lw.remaining {
		return 0, fmt.Errorf("export size exceeds maximum allowed size")
	}
	lw.remaining -= int64(len(p))
	return lw.w.Write(p)
}

func prepareImage(ctx context.Context, d string, useAuth bool, maxImageSize int64) (string, *os.File, error) {
	if ctx.Err() != nil {
		return "", nil, ctx.Err()
	}

	logger := clog.FromContext(ctx).With("image", d)
	logger.Debug("preparing image")
	tmpDir, err := os.MkdirTemp("", filepath.Base(d))
	if err != nil {
		return "", nil, fmt.Errorf("failed to create temp dir: %w", err)
	}

	// Clean up tmpDir on any error after this point
	success := false
	defer func() {
		if !success {
			os.RemoveAll(tmpDir)
		}
	}()

	tmpFile, err := os.CreateTemp(tmpDir, fmt.Sprintf("%s.tar", filepath.Base(d)))
	if err != nil {
		return "", nil, fmt.Errorf("failed to create temp file: %w", err)
	}

	// Use anonymous auth by default to avoid credential leakage.
	// This is an upstream implementation detail in the Docker registry auth spec,
	// but it's safer to default to anonymous auth by default.
	opts := []crane.Option{crane.WithContext(ctx)}
	if useAuth {
		opts = append(opts, crane.WithAuthFromKeychain(authn.DefaultKeychain))
	} else {
		opts = append(opts, crane.WithAuth(authn.Anonymous))
	}

	var image v1.Image
	if image, err = crane.Pull(d, opts...); err != nil {
		return "", nil, fmt.Errorf("failed to pull image: %w", err)
	}

	// Enforce maximum image size if configured (0 or negative means unlimited)
	if maxImageSize > 0 {
		manifest, err := image.Manifest()
		if err != nil {
			return "", nil, fmt.Errorf("failed to read image manifest: %w", err)
		}
		var totalSize int64
		for _, layer := range manifest.Layers {
			totalSize += layer.Size
		}
		totalSize += manifest.Config.Size
		if totalSize > maxImageSize {
			return "", nil, fmt.Errorf("image size (%d bytes) exceeds maximum allowed size (%d bytes)", totalSize, maxImageSize)
		}
	}

	// Use a size-limiting writer to enforce maxImageSize on the uncompressed export.
	// The manifest check above uses compressed sizes, which can be much smaller.
	var exportWriter io.Writer = tmpFile
	if maxImageSize > 0 {
		exportWriter = &limitedWriter{w: tmpFile, remaining: maxImageSize}
	}
	if err := crane.Export(image, exportWriter); err != nil {
		return "", nil, fmt.Errorf("failed to export image: %w", err)
	}
	_, err = tmpFile.Seek(0, io.SeekStart)
	if err != nil {
		return "", nil, fmt.Errorf("failed to seek to start of temp file: %w", err)
	}

	success = true
	return tmpDir, tmpFile, nil
}

// OCI returns a directory with the extracted image directories/files in it.
func OCI(ctx context.Context, path string, useAuth bool, maxImageSize int64) (string, error) {
	tmpDir, tmpFile, err := prepareImage(ctx, path, useAuth, maxImageSize)
	if err != nil {
		return "", fmt.Errorf("failed to prepare image: %w", err)
	}
	defer tmpFile.Close()

	if err := ExtractTar(ctx, tmpDir, tmpFile.Name()); err != nil {
		os.RemoveAll(tmpDir)
		return "", fmt.Errorf("extract image: %w", err)
	}
	// remove the temporary tarball after we extract it
	// otherwise we scan the tarball
	// in addition to its contents which produces odd results
	defer os.Remove(tmpFile.Name())

	return tmpDir, nil
}
