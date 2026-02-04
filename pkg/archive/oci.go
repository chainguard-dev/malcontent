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

func prepareImage(ctx context.Context, d string, useAuth bool) (string, *os.File, error) {
	if ctx.Err() != nil {
		return "", nil, ctx.Err()
	}

	logger := clog.FromContext(ctx).With("image", d)
	logger.Debug("preparing image")
	tmpDir, err := os.MkdirTemp("", filepath.Base(d))
	if err != nil {
		return "", nil, fmt.Errorf("failed to create temp dir: %w", err)
	}

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
	if err := crane.Export(image, tmpFile); err != nil {
		return "", nil, fmt.Errorf("failed to export image: %w", err)
	}
	_, err = tmpFile.Seek(0, io.SeekStart)
	if err != nil {
		return "", nil, fmt.Errorf("failed to seek to start of temp file: %w", err)
	}
	return tmpDir, tmpFile, nil
}

// OCI returns a directory with the extracted image directories/files in it.
func OCI(ctx context.Context, path string, useAuth bool) (string, error) {
	tmpDir, tmpFile, err := prepareImage(ctx, path, useAuth)
	if err != nil {
		return "", fmt.Errorf("failed to prepare image: %w", err)
	}

	if err := ExtractTar(ctx, tmpDir, tmpFile.Name()); err != nil {
		return "", fmt.Errorf("extract image: %w", err)
	}
	// remove the temporary tarball after we extract it
	// otherwise we scan the tarball
	// in addition to its contents which produces odd results
	defer os.Remove(tmpFile.Name())

	return tmpDir, nil
}
