// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/chainguard-dev/malcontent/pkg/file"
	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/chainguard-dev/malcontent/pkg/programkind"
)

// tooLong reports whether any of paths is too long to hand an extractor,
// which opens and checks paths whole. Archives at longer paths are staged:
// extracted where their paths are short.
func tooLong(paths ...string) bool {
	for _, p := range paths {
		if len(p) > file.MaxDirectPath {
			return true
		}
	}
	return false
}

// stagedName returns the path, beneath a staging directory, of a copy of the
// archive at path. Single-file extractors name what they write after the
// directory holding the archive, so the copy sits in a directory of that
// name.
func stagedName(path string) string {
	return filepath.Join(filepath.Base(filepath.Dir(path)), filepath.Base(path))
}

// makeStageDir creates a staging directory beneath root and returns its
// name. The name is random, so that concurrent extractions, and entries an
// archive holds, never claim it.
func makeStageDir(root *os.Root) (string, error) {
	for range maxCollisionNames {
		name := ".malcontent-stage-" + rand.Text()
		err := root.Mkdir(name, 0o700)
		if err == nil {
			return name, nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return "", fmt.Errorf("failed to create staging directory: %w", err)
		}
	}
	return "", errors.New("failed to create staging directory: no unused name")
}

// copyFile writes the content of name beneath src to dstName beneath dst,
// creating it.
func copyFile(src *os.Root, name string, dst *os.Root, dstName string) error {
	in, err := src.Open(name)
	if err != nil {
		return fmt.Errorf("failed to open archive for staging: %w", err)
	}
	defer in.Close()
	out, err := dst.OpenFile(dstName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("failed to create staged archive: %w", err)
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return fmt.Errorf("failed to stage archive: %w", err)
	}
	return out.Close()
}

// extractIn extracts f, relative to d, whose root is root, into dirName, an
// empty directory beneath root, with extract. When either path is too long to
// hand the operating system whole, f is extracted in a staging directory
// beneath root, where its paths are short, and whatever extraction wrote is
// moved into dirName, which root reaches however deep it lies. Symlinks the
// extractor wrote stay within what it wrote, so they resolve the same after
// the move.
func extractIn(ctx context.Context, root *os.Root, d string, extract func(context.Context, string, string) error, f, dirName string) error {
	src, dst := filepath.Join(d, f), filepath.Join(d, dirName)
	if !tooLong(src, dst) {
		return extract(ctx, dst, src)
	}

	stage, err := makeStageDir(root)
	if err != nil {
		return err
	}
	defer func() { _ = root.RemoveAll(stage) }()

	staged := filepath.Join(stage, stagedName(src))
	if err := root.MkdirAll(filepath.Dir(staged), 0o700); err != nil {
		return fmt.Errorf("failed to create staging directory: %w", err)
	}
	// A hard link stages the archive without copying it.
	if err := root.Link(f, staged); err != nil {
		if err := copyFile(root, f, root, staged); err != nil {
			return err
		}
	}
	out := filepath.Join(stage, "out")
	if err := root.Mkdir(out, 0o700); err != nil {
		return fmt.Errorf("failed to create staging directory: %w", err)
	}

	// What extraction wrote before failing is moved too, as it would have
	// been written into dirName directly. A directory is not renamed over
	// another, so dirName, still empty, makes way. Extractions in one
	// directory run one at a time, so nothing claims its name meanwhile.
	extractErr := extract(ctx, filepath.Join(d, out), filepath.Join(d, staged))
	if err := root.Remove(dirName); err != nil {
		return errors.Join(extractErr, fmt.Errorf("failed to move staged extraction: %w", err))
	}
	if err := root.Rename(out, dirName); err != nil {
		return errors.Join(extractErr, fmt.Errorf("failed to move staged extraction: %w", err))
	}
	return extractErr
}

// OpenTreeIn opens the archive name beneath dir, whose path is path, as
// OpenTree opens path. An archive at a path too long to hand the operating
// system whole is copied, through dir, to a short temporary path first, from
// which it is extracted as it would have been from path.
func OpenTreeIn(ctx context.Context, c malcontent.Config, dir *os.Root, name, path string) (*Tree, error) {
	if !tooLong(path) {
		return OpenTree(ctx, c, path)
	}

	stage, err := os.MkdirTemp("", "malcontent-stage")
	if err != nil {
		return nil, fmt.Errorf("failed to create staging directory: %w", err)
	}
	defer func() { _ = file.RemoveAllIn(filepath.Dir(stage), filepath.Base(stage)) }()
	root, err := os.OpenRoot(stage)
	if err != nil {
		return nil, fmt.Errorf("failed to open staging directory: %w", err)
	}
	defer root.Close()

	staged := stagedName(path)
	if err := root.Mkdir(filepath.Dir(staged), 0o700); err != nil {
		return nil, fmt.Errorf("failed to create staging directory: %w", err)
	}
	if err := copyFile(dir, name, root, staged); err != nil {
		return nil, err
	}
	return OpenTree(ctx, c, filepath.Join(stage, staged))
}

// detectIn returns the kind of name beneath root, a regular file of the given
// size at path, as programkind.File does, reading it through root so that the
// length of its path does not matter.
func detectIn(ctx context.Context, root *os.Root, name, path string, size int64) (*programkind.FileType, error) {
	f, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	fc, err := file.ReadContents(f, size)
	_ = f.Close()
	if err != nil {
		return nil, fmt.Errorf("file contents: %w", err)
	}
	defer func() { _ = fc.Close() }()
	return programkind.Detect(ctx, path, fc.Bytes()), nil
}
