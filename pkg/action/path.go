// Copyright 2025 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package action

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/chainguard-dev/clog"
)

// findFilesRecursively returns a list of files found recursively within a path.
func findFilesRecursively(ctx context.Context, rootPath string) ([]string, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	logger := clog.FromContext(ctx)
	var files []string

	// Follow symlink if provided at the root
	root, err := filepath.EvalSymlinks(rootPath)
	if err != nil {
		// If the target does not exist, log the error but return gracefully
		// This is useful when scanning -compat packages
		if os.IsNotExist(err) {
			logger.Debugf("symlink target does not exist: %s", err.Error())
			return nil, nil
		}
		// Allow /proc/XXX/exe to be scanned even if symlink is not resolveable
		if strings.HasPrefix(rootPath, "/proc/") {
			root = rootPath
		} else {
			return nil, fmt.Errorf("eval %q: %w", rootPath, err)
		}
	}

	err = filepath.WalkDir(root,
		func(path string, info os.DirEntry, err error) error {
			if err != nil {
				logger.Debugf("error: %s: %s", path, err)
				return nil
			}
			if info.IsDir() || strings.Contains(path, "/.git/") {
				return nil
			}

			// Ignore symlinked directories like regular directories
			if info.Type()&fs.ModeSymlink == fs.ModeSymlink {
				return nil
			}

			files = append(files, path)
			return nil
		})
	return files, err
}

// CleanPath removes the temporary directory prefix from the path.
// It only removes the prefix if it's at a directory boundary to avoid
// partial matches (e.g., "/tmp/extract" should not match "/tmp/extract2/file").
func CleanPath(path string, prefix string) string {
	if prefix == "" {
		return formatPath(path)
	}

	// Check if path starts with prefix
	if !strings.HasPrefix(path, prefix) {
		return formatPath(path)
	}

	// If path equals prefix exactly, return empty
	if len(path) == len(prefix) {
		return ""
	}

	// Only strip if the next character is a path separator (directory boundary)
	remainder := path[len(prefix):]
	if remainder[0] == '/' || remainder[0] == '\\' {
		return formatPath(remainder)
	}

	// Partial match (e.g., prefix="/tmp/extract" but path="/tmp/extract2/file")
	// Don't strip anything
	return formatPath(path)
}

// formatPath formats the path for display.
func formatPath(path string) string {
	return strings.ReplaceAll(path, "\\", "/")
}
