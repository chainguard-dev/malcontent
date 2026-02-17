// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package action

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
)

// FuzzCleanPath fuzzes the CleanPath function.
func FuzzCleanPath(f *testing.F) {
	f.Add("/tmp/extract/path/to/file", "/tmp/extract")
	f.Add("/tmp/extract2/file", "/tmp/extract")
	f.Add("/path", "")
	f.Add("", "/prefix")
	f.Add("/tmp/extract/file", "/tmp/extract")
	f.Add("/private/tmp/extract/file", "/private")
	f.Add("path\\with\\backslashes", "path")
	f.Add("/a/b/c", "/a/b")
	f.Add("/a/b/c", "/a/b/c")
	f.Add("/a/b/cd", "/a/b/c")

	f.Fuzz(func(t *testing.T, path, prefix string) {
		result := CleanPath(path, prefix)

		// Result never contains backslashes (normalized to /)
		if strings.Contains(result, "\\") {
			t.Errorf("CleanPath(%q, %q) = %q, contains backslash", path, prefix, result)
		}

		// If prefix is empty, result is formatPath(input)
		if prefix == "" {
			want := strings.ReplaceAll(path, "\\", "/")
			if result != want {
				t.Errorf("CleanPath(%q, \"\") = %q, want %q", path, result, want)
			}
		}
	})
}

// FuzzExitIfHitOrMiss fuzzes the exitIfHitOrMiss function.
func FuzzExitIfHitOrMiss(f *testing.F) {
	f.Add("/scan/path", true, false, 0)
	f.Add("/scan/path", false, true, 0)
	f.Add("/scan/path", true, true, 2)
	f.Add("/scan/path", false, false, 3)
	f.Add("", true, false, 1)

	f.Fuzz(func(t *testing.T, scanPath string, errIfHit, errIfMiss bool, numBehaviors int) {
		if numBehaviors < 0 || numBehaviors > 10 {
			return
		}

		// nil map always returns nil, nil
		fr, err := exitIfHitOrMiss(nil, scanPath, errIfHit, errIfMiss)
		if fr != nil || err != nil {
			t.Fatal("nil map should return nil, nil")
		}

		// When both flags are false, always returns nil, nil
		m := &sync.Map{}
		behaviors := make([]*malcontent.Behavior, numBehaviors)
		for i := range numBehaviors {
			behaviors[i] = &malcontent.Behavior{ID: "test"}
		}
		m.Store("file", &malcontent.FileReport{Path: "file", Behaviors: behaviors})

		fr2, err2 := exitIfHitOrMiss(m, scanPath, false, false)
		if fr2 != nil || err2 != nil {
			t.Fatal("both flags false should return nil, nil")
		}
	})
}

// FuzzFindFilesRecursively tests recursive file discovery with fuzzed
// directory structures to ensure no panics, no .git inclusion, and
// graceful handling of symlinks and broken links.
func FuzzFindFilesRecursively(f *testing.F) {
	f.Add(3, 2, true, true)
	f.Add(0, 0, false, false)
	f.Add(5, 3, true, false)
	f.Add(1, 0, false, true)

	f.Fuzz(func(t *testing.T, numFiles, numDirs int, createSymlink, createGitDir bool) {
		if numFiles < 0 || numFiles > 20 || numDirs < 0 || numDirs > 5 {
			return
		}

		tmpDir, err := os.MkdirTemp("", "fuzz-find-*")
		if err != nil {
			t.Skip()
		}
		defer os.RemoveAll(tmpDir)

		// Create subdirectories
		for i := range numDirs {
			subDir := filepath.Join(tmpDir, "dir"+string(rune('a'+i)))
			os.MkdirAll(subDir, 0o755)
			// Put a file in each subdir
			os.WriteFile(filepath.Join(subDir, "file.txt"), []byte("data"), 0o644)
		}

		// Create files at root
		for i := range numFiles {
			os.WriteFile(filepath.Join(tmpDir, "file"+string(rune('0'+i))+".txt"), []byte("data"), 0o644)
		}

		// Optionally create a .git directory (should be excluded from results)
		if createGitDir {
			gitDir := filepath.Join(tmpDir, ".git")
			os.MkdirAll(gitDir, 0o755)
			os.WriteFile(filepath.Join(gitDir, "config"), []byte("gitconfig"), 0o644)
		}

		// Optionally create a symlink (symlinked dirs should be excluded)
		if createSymlink && numDirs > 0 {
			target := filepath.Join(tmpDir, "dir"+string(rune('a')))
			os.Symlink(target, filepath.Join(tmpDir, "link_to_dir"))
		}

		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()

		files, err := findFilesRecursively(ctx, tmpDir)
		if err != nil {
			return // errors are OK (e.g., permission issues)
		}

		// Invariant: no .git files in results
		for _, f := range files {
			if strings.Contains(f, "/.git/") {
				t.Errorf("found .git file in results: %q", f)
			}
		}
	})
}
