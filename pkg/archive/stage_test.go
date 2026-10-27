// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"io/fs"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/chainguard-dev/malcontent/pkg/file"
	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	zip "github.com/klauspost/compress/zip"
)

// stageTestDeep is a directory path longer than PATH_MAX on every platform:
// 42 levels of 100-byte names.
var stageTestDeep = strings.Repeat(strings.Repeat("d", 100)+"/", 42)

// stageTestTree returns the regular files and symlinks beneath sub, a
// directory relative to dir, as paths relative to sub, and fails the test if
// a staging directory is left anywhere beneath dir.
func stageTestTree(t *testing.T, dir, sub string) []string {
	t.Helper()
	r := openTestRoot(t, dir)
	var got []string
	err := file.WalkDir(r, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if strings.HasPrefix(d.Name(), ".malcontent-stage-") {
			t.Errorf("staging directory left behind: %s", p)
		}
		rel, ok := strings.CutPrefix(p, sub)
		if ok && !d.IsDir() {
			got = append(got, strings.TrimPrefix(rel, "/"))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", dir, err)
	}
	slices.Sort(got)
	return got
}

// TestExtractArchiveToTempDirStagesDeepNestedArchives extracts the same
// nested archive at a short path and at one past PATH_MAX. Both must produce
// the same files where nested extraction puts them, and leave nothing behind
// from staging; an archive that fails to extract is retained either way.
func TestExtractArchiveToTempDirStagesDeepNestedArchives(t *testing.T) {
	t.Parallel()
	innerZip := zipSpecBytes(t, zip.Deflate, []zipSpecEntry{{name: "app/x.txt", body: "x"}, {name: "app/y.txt", body: "y"}})
	tests := []struct {
		name  string
		inner string // the nested archive's path beneath the directory checked
		body  []byte
		want  []string
	}{
		{name: "zip", inner: "inner.zip", body: innerZip, want: []string{"inner/app/x.txt", "inner/app/y.txt"}},
		{name: "gzip", inner: "tool.sh.gz", body: pkgsCompress(t, pkgsGzip, []byte("#!/bin/sh\n")), want: []string{"tool.sh/tool.sh"}},
		// zstd names its output after the archive's directory, "pkg" here,
		// which staging must keep.
		{name: "zstd", inner: "pkg/tool.sh.zst", body: pkgsCompress(t, pkgsZstd, []byte("#!/bin/sh\n")), want: []string{"pkg/tool.sh/pkg/tool.sh"}},
		{name: "corrupt archive is retained", inner: "bad.zip", body: []byte("PK\x03\x04 not a zip"), want: []string{"bad.zip"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var trees [2][]string
			for i, prefix := range []string{"short/", stageTestDeep} {
				src := filepath.Join(t.TempDir(), "outer.zip")
				zipSpecWrite(t, src, zip.Deflate, []zipSpecEntry{{name: prefix + tt.inner, body: string(tt.body)}})
				dir, err := ExtractArchiveToTempDir(t.Context(), malcontent.Config{}, src)
				if err != nil {
					t.Fatalf("ExtractArchiveToTempDir with prefix of %d bytes: %v", len(prefix), err)
				}
				t.Cleanup(func() { cleanupTempDir(t.Context(), dir) })
				trees[i] = stageTestTree(t, dir, strings.TrimSuffix(prefix, "/"))
			}
			if !slices.Equal(trees[0], tt.want) {
				t.Errorf("files at a short path: got = %q, want = %q", trees[0], tt.want)
			}
			if !slices.Equal(trees[1], trees[0]) {
				t.Errorf("files past PATH_MAX: got = %q, want = %q, as at a short path", trees[1], trees[0])
			}
		})
	}
}
