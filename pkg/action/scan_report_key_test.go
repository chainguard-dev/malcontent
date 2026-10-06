// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package action

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
)

func TestArchiveEntryKey(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		archive string
		entry   string
		trim    []string
		want    string
	}{
		{name: "entry is keyed by its archive and its path inside it", archive: "/scan/a.zip", entry: "/app/main.sh", want: "/scan/a.zip ∴ /app/main.sh"},
		{name: "nested archive entry keeps the nested archive directory", archive: "/scan/outer.tar.gz", entry: "/lib/inner/app/main.sh", want: "/scan/outer.tar.gz ∴ /lib/inner/app/main.sh"},
		{name: "archive at the scan root is trimmed to its name", archive: "/scan/a.zip", entry: "/app/main.sh", trim: []string{"/scan"}, want: "a.zip ∴ /app/main.sh"},
		{name: "archive path is trimmed once", archive: "a/a/x.zip", entry: "/main.sh", trim: []string{"a"}, want: "a/x.zip ∴ /main.sh"},
		{name: "unmatched trim prefix leaves the archive path", archive: "/scan/a.zip", entry: "/main.sh", trim: []string{"/other"}, want: "/scan/a.zip ∴ /main.sh"},
		{name: "macOS private prefix is dropped as in display paths", archive: "/private/var/a.zip", entry: "/main.sh", want: "/var/a.zip ∴ /main.sh"},
		{name: "backslashes in the entry path become slashes", archive: "a.zip", entry: `\app\main.sh`, want: "a.zip ∴ /app/main.sh"},
		{name: "archive inside an OCI image is named by the image", archive: scanTestImageURI + " ∴ /usr/lib/a.jar", entry: "/A.class", want: scanTestImageURI + " ∴ /usr/lib/a.jar ∴ /A.class"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := archiveEntryKey(tt.archive, tt.entry, tt.trim); got != tt.want {
				t.Errorf("archiveEntryKey(%q, %q, %q): got = %q, want = %q", tt.archive, tt.entry, tt.trim, got, tt.want)
			}
		})
	}

	t.Run("same entry in different archives has different keys", func(t *testing.T) {
		t.Parallel()
		archives := []string{"/scan/a.zip", "/scan/b.zip", "/scan/sub/a.zip", "/other/a.zip"}
		seen := map[string]string{}
		for _, a := range archives {
			key := archiveEntryKey(a, "/app/main.sh", nil)
			if prev, ok := seen[key]; ok {
				t.Errorf("key %q: got it for both %q and %q, want distinct keys", key, prev, a)
			}
			seen[key] = a
		}
	})
}

func TestFileKey(t *testing.T) {
	t.Parallel()
	const extract = "/tmp/oci-extract"
	oci := scanPathInfo{originalPath: scanTestImageURI, effectivePath: extract, ociExtractPath: extract, imageURI: scanTestImageURI}

	tests := []struct {
		name     string
		path     string
		scanInfo scanPathInfo
		ociScan  bool
		trim     []string
		want     string
	}{
		{name: "file is keyed by its path", path: "/scan/app/main.sh", scanInfo: scanPathInfo{originalPath: "/scan", effectivePath: "/scan"}, want: "/scan/app/main.sh"},
		{name: "file path is trimmed", path: "/scan/app/main.sh", scanInfo: scanPathInfo{originalPath: "/scan", effectivePath: "/scan"}, trim: []string{"/scan"}, want: "app/main.sh"},
		{name: "OCI image file is keyed by the image and its path in it", path: extract + "/app/main.sh", scanInfo: oci, ociScan: true, want: scanTestImageURI + " ∴ /app/main.sh"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c := malcontent.Config{OCI: tt.ociScan, TrimPrefixes: tt.trim}
			if got := fileKey(tt.path, tt.scanInfo, c); got != tt.want {
				t.Errorf("fileKey(%q): got = %q, want = %q", tt.path, got, tt.want)
			}
		})
	}
}

// scanTestEntries maps entry names to the hit and clean fixture contents.
func scanTestEntries(t *testing.T) map[string][]byte {
	t.Helper()
	return map[string][]byte{
		"app/locale.sh":    []byte(scanTestLocaleScript),
		"app/package.json": readTestFile(t, scanTestNPMFixture),
	}
}

func TestScanArchiveEntryKeysAreDistinct(t *testing.T) {
	t.Parallel()
	yrs, rfs := scanTestRules(t)
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("resolve scan root: %v", err)
	}

	buildZipFile(t, filepath.Join(root, "a.zip"), scanTestEntries(t))
	buildZipFile(t, filepath.Join(root, "b.zip"), scanTestEntries(t))
	if err := os.Mkdir(filepath.Join(root, "sub"), 0o700); err != nil {
		t.Fatalf("create sub: %v", err)
	}
	buildZipFile(t, filepath.Join(root, "sub", "a.zip"), scanTestEntries(t))
	inner := filepath.Join(t.TempDir(), "inner.zip")
	buildZipFile(t, inner, scanTestEntries(t))
	outer := map[string][]byte{
		"app/package.json": readTestFile(t, scanTestNPMFixture),
		"lib/inner.zip":    readTestFile(t, inner),
	}
	buildZipFile(t, filepath.Join(root, "outer.zip"), outer)

	tests := []struct {
		name      string
		scanPaths []string
		trim      []string
		want      []string
	}{
		{
			name:      "archives in a directory keep their entries apart",
			scanPaths: []string{root},
			trim:      []string{root},
			want: []string{
				"a.zip ∴ /app/locale.sh", "a.zip ∴ /app/package.json",
				"b.zip ∴ /app/locale.sh", "b.zip ∴ /app/package.json",
				"outer.zip ∴ /app/package.json", "outer.zip ∴ /lib/inner/app/locale.sh", "outer.zip ∴ /lib/inner/app/package.json",
				"sub/a.zip ∴ /app/locale.sh", "sub/a.zip ∴ /app/package.json",
			},
		},
		{
			name:      "archive given as the scan path is keyed by that path",
			scanPaths: []string{filepath.Join(root, "a.zip")},
			want:      []string{filepath.Join(root, "a.zip") + " ∴ /app/locale.sh", filepath.Join(root, "a.zip") + " ∴ /app/package.json"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c := malcontent.Config{Concurrency: 2, Rules: yrs, RuleFS: rfs, ScanPaths: tt.scanPaths, TrimPrefixes: tt.trim}

			r, err := Scan(t.Context(), c)
			if err != nil {
				t.Fatalf("Scan: %v", err)
			}
			if got := scanTestKeys(r.Files); !slices.Equal(got, tt.want) {
				t.Errorf("report keys: got = %v, want = %v", got, tt.want)
			}
			r.Files.Range(func(key string, fr *malcontent.FileReport) bool {
				if fr.Path != key {
					t.Errorf("Path for key %q: got = %q, want = %q", key, fr.Path, key)
				}
				return true
			})
		})
	}
}

func TestScanArchiveEntryPathsWithSymlinkedTempDir(t *testing.T) {
	// Not parallel: points TMPDIR at a symlink.
	yrs, rfs := scanTestRules(t)
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("resolve temp dir: %v", err)
	}
	archivePath := filepath.Join(base, "bundle.zip")
	buildZipFile(t, archivePath, scanTestEntries(t))
	realTmp := filepath.Join(base, "tmp-real")
	if err := os.Mkdir(realTmp, 0o700); err != nil {
		t.Fatalf("create %s: %v", realTmp, err)
	}
	linkTmp := filepath.Join(base, "tmp-link")
	if err := os.Symlink(realTmp, linkTmp); err != nil {
		t.Fatalf("symlink %s: %v", linkTmp, err)
	}
	t.Setenv("TMPDIR", linkTmp)

	c := malcontent.Config{Concurrency: 2, Rules: yrs, RuleFS: rfs, ScanPaths: []string{archivePath}}
	r, err := Scan(t.Context(), c)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	want := []string{archivePath + " ∴ /app/locale.sh", archivePath + " ∴ /app/package.json"}
	if got := scanTestKeys(r.Files); !slices.Equal(got, want) {
		t.Errorf("report keys: got = %v, want = %v", got, want)
	}
	r.Files.Range(func(key string, fr *malcontent.FileReport) bool {
		if fr.Path != key {
			t.Errorf("Path for key %q: got = %q, want = %q", key, fr.Path, key)
		}
		if strings.Contains(fr.Path, realTmp) || strings.Contains(fr.Path, linkTmp) {
			t.Errorf("Path: got = %q, want no temporary directory", fr.Path)
		}
		return true
	})

	left, err := os.ReadDir(realTmp)
	if err != nil {
		t.Fatalf("read %s: %v", realTmp, err)
	}
	if len(left) != 0 {
		t.Errorf("temporary entries after scan: got = %d, want = 0", len(left))
	}
}

func TestProcessPathsEvaluatesEachOCIImageOnItsOwn(t *testing.T) {
	t.Parallel()
	yrs, rfs := scanTestRules(t)
	fx := newScanTestFixture(t, yrs, rfs)
	cleanRoot := t.TempDir()
	clean := scanTestWriteFile(t, filepath.Join(cleanRoot, "app", "locale.sh"), []byte(scanTestLocaleScript))
	const firstImage = "registry.example/malcontent/first:latest"
	const secondImage = "registry.example/malcontent/second:latest"

	logger, _ := scanTestLogger()
	r := initializeReport(nil)
	matchChan := make(chan matchResult, 1)
	var once sync.Once
	c := malcontent.Config{Concurrency: 2, ExitFirstMiss: true, OCI: true, Rules: yrs, RuleFS: rfs}

	first := scanPathInfo{originalPath: firstImage, effectivePath: fx.root, ociExtractPath: fx.root, imageURI: firstImage}
	if err := processPaths(t.Context(), []string{fx.hit, fx.clean}, first, c, r, matchChan, &once, logger); err != nil {
		t.Fatalf("image with a hit under exit-first-miss: got = %v, want = nil", err)
	}
	if got, want := scanTestKeys(r.Files), []string{firstImage + " ∴ /app/locale.sh", firstImage + " ∴ /app/package.json"}; !slices.Equal(got, want) {
		t.Fatalf("keys after the first image: got = %v, want = %v", got, want)
	}

	second := scanPathInfo{originalPath: secondImage, effectivePath: cleanRoot, ociExtractPath: cleanRoot, imageURI: secondImage}
	err := processPaths(t.Context(), []string{clean}, second, c, r, matchChan, &once, logger)
	if !errors.Is(err, ErrMatchedCondition) {
		t.Fatalf("image without hits after one with hits: got = %v, want = %v", err, ErrMatchedCondition)
	}
	if !strings.Contains(err.Error(), secondImage) {
		t.Errorf("error: got = %v, want it to name %q", err, secondImage)
	}
	if got := r.Files.Size(); got != 0 {
		t.Errorf("reports after a miss: got = %d, want = 0", got)
	}
}
