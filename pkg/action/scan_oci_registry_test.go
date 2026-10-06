// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package action

import (
	"errors"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/registry"
)

// scanTestPushImage serves an in-process registry, pushes a single-layer image
// built from files, and returns the image reference.
func scanTestPushImage(t *testing.T, files map[string][]byte) string {
	t.Helper()
	// The registry takes a *log.Logger; this one discards its request logs.
	srv := httptest.NewServer(registry.New(registry.Logger(slog.NewLogLogger(slog.DiscardHandler, slog.LevelDebug))))
	t.Cleanup(srv.Close)

	img, err := crane.Image(files)
	if err != nil {
		t.Fatalf("build image: %v", err)
	}
	ref := strings.TrimPrefix(srv.URL, "http://") + "/malcontent/scan-test:latest"
	if err := crane.Push(img, ref, crane.WithContext(t.Context())); err != nil {
		t.Fatalf("push %s: %v", ref, err)
	}
	return ref
}

func TestScanOCIImageRemovesExtractedImage(t *testing.T) {
	// Not parallel: points TMPDIR, through a symlink, at a directory the test
	// can inspect for the extracted image.
	yrs, rfs := scanTestRules(t)
	ref := scanTestPushImage(t, map[string][]byte{
		"app/package.json":        readTestFile(t, scanTestNPMFixture),
		"etc/profile.d/locale.sh": []byte(scanTestLocaleScript),
	})
	base := t.TempDir()
	tmp := filepath.Join(base, "tmp-real")
	if err := os.Mkdir(tmp, 0o700); err != nil {
		t.Fatalf("create %s: %v", tmp, err)
	}
	link := filepath.Join(base, "tmp-link")
	if err := os.Symlink(tmp, link); err != nil {
		t.Fatalf("symlink %s: %v", link, err)
	}
	t.Setenv("TMPDIR", link)

	c := malcontent.Config{Concurrency: 2, OCI: true, Rules: yrs, RuleFS: rfs, ScanPaths: []string{ref}}
	r, err := Scan(t.Context(), c)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	// Reports name image files by the image and their path in it, never by
	// the temporary extraction path, and key them the same way.
	want := []string{ref + " ∴ /app/package.json", ref + " ∴ /etc/profile.d/locale.sh"}
	if got := scanTestKeys(r.Files); !slices.Equal(got, want) {
		t.Errorf("report keys: got = %v, want = %v", got, want)
	}
	var paths []string
	r.Files.Range(func(_ string, fr *malcontent.FileReport) bool {
		paths = append(paths, fr.Path)
		return true
	})
	slices.Sort(paths)
	if !slices.Equal(paths, want) {
		t.Errorf("report paths: got = %v, want = %v", paths, want)
	}

	entries, err := os.ReadDir(tmp)
	if err != nil {
		t.Fatalf("read %s: %v", tmp, err)
	}
	if len(entries) != 0 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("temporary directory after scan: got = %v, want = empty", names)
	}
}

func TestScanOCIExitCriteriaEvaluateEachImage(t *testing.T) {
	t.Parallel()
	yrs, rfs := scanTestRules(t)
	hitImage := scanTestPushImage(t, map[string][]byte{
		"app/package.json": readTestFile(t, scanTestNPMFixture),
	})
	cleanImage := scanTestPushImage(t, map[string][]byte{
		"etc/profile.d/locale.sh": []byte(scanTestLocaleScript),
	})

	tests := []struct {
		name      string
		scanPaths []string
		exitHit   bool
		exitMiss  bool
		wantImage string
		wantKeys  []string
	}{
		{
			name:      "image without hits after an image with hits ends the scan under exit-first-miss",
			scanPaths: []string{hitImage, cleanImage}, exitMiss: true, wantImage: cleanImage,
		},
		{
			name:      "image with hits after an image without hits ends the scan under exit-first-hit",
			scanPaths: []string{cleanImage, hitImage}, exitHit: true, wantImage: hitImage,
			wantKeys: []string{hitImage + " ∴ /app/package.json"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c := malcontent.Config{
				Concurrency:   2,
				ExitFirstHit:  tt.exitHit,
				ExitFirstMiss: tt.exitMiss,
				OCI:           true,
				Rules:         yrs,
				RuleFS:        rfs,
				ScanPaths:     tt.scanPaths,
			}

			r, err := Scan(t.Context(), c)
			if !errors.Is(err, ErrMatchedCondition) {
				t.Fatalf("Scan error: got = %v, want = %v", err, ErrMatchedCondition)
			}
			if !strings.Contains(err.Error(), tt.wantImage) {
				t.Errorf("Scan error: got = %v, want it to name %q", err, tt.wantImage)
			}
			if got := scanTestKeys(r.Files); !slices.Equal(got, tt.wantKeys) {
				t.Errorf("report keys: got = %v, want = %v", got, tt.wantKeys)
			}
		})
	}
}
