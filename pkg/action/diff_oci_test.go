// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package action

import (
	"fmt"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/registry"
)

// diffTestPushImages serves an in-process registry, pushes one single-layer
// image per file map, and returns their references in order.
func diffTestPushImages(t *testing.T, images ...map[string][]byte) []string {
	t.Helper()
	srv := httptest.NewServer(registry.New(registry.Logger(slog.NewLogLogger(slog.DiscardHandler, slog.LevelInfo))))
	t.Cleanup(srv.Close)
	host := strings.TrimPrefix(srv.URL, "http://")

	refs := make([]string, 0, len(images))
	for i, files := range images {
		img, err := crane.Image(files)
		if err != nil {
			t.Fatalf("build image %d: %v", i, err)
		}
		ref := fmt.Sprintf("%s/malcontent/diff-test:v%d", host, i+1)
		if err := crane.Push(img, ref, crane.WithContext(t.Context())); err != nil {
			t.Fatalf("push %s: %v", ref, err)
		}
		refs = append(refs, ref)
	}
	return refs
}

func TestDiffImages(t *testing.T) {
	// Not parallel: points TMPDIR through a symlink, so the extracted images'
	// roots are spelled differently from the scanned paths, and inspects the
	// directory once the diff returns.
	c := diffTestConfig(t)
	script := func(s string) []byte { return []byte("#!/bin/sh\necho " + s + "\n") }
	refs := diffTestPushImages(t,
		map[string][]byte{"usr/bin/app": script("bin v1"), "usr/sbin/app": script("sbin v1"), "etc/gone.sh": script("gone")},
		map[string][]byte{"usr/bin/app": script("bin v2"), "usr/sbin/app": script("sbin v2"), "etc/new.sh": script("new")},
	)
	tmpReal, tmpLink := diffTestSymlinkedDir(t)
	t.Setenv("TMPDIR", tmpLink)

	c.OCI = true
	d := diffTestRun(t, c, refs[0], refs[1])
	src, dest := refs[0], refs[1]
	// Files that share a base name stay distinct and pair with their counterparts.
	diffTestAssertKeys(t, d,
		[]string{src + " ∴ /etc/gone.sh"},
		[]string{dest + " ∴ /etc/new.sh"},
		[]string{dest + " ∴ /usr/bin/app", dest + " ∴ /usr/sbin/app"},
	)
	for pair := d.Modified.Oldest(); pair != nil; pair = pair.Next() {
		if pair.Value.Path != pair.Key {
			t.Errorf("Modified Path: got = %q, want = %q", pair.Value.Path, pair.Key)
		}
	}

	entries, err := scanTestReadDir(tmpReal)
	if err != nil {
		t.Fatalf("ReadDir(%q): %v", tmpReal, err)
	}
	if len(entries) != 0 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("temporary directory after diff: got = %q, want empty", names)
	}
}
