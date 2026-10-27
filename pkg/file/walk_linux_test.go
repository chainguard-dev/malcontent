// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package file

import (
	"errors"
	"os"
	"strings"
	"testing"
)

// walkLinuxTestRoot opens a root on "/", skipping the test unless /proc and
// /sys are mounted beneath it.
func walkLinuxTestRoot(t *testing.T) *os.Root {
	t.Helper()
	r, err := os.OpenRoot("/")
	if err != nil {
		t.Skipf("open /: %v", err)
	}
	t.Cleanup(func() { _ = r.Close() })
	for _, name := range []string{"proc", "sys"} {
		dir, err := r.OpenRoot(name)
		if err != nil {
			t.Skipf("open /%s: %v", name, err)
		}
		pseudo := isPseudoFS(dir)
		_ = dir.Close()
		if !pseudo {
			t.Skipf("/%s is not a pseudo filesystem here", name)
		}
	}
	return r
}

func TestWalkerSkipsPseudoFilesystems(t *testing.T) {
	t.Parallel()
	r := walkLinuxTestRoot(t)

	tests := []struct {
		name        string
		skip        bool
		detach      bool
		wantEntries bool // entries below /proc and /sys are yielded
		wantErrs    bool // /proc and /sys are reported with ErrPseudoFS
	}{
		{name: "a walk that skips pseudo filesystems yields nothing below /proc or /sys", skip: true, wantErrs: true},
		{name: "a detaching walk that skips pseudo filesystems is refused /proc and /sys", skip: true, detach: true, wantErrs: true},
		{name: "a walk that does not skip them enters /proc and /sys", wantEntries: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			w := NewWalker(r, ".")
			defer w.Close()
			if tt.skip {
				w.SkipPseudoFilesystems()
			}
			var entries, errs int
			for w.Next() {
				path := w.Path()
				top, _, nested := strings.Cut(path, "/")
				if top != "proc" && top != "sys" {
					// Only the top of every other directory is visited.
					if w.Entry() != nil && w.Entry().IsDir() && path != "." && w.Err() == nil {
						w.SkipDir()
					}
					continue
				}
				switch {
				case errors.Is(w.Err(), ErrPseudoFS):
					errs++
				case nested:
					entries++
					w.SkipDir()
				case tt.detach && w.Err() == nil:
					dir, err := w.Detach()
					if errors.Is(err, ErrPseudoFS) {
						errs++
						continue
					}
					if err != nil {
						t.Fatalf("Detach(%q): %v", path, err)
					}
					_ = dir.Close()
					entries++
				}
			}
			if got := entries > 0; got != tt.wantEntries {
				t.Errorf("entries below /proc and /sys: got = %d, want any = %t", entries, tt.wantEntries)
			}
			if got := errs == 2; got != tt.wantErrs {
				t.Errorf("pseudo filesystems reported: got = %d, want both = %t", errs, tt.wantErrs)
			}
		})
	}
}

func TestIsPseudoFS(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		dir  string
		want bool
	}{
		{name: "proc is a pseudo filesystem", dir: "/proc", want: true},
		{name: "sysfs is a pseudo filesystem", dir: "/sys", want: true},
		{name: "a temporary directory holds stored files", dir: t.TempDir()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r, err := os.OpenRoot(tt.dir)
			if err != nil {
				t.Skipf("open %s: %v", tt.dir, err)
			}
			defer r.Close()
			if got := isPseudoFS(r); got != tt.want {
				t.Errorf("isPseudoFS(%s): got = %t, want = %t", tt.dir, got, tt.want)
			}
		})
	}
}
