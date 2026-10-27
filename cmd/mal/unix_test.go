// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/chainguard-dev/malcontent/pkg/file"
	"github.com/chainguard-dev/malcontent/pkg/malcontent"
)

func TestCheckScanPaths(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := func(name string) string { return filepath.Join(dir, name) }
	if err := file.WriteFileIn(dir, "app.sh", []byte("#!/bin/sh\necho hello\n"), 0o600); err != nil {
		t.Fatalf("write app.sh: %v", err)
	}
	if err := file.WriteFileIn(dir, "secret.sh", nil, 0o600); err != nil {
		t.Fatalf("write secret.sh: %v", err)
	}
	for _, d := range []string{"sub", "locked"} {
		if err := os.Mkdir(path(d), 0o700); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}
	if err := file.WriteFileIn(path("locked"), "inner.sh", nil, 0o600); err != nil {
		t.Fatalf("write locked/inner.sh: %v", err)
	}
	links := map[string]string{"compat": path("gone"), "link": path("app.sh"), "lockedlink": path("locked/inner.sh")}
	for name, target := range links {
		if err := os.Symlink(target, path(name)); err != nil {
			t.Fatalf("symlink %s: %v", name, err)
		}
	}
	if err := syscall.Mkfifo(path("fifo"), 0o600); err != nil {
		t.Fatalf("mkfifo: %v", err)
	}
	for _, p := range []string{path("secret.sh"), path("locked")} {
		if err := os.Chmod(p, 0); err != nil {
			t.Fatalf("chmod %s: %v", p, err)
		}
	}
	// Restore access first, so the temporary directory can be removed.
	t.Cleanup(func() { _ = os.Chmod(path("locked"), 0o700) })
	privileged := os.Geteuid() == 0

	tests := []struct {
		name     string
		mc       malcontent.Config
		wantCode int
		wantMsg  string
		// denied names a row that relies on a permission check, which
		// does not apply to root.
		denied bool
	}{
		{name: "no path given", wantCode: ExitInvalidArgument, wantMsg: "no path to scan"},
		{name: "images need no paths on disk", mc: malcontent.Config{OCI: true, ScanPaths: []string{"cgr.dev/chainguard/static"}}},
		{name: "processes need no paths", mc: malcontent.Config{Processes: true}},
		{name: "existing file", mc: malcontent.Config{ScanPaths: []string{path("app.sh")}}},
		{name: "existing directory", mc: malcontent.Config{ScanPaths: []string{path("sub")}}},
		{name: "symlink to a file", mc: malcontent.Config{ScanPaths: []string{path("link")}}},
		{name: "symlink to a missing target stays lenient", mc: malcontent.Config{ScanPaths: []string{path("compat")}}},
		{name: "proc path stays lenient", mc: malcontent.Config{ScanPaths: []string{"/proc/999999999/exe"}}},
		{name: "fifo is left to the scanner", mc: malcontent.Config{ScanPaths: []string{path("fifo")}}},
		{name: "missing path", mc: malcontent.Config{ScanPaths: []string{path("missing")}}, wantCode: ExitInvalidArgument, wantMsg: fmt.Sprintf("%q", path("missing"))},
		{name: "missing path after an existing one", mc: malcontent.Config{ScanPaths: []string{path("app.sh"), path("missing")}}, wantCode: ExitInvalidArgument, wantMsg: fmt.Sprintf("%q", path("missing"))},
		{name: "unreadable file", mc: malcontent.Config{ScanPaths: []string{path("secret.sh")}}, wantCode: ExitInputOutput, wantMsg: "permission denied", denied: true},
		{name: "unreadable directory", mc: malcontent.Config{ScanPaths: []string{path("locked")}}, wantCode: ExitInputOutput, wantMsg: "permission denied", denied: true},
		{name: "path below an unreadable directory", mc: malcontent.Config{ScanPaths: []string{path("locked/inner.sh")}}, wantCode: ExitInputOutput, wantMsg: "permission denied", denied: true},
		{name: "symlink into an unreadable directory", mc: malcontent.Config{ScanPaths: []string{path("lockedlink")}}, wantCode: ExitInputOutput, wantMsg: "permission denied", denied: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if tt.denied && privileged {
				t.Skip("root bypasses permission checks")
			}
			code, err := checkScanPaths(&tt.mc)
			if code != tt.wantCode {
				t.Errorf("checkScanPaths(%v) code: got = %d, want = %d", tt.mc.ScanPaths, code, tt.wantCode)
			}
			switch {
			case tt.wantMsg == "" && err != nil:
				t.Errorf("checkScanPaths(%v) error: got = %v, want = nil", tt.mc.ScanPaths, err)
			case tt.wantMsg != "" && (err == nil || !strings.Contains(err.Error(), tt.wantMsg)):
				t.Errorf("checkScanPaths(%v) error: got = %v, want one containing %s", tt.mc.ScanPaths, err, tt.wantMsg)
			}
		})
	}
}
