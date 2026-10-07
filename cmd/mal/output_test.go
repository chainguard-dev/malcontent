// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"

	"github.com/chainguard-dev/malcontent/pkg/file"
)

func TestInheritedOutput(t *testing.T) {
	t.Parallel()
	tests := []struct {
		path   string
		wantFD uintptr
		wantOK bool
	}{
		{path: "/dev/stdout", wantFD: 1, wantOK: true},
		{path: "/dev/stderr", wantFD: 2, wantOK: true},
		{path: "/dev/fd/3", wantFD: 3, wantOK: true},
		{path: "/proc/self/fd/7", wantFD: 7, wantOK: true},
		{path: "/dev/fd/9", wantFD: 9, wantOK: true},
		{path: "/dev/fd/2147483647", wantFD: 2147483647, wantOK: true},
		{path: "/dev/fd/2147483648"},
		{path: "/dev/fd/a"},
		{path: "/dev/fd/x"},
		{path: "/dev/fd/-1"},
		{path: "/dev/fd/"},
		{path: "/dev/stdin"},
		{path: "report.json"},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			t.Parallel()
			fd, ok := inheritedOutput(tt.path)
			if runtime.GOOS == "windows" {
				tt.wantFD, tt.wantOK = 0, false
			}
			if fd != tt.wantFD || ok != tt.wantOK {
				t.Errorf("inheritedOutput(%q): got = (%d, %v), want = (%d, %v)", tt.path, fd, ok, tt.wantFD, tt.wantOK)
			}
		})
	}
}

func TestOpenOutputWritesToAnInheritedDescriptor(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("descriptor paths are Unix-only")
	}
	t.Parallel()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("Pipe: %v", err)
	}
	defer r.Close()
	out, err := openOutput("/dev/fd/" + strconv.Itoa(int(w.Fd())))
	if err != nil {
		t.Fatalf("openOutput: %v", err)
	}
	if _, err := io.WriteString(out, "report"); err != nil {
		t.Fatalf("write: %v", err)
	}
	// out and w share the descriptor; closing one closes the write end.
	_ = out.Close()
	got, err := io.ReadAll(r)
	if err != nil || string(got) != "report" {
		t.Errorf("read from the pipe: got = (%q, %v), want = (%q, nil)", got, err, "report")
	}
}

func TestOpenOutputCreatesAFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	out, err := openOutput(filepath.Join(dir, "report.json"))
	if err != nil {
		t.Fatalf("openOutput: %v", err)
	}
	_, err = io.WriteString(out, "{}")
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	if got, err := file.ReadFileIn(dir, "report.json"); err != nil || string(got) != "{}" {
		t.Errorf("report: got = (%q, %v), want = (%q, nil)", got, err, "{}")
	}
}
