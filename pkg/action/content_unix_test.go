// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package action

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestSniffEntryMatchesSniffFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	scanTestWriteFile(t, filepath.Join(dir, "run"), []byte("#!/bin/sh\necho hi\n"))
	scanTestWriteFile(t, filepath.Join(dir, "empty.sh"), nil)
	scanTestWriteFile(t, filepath.Join(dir, "notes.txt"), []byte("plain words\n"))
	scanTestWriteFile(t, filepath.Join(dir, "locked.sh"), []byte("#!/bin/sh\n"))
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("open root: %v", err)
	}
	// Subtests run in parallel after this function returns.
	t.Cleanup(func() { _ = root.Close() })
	if err := root.Mkdir("sub", 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := root.Chmod("locked.sh", 0); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	d, err := root.Open(".")
	if err != nil {
		t.Fatalf("open directory: %v", err)
	}
	err = unix.Mkfifoat(int(d.Fd()), "fifo", 0o600)
	_ = d.Close()
	if err != nil {
		t.Fatalf("mkfifo: %v", err)
	}

	tests := []struct {
		name    string
		file    string
		regular bool // as the walk found it
	}{
		{name: "script", file: "run", regular: true},
		{name: "data file", file: "notes.txt", regular: true},
		{name: "empty file", file: "empty.sh", regular: true},
		{name: "unreadable file", file: "locked.sh", regular: true},
		{name: "directory", file: "sub"},
		{name: "FIFO", file: "fifo"},
		// A FIFO put where the walk found a regular file is not waited on.
		{name: "FIFO found as a regular file", file: "fifo", regular: true},
		{name: "directory found as a regular file", file: "sub", regular: true},
		{name: "vanished file", file: "missing", regular: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if tt.file == "locked.sh" && os.Geteuid() == 0 {
				t.Skip("root reads files regardless of permissions")
			}
			path := filepath.Join(dir, tt.file)
			got, err := sniffEntry(t.Context(), root, tt.file, path, tt.regular)
			defer got.close()
			fi, wantErr := root.Stat(tt.file)
			if fmt.Sprint(err) != fmt.Sprint(wantErr) {
				t.Fatalf("error: got = %v, want = %v", err, wantErr)
			}
			if wantErr != nil {
				return
			}
			want := sniffFile(t.Context(), root, tt.file, path, fi)
			defer want.close()
			if !reflect.DeepEqual(got.kind, want.kind) || fmt.Sprint(got.err) != fmt.Sprint(want.err) {
				t.Errorf("kind: got = %+v (%v), want = %+v (%v)", got.kind, got.err, want.kind, want.err)
			}
			if got.fi.Size() != want.fi.Size() || got.fi.Mode() != want.fi.Mode() {
				t.Errorf("file info: got = (%d, %v), want = (%d, %v)", got.fi.Size(), got.fi.Mode(), want.fi.Size(), want.fi.Mode())
			}
			if (got.content == nil) != (want.content == nil) || !bytes.Equal(got.content.Bytes(), want.content.Bytes()) {
				t.Errorf("contents: got = %q, want = %q", got.content.Bytes(), want.content.Bytes())
			}
		})
	}
}

func TestLoadDoesNotOpenFilesThatAreNotRegular(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("open root: %v", err)
	}
	defer root.Close()
	d, err := root.Open(".")
	if err != nil {
		t.Fatalf("open directory: %v", err)
	}
	err = unix.Mkfifoat(int(d.Fd()), "fifo", 0o600)
	_ = d.Close()
	if err != nil {
		t.Fatalf("mkfifo: %v", err)
	}
	fi, err := root.Stat("fifo")
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	s := sniffFile(t.Context(), root, "fifo", filepath.Join(dir, "fifo"), fi)
	defer s.close()
	// Opening a FIFO for reading would wait for a writer.
	if err := s.load(t.Context()); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("load: got err = %v, want the file refused as not regular", err)
	}
}
