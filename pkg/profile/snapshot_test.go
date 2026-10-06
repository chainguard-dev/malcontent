// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package profile

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// captureStderr runs fn with os.Stderr redirected to a pipe and returns what
// fn wrote there. Callers must not run in parallel because os.Stderr is
// process-wide.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	orig := os.Stderr
	t.Cleanup(func() { os.Stderr = orig })

	os.Stderr = w
	fn()
	os.Stderr = orig

	if err := w.Close(); err != nil {
		t.Fatalf("close pipe writer: %v", err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read captured stderr: %v", err)
	}
	_ = r.Close()
	return string(out)
}

func TestWriteHeapSnapshot(t *testing.T) {
	// Not parallel: the subtests redirect the process-wide os.Stderr.
	t.Run("writes a gzip-compressed heap profile", func(t *testing.T) {
		dir := t.TempDir()
		p := &Profiler{config: &Config{OutputDir: dir, FilePrefix: "snap"}}

		if stderr := captureStderr(t, p.writeHeapSnapshot); stderr != "" {
			t.Errorf("stderr: got = %q, want = empty", stderr)
		}

		matches, err := filepath.Glob(filepath.Join(dir, "snap_mem_*.pprof"))
		if err != nil {
			t.Fatalf("glob heap snapshots: %v", err)
		}
		if len(matches) != 1 {
			t.Fatalf("heap snapshots: got = %d, want = 1", len(matches))
		}
		data, err := os.ReadFile(matches[0])
		if err != nil {
			t.Fatalf("read heap snapshot: %v", err)
		}
		if !bytes.HasPrefix(data, []byte{0x1f, 0x8b}) {
			t.Errorf("heap snapshot header: got = % x, want = 1f 8b", data[:min(len(data), 2)])
		}
		// Neither the snapshot nor the directory handle used to create it
		// stays open.
		if n := profileOpenFilesUnder(t, dir); n != 0 {
			t.Errorf("files left open in the output directory: got = %d, want = 0", n)
		}
	})

	t.Run("reports a missing output directory", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "missing")
		p := &Profiler{config: &Config{OutputDir: dir, FilePrefix: "snap"}}

		const want = "failed to create heap profile"
		if stderr := captureStderr(t, p.writeHeapSnapshot); !strings.Contains(stderr, want) {
			t.Errorf("stderr: got = %q, want it to contain %q", stderr, want)
		}
		if _, err := os.Stat(dir); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("output directory stat error: got = %v, want = %v", err, fs.ErrNotExist)
		}
	})
}
