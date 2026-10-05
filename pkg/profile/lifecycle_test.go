// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package profile

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime/pprof"
	"runtime/trace"
	"strings"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	t.Parallel()
	c := DefaultConfig()
	if c.OutputDir != "profiles" {
		t.Errorf("OutputDir: got = %q, want = %q", c.OutputDir, "profiles")
	}
	if !strings.HasPrefix(c.FilePrefix, "profile_") {
		t.Errorf("FilePrefix: got = %q, want prefix %q", c.FilePrefix, "profile_")
	}
	if c.SampleInterval != 5*time.Second {
		t.Errorf("SampleInterval: got = %v, want = %v", c.SampleInterval, 5*time.Second)
	}
}

// checkProfilerRun starts profiling with cfg and stops it, then verifies that
// one file of each profile kind landed in dir under prefix, that Stop reported
// nothing, and that Stop closed every file.
func checkProfilerRun(t *testing.T, cfg *Config, dir, prefix string) {
	t.Helper()
	p, err := StartProfiling(t.Context(), cfg)
	if err != nil {
		t.Fatalf("StartProfiling: %v", err)
	}
	if stderr := captureStderr(t, p.Stop); stderr != "" {
		t.Errorf("Stop stderr: got = %q, want = empty", stderr)
	}

	for _, suffix := range []string{"_cpu.pprof", "_mem_final.pprof", "_trace.out", "_goroutines.txt"} {
		matches, err := filepath.Glob(filepath.Join(dir, prefix+"*"+suffix))
		if err != nil {
			t.Fatalf("glob %s: %v", suffix, err)
		}
		if len(matches) != 1 {
			t.Errorf("%s files in %s: got = %v, want exactly one", suffix, dir, matches)
		}
	}

	heap, err := os.ReadFile(p.memFile.Name())
	if err != nil {
		t.Fatalf("read final heap profile: %v", err)
	}
	if !bytes.HasPrefix(heap, []byte{0x1f, 0x8b}) {
		t.Errorf("final heap profile header: got = % x, want = 1f 8b", heap[:min(len(heap), 2)])
	}

	for _, f := range []*os.File{p.cpuFile, p.memFile, p.traceFile, p.goroutFile} {
		if _, err := f.Write([]byte("x")); !errors.Is(err, os.ErrClosed) {
			t.Errorf("write to %s after Stop: got error = %v, want = %v", filepath.Base(f.Name()), err, os.ErrClosed)
		}
	}
}

func TestStartProfilingWritesProfiles(t *testing.T) {
	// Not parallel: the CPU profiler, the execution tracer, and os.Stderr are
	// process-wide, and one subtest changes the working directory.
	t.Run("custom configuration", func(t *testing.T) {
		dir := t.TempDir()
		// A zero sample interval turns off periodic heap snapshots.
		checkProfilerRun(t, &Config{OutputDir: dir, FilePrefix: "custom", SampleInterval: 0}, dir, "custom")
	})

	t.Run("nil configuration uses the defaults", func(t *testing.T) {
		dir := t.TempDir()
		t.Chdir(dir)
		checkProfilerRun(t, nil, filepath.Join(dir, "profiles"), "profile_")
	})
}

func TestStopReportsFinalHeapProfileFailure(t *testing.T) {
	// Not parallel: os.Stderr is redirected. A profiler whose files were never
	// opened cannot write the final heap profile.
	p := &Profiler{cancel: func() {}, stopChan: make(chan struct{})}

	const want = "failed to write final heap profile"
	if stderr := captureStderr(t, p.Stop); !strings.Contains(stderr, want) {
		t.Errorf("Stop stderr: got = %q, want it to contain %q", stderr, want)
	}
}

func TestWriteGoroutineDump(t *testing.T) {
	// Not parallel: os.Stderr is redirected.
	if maxStackBuf != 64<<20 {
		t.Errorf("maxStackBuf: got = %d, want = %d", maxStackBuf, 64<<20)
	}

	tests := []struct {
		name      string
		bufSize   int
		limit     int
		wantReuse bool
		wantFull  bool
		wantLen   int
	}{
		{"dump that fits reuses the scratch buffer", 1 << 20, maxStackBuf, true, true, 0},
		{"small scratch buffer grows until the dump fits", 16, 1 << 20, false, true, 0},
		{"dump is cut where doubling would pass the limit", 16, 64, false, false, 64},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "goroutines.txt")
			f, err := os.Create(path)
			if err != nil {
				t.Fatalf("create %s: %v", path, err)
			}
			t.Cleanup(func() { _ = f.Close() })
			p := &Profiler{goroutFile: f}

			var got []byte
			stderr := captureStderr(t, func() { got = p.writeGoroutineDump(make([]byte, tt.bufSize), tt.limit) })
			if stderr != "" {
				t.Errorf("stderr: got = %q, want = empty", stderr)
			}

			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			const header = "\n--- Goroutine dump at "
			rest, ok := strings.CutPrefix(string(data), header)
			if !ok {
				t.Fatalf("dump header: got = %q, want prefix %q", data[:min(len(data), len(header))], header)
			}
			_, dump, ok := strings.Cut(rest, " ---\n")
			if !ok {
				t.Fatalf("dump header terminator missing in %q", rest)
			}
			if dump != string(got) {
				t.Errorf("written dump: got %d bytes, want the %d returned bytes", len(dump), len(got))
			}
			if tt.wantLen > 0 && len(dump) != tt.wantLen {
				t.Errorf("dump length: got = %d, want = %d", len(dump), tt.wantLen)
			}
			// Unused scratch space past the end of the dump is zeroed, so a
			// NUL byte means the dump was written at the buffer's size rather
			// than at the length runtime.Stack reported.
			if i := strings.IndexByte(dump, 0); i >= 0 {
				t.Errorf("dump: got a NUL byte at offset %d of %d, want only stack text", i, len(dump))
			}
			if tt.wantFull && !strings.Contains(dump, "TestWriteGoroutineDump") {
				t.Errorf("dump: got %d bytes without this test's goroutine, want the complete dump", len(dump))
			}
			if tt.wantFull && !strings.HasSuffix(dump, "\n") {
				t.Errorf("dump: got %q at its end, want it to end with a newline", dump[max(0, len(dump)-16):])
			}
			if reused := cap(got) == tt.bufSize; reused != tt.wantReuse {
				t.Errorf("scratch buffer reused: got = %v (cap %d), want = %v", reused, cap(got), tt.wantReuse)
			}
		})
	}

	t.Run("failed timestamp write skips the dump", func(t *testing.T) {
		f, err := os.Create(filepath.Join(t.TempDir(), "goroutines.txt"))
		if err != nil {
			t.Fatalf("create goroutine file: %v", err)
		}
		if err := f.Close(); err != nil {
			t.Fatalf("close goroutine file: %v", err)
		}
		p := &Profiler{goroutFile: f}

		stderr := captureStderr(t, func() { p.writeGoroutineDump(make([]byte, 1<<20), maxStackBuf) })
		if !strings.Contains(stderr, "failed to write goroutine timestamp") {
			t.Errorf("stderr: got = %q, want a timestamp write failure", stderr)
		}
		if strings.Contains(stderr, "failed to write goroutine dump") {
			t.Errorf("stderr: got = %q, want no dump write attempt", stderr)
		}
	})
}

// profileOpenFilesUnder counts this process's open file descriptors that refer
// to paths beneath dir. It reads /proc/self/fd and skips the test where that
// is unavailable.
func profileOpenFilesUnder(t *testing.T, dir string) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skipf("open file descriptors are not listable: %v", err)
	}
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatalf("EvalSymlinks(%q): %v", dir, err)
	}
	prefix := resolved + string(filepath.Separator)
	n := 0
	for _, e := range entries {
		target, err := os.Readlink(filepath.Join("/proc/self/fd", e.Name()))
		if err == nil && strings.HasPrefix(target, prefix) {
			n++
		}
	}
	return n
}

func TestStartProfilingCleansUpAfterFailure(t *testing.T) {
	// Not parallel: the CPU profiler and the execution tracer are
	// process-wide, and two subtests occupy one of them on purpose.
	tests := []struct {
		name    string
		setup   func(t *testing.T, dir string)
		wantErr string
	}{
		{
			name: "profile file cannot be created",
			setup: func(t *testing.T, dir string) {
				t.Helper()
				// A directory where the final heap profile belongs fails its
				// creation after the CPU profile file is already open.
				if err := os.Mkdir(filepath.Join(dir, "fail_mem_final.pprof"), 0o700); err != nil {
					t.Fatalf("mkdir: %v", err)
				}
			},
			wantErr: "failed to create memory profile",
		},
		{
			name: "CPU profiler already running",
			setup: func(t *testing.T, _ string) {
				t.Helper()
				if err := pprof.StartCPUProfile(io.Discard); err != nil {
					t.Fatalf("StartCPUProfile: %v", err)
				}
				t.Cleanup(pprof.StopCPUProfile)
			},
			wantErr: "failed to start CPU profile",
		},
		{
			name: "execution tracer already running",
			setup: func(t *testing.T, _ string) {
				t.Helper()
				if err := trace.Start(io.Discard); err != nil {
					t.Fatalf("trace.Start: %v", err)
				}
				t.Cleanup(trace.Stop)
				t.Cleanup(pprof.StopCPUProfile)
			},
			wantErr: "failed to start trace",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			tt.setup(t, dir)

			var p *Profiler
			var err error
			// A failed start stops the profiler, which reports the final heap
			// profile it could not write when that file was never opened.
			captureStderr(t, func() {
				p, err = StartProfiling(t.Context(), &Config{OutputDir: dir, FilePrefix: "fail"})
			})
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("StartProfiling() error: got = %v, want one containing %q", err, tt.wantErr)
			}
			if p != nil {
				t.Error("StartProfiling() profiler: got = non-nil, want = nil")
			}
			if n := profileOpenFilesUnder(t, dir); n != 0 {
				t.Errorf("profile files left open: got = %d, want = 0", n)
			}
		})
	}
}
