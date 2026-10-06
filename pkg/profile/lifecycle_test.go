// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package profile

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"runtime/trace"
	"strings"
	"testing"
	"testing/synctest"
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

// checkStopped verifies that the stopped profiler p left one file of each
// profile kind in dir under prefix, wrote the final heap profile, and closed
// every file it opened there.
func checkStopped(t *testing.T, p *Profiler, dir, prefix string) {
	t.Helper()
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

	if n := profileOpenFilesUnder(t, dir); n != 0 {
		t.Errorf("files left open in %s: got = %d, want = 0", dir, n)
	}
}

// checkProfilerRun starts profiling with cfg, stops it, verifies that Stop
// reported nothing, and checks the result with checkStopped.
func checkProfilerRun(t *testing.T, cfg *Config, dir, prefix string) {
	t.Helper()
	p, err := StartProfiling(t.Context(), cfg)
	if err != nil {
		t.Fatalf("StartProfiling: %v", err)
	}
	if stderr := captureStderr(t, p.Stop); stderr != "" {
		t.Errorf("Stop stderr: got = %q, want = empty", stderr)
	}
	checkStopped(t, p, dir, prefix)
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

// waitForGlob polls until pattern matches at least one file or timeout has
// passed.
func waitForGlob(t *testing.T, pattern string, timeout time.Duration) {
	t.Helper()
	deadline := time.After(timeout)
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatalf("glob %s: %v", pattern, err)
		}
		if len(matches) > 0 {
			return
		}
		select {
		case <-deadline:
			return
		case <-tick.C:
		}
	}
}

func TestStartProfilingHeapSnapshots(t *testing.T) {
	// Not parallel: the CPU profiler, the execution tracer, and os.Stderr are
	// process-wide.
	tests := []struct {
		name     string
		interval time.Duration
		want     bool
	}{
		{"one nanosecond interval takes periodic snapshots", time.Nanosecond, true},
		{"zero interval takes none", 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			p, err := StartProfiling(t.Context(), &Config{OutputDir: dir, FilePrefix: "snap", SampleInterval: tt.interval})
			if err != nil {
				t.Fatalf("StartProfiling: %v", err)
			}
			pattern := filepath.Join(dir, "snap_mem_[0-9]*.pprof")
			if tt.want {
				waitForGlob(t, pattern, 10*time.Second)
			}
			if stderr := captureStderr(t, p.Stop); stderr != "" {
				t.Errorf("Stop stderr: got = %q, want = empty", stderr)
			}
			checkStopped(t, p, dir, "snap")

			// Stop waits for the snapshot goroutine, so every snapshot is
			// complete by now.
			matches, err := filepath.Glob(pattern)
			if err != nil {
				t.Fatalf("glob heap snapshots: %v", err)
			}
			if got := len(matches) > 0; got != tt.want {
				t.Fatalf("heap snapshots taken: got = %v (%d files), want = %v", got, len(matches), tt.want)
			}
			for _, m := range matches {
				data, err := os.ReadFile(m)
				if err != nil {
					t.Fatalf("read heap snapshot: %v", err)
				}
				if !bytes.HasPrefix(data, []byte{0x1f, 0x8b}) {
					t.Errorf("%s header: got = % x, want = 1f 8b", filepath.Base(m), data[:min(len(data), 2)])
				}
			}
		})
	}
}

// profileGoroutineCount counts the goroutines whose stacks include fn.
func profileGoroutineCount(fn string) int {
	buf := make([]byte, 64<<10)
	n := runtime.Stack(buf, true)
	for n == len(buf) {
		buf = make([]byte, 2*len(buf))
		n = runtime.Stack(buf, true)
	}
	count := 0
	// runtime.Stack separates goroutines with a blank line.
	for g := range bytes.SplitSeq(buf[:n], []byte("\n\n")) {
		if bytes.Contains(g, []byte(fn)) {
			count++
		}
	}
	return count
}

// waitForGoroutineCount polls until exactly want goroutines include fn in
// their stacks or timeout has passed, and returns the last count.
func waitForGoroutineCount(t *testing.T, fn string, want int, timeout time.Duration) int {
	t.Helper()
	deadline := time.After(timeout)
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		got := profileGoroutineCount(fn)
		if got == want {
			return got
		}
		select {
		case <-deadline:
			return got
		case <-tick.C:
		}
	}
}

func TestStartProfilingRunsBackgroundWorkers(t *testing.T) {
	// Not parallel: the CPU profiler and the execution tracer are
	// process-wide, and parallel tests run their own workers.
	tests := []struct {
		name     string
		worker   string // method each worker goroutine runs
		interval time.Duration
	}{
		{"goroutine dump worker runs while profiling", "(*Profiler).profileGoroutines", 0},
		// An hour-long interval keeps the worker running without taking a
		// snapshot during the test.
		{"heap snapshot worker runs while profiling", "(*Profiler).periodicHeapProfile", time.Hour},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := profileGoroutineCount(tt.worker)
			p, err := StartProfiling(t.Context(), &Config{OutputDir: t.TempDir(), FilePrefix: "workers", SampleInterval: tt.interval})
			if err != nil {
				t.Fatalf("StartProfiling: %v", err)
			}
			t.Cleanup(p.Stop)

			// The worker starts on its own goroutine, so it may not be
			// running yet when StartProfiling returns.
			if got := waitForGoroutineCount(t, tt.worker, before+1, 10*time.Second); got != before+1 {
				t.Errorf("%s goroutines while profiling: got = %d, want = %d", tt.worker, got, before+1)
			}

			// Stop waits for the workers, so none is left once it returns.
			p.Stop()
			if got := profileGoroutineCount(tt.worker); got != before {
				t.Errorf("%s goroutines after Stop: got = %d, want = %d", tt.worker, got, before)
			}
		})
	}
}

func TestStopReportsFinalHeapProfileFailure(t *testing.T) {
	// Not parallel: os.Stderr is redirected. A profiler whose files were never
	// opened cannot write the final heap profile.
	p := &Profiler{cancel: func() {}}

	const want = "failed to write final heap profile"
	if stderr := captureStderr(t, p.Stop); !strings.Contains(stderr, want) {
		t.Errorf("Stop stderr: got = %q, want it to contain %q", stderr, want)
	}
}

func TestStopWaitsForBackgroundWork(t *testing.T) {
	// Not parallel: Stop stops the process-wide CPU profiler and tracer.
	synctest.Test(t, func(t *testing.T) {
		mem, err := os.Create(filepath.Join(t.TempDir(), "mem.pprof"))
		if err != nil {
			t.Fatalf("create memory profile: %v", err)
		}
		ctx, cancel := context.WithCancel(t.Context())
		p := &Profiler{memFile: mem, ctx: ctx, cancel: cancel}

		release := make(chan struct{})
		p.workers.Go(func() {
			<-ctx.Done()
			<-release
		})

		stopped := make(chan struct{})
		go func() {
			p.Stop()
			close(stopped)
		}()
		synctest.Wait()

		if err := ctx.Err(); !errors.Is(err, context.Canceled) {
			t.Errorf("context while Stop waits: got error = %v, want = %v", err, context.Canceled)
			cancel()
		}
		select {
		case <-stopped:
			t.Error("Stop: returned while background work was running, want it to wait")
		default:
		}
		if _, err := mem.Stat(); err != nil {
			t.Errorf("memory profile while Stop waits: got stat error = %v, want the file still open", err)
		}

		close(release)
		<-stopped
		if _, err := mem.Stat(); !errors.Is(err, os.ErrClosed) {
			t.Errorf("memory profile after Stop: got stat error = %v, want = %v", err, os.ErrClosed)
		}
	})
}

func TestProfileGoroutinesInterval(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "goroutines.txt")
		f, err := os.Create(path)
		if err != nil {
			t.Fatalf("create %s: %v", path, err)
		}
		t.Cleanup(func() { _ = f.Close() })

		ctx, cancel := context.WithCancel(t.Context())
		p := &Profiler{goroutFile: f, ctx: ctx}
		p.workers.Go(p.profileGoroutines)

		// The bubble's clock is fake: each step advances it at once and
		// returns when the dump goroutine is idle again.
		steps := []struct {
			name    string
			advance time.Duration
			want    int
		}{
			{"just before the first interval", 5*time.Second - time.Nanosecond, 0},
			{"at the first interval", time.Nanosecond, 1},
			{"at the second interval", 5 * time.Second, 2},
		}
		for _, s := range steps {
			synctest.Sleep(s.advance)
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			if got := strings.Count(string(data), "\n--- Goroutine dump at "); got != s.want {
				t.Errorf("dumps %s: got = %d, want = %d", s.name, got, s.want)
			}
		}

		cancel()
		p.workers.Wait()
	})
}

// errWriteRefused is the error failingWriter returns.
var errWriteRefused = errors.New("write refused")

// failingWriter accepts its first accept writes and refuses every later one.
type failingWriter struct {
	accept int
	writes int
}

func (w *failingWriter) Write(b []byte) (int, error) {
	w.writes++
	if w.writes > w.accept {
		return 0, errWriteRefused
	}
	return len(b), nil
}

func TestWriteGoroutineDump(t *testing.T) {
	// Not parallel: os.Stderr is redirected.
	if maxStackBuf != 64<<20 {
		t.Errorf("maxStackBuf: got = %d, want = %d", maxStackBuf, 64<<20)
	}

	tests := []struct {
		name      string
		bufLen    int
		bufCap    int
		limit     int
		wantReuse bool
		wantFull  bool
		wantLen   int
	}{
		{"dump that fits reuses the scratch buffer", 1 << 20, 1 << 20, maxStackBuf, true, true, 0},
		{"scratch buffer shortened by the previous dump is reused in full", 16, 1 << 20, maxStackBuf, true, true, 0},
		{"small scratch buffer grows until the dump fits", 16, 16, 1 << 20, false, true, 0},
		{"dump is cut where doubling would pass the limit", 16, 16, 64, false, false, 64},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			var got []byte
			stderr := captureStderr(t, func() { got = writeGoroutineDump(&out, make([]byte, tt.bufLen, tt.bufCap), tt.limit) })
			if stderr != "" {
				t.Errorf("stderr: got = %q, want = empty", stderr)
			}

			data := out.String()
			const header = "\n--- Goroutine dump at "
			rest, ok := strings.CutPrefix(data, header)
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
			if reused := cap(got) == tt.bufCap; reused != tt.wantReuse {
				t.Errorf("scratch buffer reused: got = %v (cap %d), want = %v", reused, cap(got), tt.wantReuse)
			}
		})
	}

	failures := []struct {
		name       string
		accept     int
		wantStderr string
		wantWrites int
	}{
		{"failed timestamp write skips the dump", 0, "failed to write goroutine timestamp: write refused\n", 1},
		{"failed dump write is reported", 1, "failed to write goroutine dump: write refused\n", 2},
	}

	for _, tt := range failures {
		t.Run(tt.name, func(t *testing.T) {
			w := &failingWriter{accept: tt.accept}
			buf := make([]byte, 1<<20)
			var got []byte
			stderr := captureStderr(t, func() { got = writeGoroutineDump(w, buf, maxStackBuf) })
			if stderr != tt.wantStderr {
				t.Errorf("stderr: got = %q, want = %q", stderr, tt.wantStderr)
			}
			if w.writes != tt.wantWrites {
				t.Errorf("write calls: got = %d, want = %d", w.writes, tt.wantWrites)
			}
			if cap(got) != cap(buf) {
				t.Errorf("returned scratch buffer cap: got = %d, want = %d", cap(got), cap(buf))
			}
		})
	}
}

// profileOpenFilesUnder counts this process's open file descriptors that refer
// to dir itself or to paths beneath it. It reads /proc/self/fd and skips the
// test where that is unavailable.
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
		if err == nil && (target == resolved || strings.HasPrefix(target, prefix)) {
			n++
		}
	}
	return n
}

// occupy returns a setup that puts a directory where the profile file name
// belongs, so creating that file fails.
func occupy(name string) func(t *testing.T, dir string) {
	return func(t *testing.T, dir string) {
		t.Helper()
		if err := os.Mkdir(filepath.Join(dir, name), 0o700); err != nil {
			t.Fatalf("mkdir %s: %v", name, err)
		}
	}
}

func TestStartProfilingCleansUpAfterFailure(t *testing.T) {
	// Not parallel: the CPU profiler and the execution tracer are
	// process-wide, and two subtests occupy one of them on purpose.
	tests := []struct {
		name      string
		setup     func(t *testing.T, dir string)
		outputDir string // relative to the subtest's temporary directory
		wantErr   string
	}{
		{
			name: "output directory cannot be created",
			setup: func(t *testing.T, dir string) {
				t.Helper()
				// A regular file where a parent directory belongs.
				if err := os.WriteFile(filepath.Join(dir, "blocked"), nil, 0o600); err != nil {
					t.Fatalf("write blocking file: %v", err)
				}
			},
			outputDir: filepath.Join("blocked", "profiles"),
			wantErr:   "failed to create profile directory",
		},
		{
			name:    "CPU profile file cannot be created",
			setup:   occupy("fail_cpu.pprof"),
			wantErr: "failed to create CPU profile",
		},
		{
			// Creating the final heap profile fails after the CPU profile
			// file is already open.
			name:    "memory profile file cannot be created",
			setup:   occupy("fail_mem_final.pprof"),
			wantErr: "failed to create memory profile",
		},
		{
			name:    "trace file cannot be created",
			setup:   occupy("fail_trace.out"),
			wantErr: "failed to create trace file",
		},
		{
			name:    "goroutine profile file cannot be created",
			setup:   occupy("fail_goroutines.txt"),
			wantErr: "failed to create goroutine profile",
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
				p, err = StartProfiling(t.Context(), &Config{OutputDir: filepath.Join(dir, tt.outputDir), FilePrefix: "fail"})
			})
			if p != nil {
				// Release the process-wide profilers for the tests that follow.
				captureStderr(t, p.Stop)
				t.Error("StartProfiling() profiler: got = non-nil, want = nil")
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("StartProfiling() error: got = %v, want one containing %q", err, tt.wantErr)
			}
			if n := profileOpenFilesUnder(t, dir); n != 0 {
				t.Errorf("profile files left open: got = %d, want = 0", n)
			}
		})
	}
}
