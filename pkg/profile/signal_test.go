// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package profile

import (
	"os"
	"os/signal"
	"syscall"
	"testing"
	"time"
)

func TestStartProfilingStopsOnSignal(t *testing.T) {
	// Not parallel: the CPU profiler, the execution tracer, and signal
	// delivery are process-wide.
	dir := t.TempDir()

	// The test's own registration keeps SIGTERM from ending the test binary
	// even when the profiler does not catch it.
	held := make(chan os.Signal, 1)
	signal.Notify(held, syscall.SIGTERM)
	t.Cleanup(func() { signal.Stop(held) })

	p, err := StartProfiling(t.Context(), &Config{OutputDir: dir, FilePrefix: "signal"})
	if err != nil {
		t.Fatalf("StartProfiling: %v", err)
	}
	t.Cleanup(p.Stop)

	// StartProfiling registers for signals before it returns, so one signal
	// sent now is enough.
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatalf("send SIGTERM: %v", err)
	}
	select {
	case <-p.ctx.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("profiler: still running 10s after SIGTERM, want it stopped")
	}

	// Stop returns only once the stop the signal began has finished.
	p.Stop()
	checkStopped(t, p, dir, "signal")
}
