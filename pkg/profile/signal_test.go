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

func TestHandleSignalsStopsRelayingSignals(t *testing.T) {
	// Not parallel: the CPU profiler and the execution tracer are
	// process-wide.
	tests := []struct {
		name string
		// signal ends the profiler with a signal rather than Stop.
		signal bool
	}{
		{"after the signal that stops the profiler", true},
		{"after the profiler stops without a signal", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := StartProfiling(t.Context(), &Config{OutputDir: t.TempDir(), FilePrefix: "relay"})
			if err != nil {
				t.Fatalf("StartProfiling: %v", err)
			}
			t.Cleanup(p.Stop)
			sigChan := make(chan os.Signal, 1)
			var stopped []chan<- os.Signal
			done := make(chan struct{})
			go func() {
				defer close(done)
				p.handleSignals(sigChan, func(c chan<- os.Signal) { stopped = append(stopped, c) })
			}()

			if tt.signal {
				sigChan <- syscall.SIGTERM
			} else {
				p.Stop()
			}
			<-done

			// Stopping the relay leaves a later signal to its default action.
			if len(stopped) != 1 || stopped[0] != chan<- os.Signal(sigChan) {
				t.Errorf("signal relay stops: got = %v, want = one stop of the signal channel", stopped)
			}
		})
	}
}
