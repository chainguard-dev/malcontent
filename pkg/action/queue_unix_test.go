// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package action

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
)

// TestScanPassesOverFIFOsNamedLikeArchives checks that a FIFO named like an
// archive is neither opened for extraction, which blocks until a writer
// appears, nor read, while the rest of the scan path is scanned.
func TestScanPassesOverFIFOsNamedLikeArchives(t *testing.T) {
	t.Parallel()
	yrs, rfs := scanTestRules(t)

	tests := []struct {
		name string
		fifo string
	}{
		{name: "a FIFO named .tar.gz", fifo: "x.tar.gz"},
		{name: "a FIFO named .zip", fifo: "x.zip"},
		{name: "a FIFO named .upx", fifo: "x.upx"},
		{name: "a FIFO with no archive name", fifo: "x.sh"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := diffTestTempDir(t)
			fifo := filepath.Join(dir, tt.fifo)
			if err := syscall.Mkfifo(fifo, 0o600); err != nil {
				t.Skipf("mkfifo: %v", err)
			}
			flagged := scanTestWriteFile(t, filepath.Join(dir, "flagged.sh"), []byte(diffTestShellPayload("fifo")))
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()
			// Should the scan block on the FIFO, writers unblock it after a
			// while, so that the test ends and reports the wait.
			const grace = 10 * time.Second
			done := make(chan struct{})
			var wg sync.WaitGroup
			wg.Go(func() {
				select {
				case <-done:
					return
				case <-time.After(grace):
				}
				for {
					select {
					case <-done:
						return
					case <-time.After(50 * time.Millisecond):
						if w, err := os.OpenFile(fifo, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
							_ = w.Close()
						}
					}
				}
			})

			start := time.Now()
			c := malcontent.Config{Concurrency: 2, Rules: yrs, RuleFS: rfs, ScanPaths: []string{dir}}
			r, err := Scan(ctx, c)
			close(done)
			wg.Wait()
			if err != nil {
				t.Fatalf("Scan: %v", err)
			}
			if elapsed := time.Since(start); elapsed >= grace {
				t.Errorf("scan time: got = %v, want the FIFO passed over without waiting", elapsed)
			}
			if fr, ok := r.Files.Load(flagged); !ok || len(fr.Behaviors) == 0 {
				t.Errorf("report of %s: got = %+v, want its behaviors", flagged, fr)
			}
			if fr, ok := r.Files.Load(fifo); ok && fr.Skipped == "" {
				t.Errorf("report of the FIFO: got = %+v, want it skipped or absent", fr)
			}
		})
	}
}
