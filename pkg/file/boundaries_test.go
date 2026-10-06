// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package file

import (
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
)

// fileRecordWarnings swaps the package warning function for a recorder for
// the rest of the test and returns a function listing the recorded messages.
// Callers must not run in parallel because the warning function is a package
// variable.
func fileRecordWarnings(t *testing.T) func() []string {
	t.Helper()
	var (
		mu   sync.Mutex
		msgs []string
	)
	prev := logWarn
	logWarn = func(msg string, _ ...any) {
		mu.Lock()
		defer mu.Unlock()
		msgs = append(msgs, msg)
	}
	t.Cleanup(func() { logWarn = prev })
	return func() []string {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(msgs)
	}
}

func TestArchiveCounter_CapBoundaries(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		maxBytes   int64
		maxRatio   float64
		inputBytes int64
		writes     []int
		wantErr    error
	}{
		{"total equal to MaxBytes is allowed", 100, 0, 0, []int{60, 40}, nil},
		{"one byte over MaxBytes is rejected", 100, 0, 0, []int{100, 1}, ErrArchiveBytesCap},
		{"total equal to a one-byte MaxBytes is allowed", 1, 0, 0, []int{1}, nil},
		{"one byte over a one-byte MaxBytes is rejected", 1, 0, 0, []int{1, 1}, ErrArchiveBytesCap},
		{"negative MaxBytes disables the byte cap", -1, 0, 0, []int{1 << 20}, nil},
		{"zero InputBytes disables the ratio cap", 0, 2, 0, []int{1 << 20}, nil},
		{"negative InputBytes disables the ratio cap", 0, 2, -1, []int{1 << 20}, nil},
		{"total at the ratio threshold of a one-byte input is allowed", 0, 2, 1, []int{2}, nil},
		{"one byte past the ratio threshold of a one-byte input is rejected", 0, 2, 1, []int{2, 1}, ErrArchiveRatioCap},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c := &ArchiveCounter{MaxBytes: tt.maxBytes, MaxRatio: tt.maxRatio, InputBytes: tt.inputBytes}
			var err error
			for _, n := range tt.writes {
				if err = c.Add(n); err != nil {
					break
				}
			}
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("Add() error: got = %v, want = %v", err, tt.wantErr)
			}
		})
	}
}

func TestArchiveCounter_WarnsWhenRatioCapCannotFire(t *testing.T) {
	// Not parallel: the package warning function is swapped for a recorder.
	const warning = "archive ratio cap disabled"
	tests := []struct {
		name       string
		maxRatio   float64
		inputBytes int64
		wantWarn   bool
	}{
		// 2 * 2^62 is exactly 2^63, the float64 value of math.MaxInt64; no
		// int64 total can exceed it.
		{"threshold at the int64 limit", 2, 1 << 62, true},
		{"threshold below the int64 limit", 1, 1 << 62, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			warnings := fileRecordWarnings(t)

			c := &ArchiveCounter{MaxRatio: tt.maxRatio, InputBytes: tt.inputBytes}
			if err := c.Add(1 << 40); err != nil {
				t.Fatalf("Add(1<<40) error: got = %v, want = nil", err)
			}
			got := warnings()
			warned := slices.ContainsFunc(got, func(msg string) bool { return strings.Contains(msg, warning) })
			if warned != tt.wantWarn {
				t.Errorf("ratio cap warning logged: got = %v, want = %v (warnings %q)", warned, tt.wantWarn, got)
			}
		})
	}
}
