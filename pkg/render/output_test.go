// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package render

import (
	"bytes"
	"errors"
	"slices"
	"testing"
)

func TestBlockWriterWritesEachBlockOnce(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		block      string
		failAt     int
		wantWrites []string
		wantErr    error
	}{
		{name: "empty block writes nothing", block: ""},
		{name: "one-byte block is written", block: "x", wantWrites: []string{"x"}},
		{name: "block of several lines is written with one call", block: "line one\nline two\n", wantWrites: []string{"line one\nline two\n"}},
		{name: "write error is returned", block: "x", failAt: 1, wantWrites: []string{"x"}, wantErr: errRenderWrite},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			w := &renderWriteLog{failAt: tt.failAt}
			bw := &blockWriter{w: w}
			b := bytes.NewBufferString(tt.block)
			if err := bw.flush(b); !errors.Is(err, tt.wantErr) {
				t.Errorf("flush error: got = %v, want = %v", err, tt.wantErr)
			}
			got := make([]string, 0, len(w.writes))
			for _, p := range w.writes {
				got = append(got, string(p))
			}
			if !slices.Equal(got, tt.wantWrites) {
				t.Errorf("writes: got = %q, want = %q", got, tt.wantWrites)
			}
			if b.Len() != 0 {
				t.Errorf("buffer after flush: got = %q, want = empty", b.String())
			}
		})
	}
}

// testing.AllocsPerRun counts allocations process-wide, so this test does not
// run in parallel.
func TestBufferPoolKeepsBuffersUpToOneMiB(t *testing.T) {
	if raceEnabled {
		t.Skip("the race detector drops pooled buffers on purpose")
	}
	tests := []struct {
		name      string
		size      int
		wantReuse bool
	}{
		{name: "small buffer is reused", size: 64, wantReuse: true},
		{name: "buffer of exactly 1 MiB is reused", size: 1 << 20, wantReuse: true},
		{name: "buffer over 1 MiB is dropped", size: 1<<20 + 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allocs := testing.AllocsPerRun(100, func() {
				b := getBuffer()
				b.Grow(tt.size)
				putBuffer(b)
			})
			if reused := allocs == 0; reused != tt.wantReuse {
				t.Errorf("allocations per cycle: got = %v, want reuse = %v", allocs, tt.wantReuse)
			}
		})
	}
}
