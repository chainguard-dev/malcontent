// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package render

import (
	"fmt"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

// ptyTerminal opens a pseudo-terminal sized to cols columns and returns its
// terminal end. It skips the test where pseudo-terminals are unavailable.
func ptyTerminal(t *testing.T, cols uint16) *os.File {
	t.Helper()
	ptmx, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("open /dev/ptmx: %v", err)
	}
	t.Cleanup(func() { _ = ptmx.Close() })
	if err := unix.IoctlSetPointerInt(int(ptmx.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		t.Skipf("unlock the pseudo-terminal: %v", err)
	}
	n, err := unix.IoctlGetUint32(int(ptmx.Fd()), unix.TIOCGPTN)
	if err != nil {
		t.Skipf("number the pseudo-terminal: %v", err)
	}
	pts, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("open the pseudo-terminal: %v", err)
	}
	t.Cleanup(func() { _ = pts.Close() })
	if err := unix.IoctlSetWinsize(int(pts.Fd()), unix.TIOCSWINSZ, &unix.Winsize{Row: 24, Col: cols}); err != nil {
		t.Fatalf("set the terminal size: got err = %v, want = nil", err)
	}
	return pts
}

// ptyWithStdin runs fn with f as standard input, file descriptor 0.
func ptyWithStdin(t *testing.T, f *os.File, fn func()) {
	t.Helper()
	saved, err := unix.Dup(0)
	if err != nil {
		t.Skipf("duplicate standard input: %v", err)
	}
	defer func() {
		if err := unix.Dup2(saved, 0); err != nil {
			t.Errorf("restore standard input: got err = %v, want = nil", err)
		}
		_ = unix.Close(saved)
	}()
	if err := unix.Dup2(int(f.Fd()), 0); err != nil {
		t.Fatalf("replace standard input: got err = %v, want = nil", err)
	}
	fn()
}

// Replacing file descriptor 0 affects the whole process, so this test does
// not run in parallel.
func TestSuggestedWidthFollowsTheTerminal(t *testing.T) {
	tests := []struct {
		name string
		cols uint16
		want int
	}{
		{name: "wide terminal", cols: 200, want: 200},
		{name: "terminal one column over the minimum", cols: 76, want: 76},
		{name: "terminal at the minimum", cols: 75, want: 75},
		{name: "terminal one column under the minimum", cols: 74, want: 75},
		{name: "terminal without a size", cols: 0, want: 75},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pts := ptyTerminal(t, tt.cols)
			var got int
			ptyWithStdin(t, pts, func() { got = suggestedWidth() })
			if got != tt.want {
				t.Errorf("suggestedWidth: got = %d, want = %d", got, tt.want)
			}
		})
	}
	t.Run("standard input that is not a terminal", func(t *testing.T) {
		f, err := os.Open(os.DevNull)
		if err != nil {
			t.Fatalf("open %s: got err = %v, want = nil", os.DevNull, err)
		}
		t.Cleanup(func() { _ = f.Close() })
		var got int
		ptyWithStdin(t, f, func() { got = suggestedWidth() })
		if got != 160 {
			t.Errorf("suggestedWidth: got = %d, want = 160", got)
		}
	})
}
