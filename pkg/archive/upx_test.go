// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"bytes"
	"context"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestUPX_PortableHardeningCrossPlatform verifies the configured *exec.Cmd
// applies env scrubbing, Stdin nil, and WaitDelay on every supported GOOS.
// Inspection is performed without invoking cmd.Run() so the upx binary need
// not be installed on the test runner.
func TestUPX_PortableHardeningCrossPlatform(t *testing.T) {
	t.Parallel()

	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skipf("hardening invariants checked on linux/darwin only; got %s", runtime.GOOS)
	}

	tests := []struct {
		name   string
		tmpdir string
		target string
	}{
		{name: "typical inputs", tmpdir: "/tmp/mal-upx-x", target: "/tmp/mal-upx-x/in"},
		{name: "empty target", tmpdir: "/tmp/mal-upx-y", target: ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()

			cmd := buildUPXCmd(ctx, "/usr/bin/upx", tc.tmpdir, tc.target)

			if got, want := len(cmd.Env), 2; got != want {
				t.Fatalf("Env length: got %d, want %d (%v)", got, want, cmd.Env)
			}
			if cmd.Env[0] != "PATH=/usr/bin" {
				t.Errorf("Env[0]: got %q, want PATH=/usr/bin", cmd.Env[0])
			}
			if cmd.Env[1] != "LANG=C" {
				t.Errorf("Env[1]: got %q, want LANG=C", cmd.Env[1])
			}
			if cmd.Stdin != nil {
				t.Errorf("Stdin: got %v, want nil", cmd.Stdin)
			}
			if cmd.WaitDelay != upxWaitDelay {
				t.Errorf("WaitDelay: got %v, want %v", cmd.WaitDelay, upxWaitDelay)
			}
			if cmd.WaitDelay != 5*time.Second {
				t.Errorf("WaitDelay numeric: got %v, want 5s", cmd.WaitDelay)
			}
		})
	}
}

// TestUPX_NotInstalledRendersAsSkipped verifies that when UPX cannot be
// resolved, ExtractUPX returns the established ErrUPXNotFound rather than
// silently succeeding. This preserves the legitimate "UPX missing" surface
// for upstream reporting.
func TestUPX_NotInstalledRendersAsSkipped(t *testing.T) {
	t.Setenv("MALCONTENT_UPX_PATH", "/nonexistent/path/to/upx")

	tmpDir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := ExtractUPX(ctx, tmpDir, "/nonexistent/file")
	if err == nil {
		t.Fatal("expected error when UPX is not installed; got nil")
	}
	// Any "not found" / stat error path is acceptable; we only require
	// that the call surfaces the absence rather than swallowing it.
	if !strings.Contains(err.Error(), "UPX") && !strings.Contains(err.Error(), "upx") &&
		!strings.Contains(err.Error(), "not exist") && !strings.Contains(err.Error(), "no such") {
		t.Errorf("error should reference UPX absence; got %v", err)
	}
}

// TestUPX_OutputTruncationFires verifies the bounded buffer caps writes at
// the configured limit without panic or unbounded growth.
func TestUPX_OutputTruncationFires(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		writeSize int
		wantLen   int
	}{
		{name: "well under cap", writeSize: 1024, wantLen: 1024},
		{name: "exactly at cap", writeSize: upxOutputCap, wantLen: upxOutputCap},
		{name: "twice over cap", writeSize: upxOutputCap * 2, wantLen: upxOutputCap},
		{name: "ten times over cap", writeSize: upxOutputCap * 10, wantLen: upxOutputCap},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var b boundedBuffer
			b.cap = upxOutputCap

			payload := make([]byte, tc.writeSize)
			n, err := b.Write(payload)
			if err != nil {
				t.Fatalf("Write returned error: %v", err)
			}
			if n != tc.writeSize {
				t.Errorf("Write returned n=%d, want %d (must always report full input)", n, tc.writeSize)
			}
			if got := b.Len(); got != tc.wantLen {
				t.Errorf("buffered bytes: got %d, want %d", got, tc.wantLen)
			}
		})
	}
}

// TestUPX_OutputTruncationMultipleWrites simulates the streaming case where
// stdout/stderr is written in many small chunks past the cap.
func TestUPX_OutputTruncationMultipleWrites(t *testing.T) {
	t.Parallel()

	var b boundedBuffer
	b.cap = upxOutputCap

	chunk := make([]byte, 4096)
	totalAttempted := 0
	for range (upxOutputCap / 4096) * 3 { // 3x the cap
		n, err := b.Write(chunk)
		if err != nil {
			t.Fatalf("Write returned error: %v", err)
		}
		if n != len(chunk) {
			t.Errorf("Write returned n=%d, want %d", n, len(chunk))
		}
		totalAttempted += len(chunk)
	}

	if got := b.Len(); got != upxOutputCap {
		t.Errorf("buffered bytes after %d-byte streaming: got %d, want %d (cap)", totalAttempted, got, upxOutputCap)
	}
}

// TestUPX_WaitDelayConfigured verifies that buildUPXCmd returns a command
// with a positive WaitDelay (the bound applied to a stuck child after its
// context expires) and that a deadline context wired through the test
// actually expires with DeadlineExceeded. It does not exec /bin/sh; the
// command object is inspected only.
func TestUPX_WaitDelayConfigured(t *testing.T) {
	t.Parallel()

	parent := t.Context()

	cmd := buildUPXCmd(parent, "/bin/sh", t.TempDir(), "-c sleep 30")
	if cmd == nil {
		t.Fatal("buildUPXCmd returned nil")
	}
	if cmd.WaitDelay <= 0 {
		t.Errorf("WaitDelay must be positive to bound a stuck child; got %v", cmd.WaitDelay)
	}

	deadlineCtx, cancel := context.WithTimeout(parent, 50*time.Millisecond)
	defer cancel()

	<-deadlineCtx.Done()
	if deadlineCtx.Err() != context.DeadlineExceeded {
		t.Errorf("deadline context should expire with DeadlineExceeded; got %v", deadlineCtx.Err())
	}
}

// TestCopyBoundedToSandbox_LimitEnforced verifies that the streaming-copy
// helper used by ExtractUPX enforces its byte cap via io.LimitReader and
// rejects non-positive limits. Driving the helper directly with bytes.Buffer
// and bytes.Reader keeps the test off the file system and out of the
// validateUPXPath / subprocess path entirely.
func TestCopyBoundedToSandbox_LimitEnforced(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		limit   int64
		wantN   int64
		wantErr bool
	}{
		{name: "input_smaller_than_limit_writes_all", input: bytes.Repeat([]byte{0xAB}, 1024), limit: 4096, wantN: 1024},
		{name: "input_equal_to_limit_writes_all", input: bytes.Repeat([]byte{0xCD}, 4096), limit: 4096, wantN: 4096},
		{name: "input_larger_than_limit_caps_at_limit", input: bytes.Repeat([]byte{0xEF}, 8192), limit: 4096, wantN: 4096},
		{name: "zero_limit_rejected", input: []byte{0x01}, limit: 0, wantErr: true},
		{name: "negative_limit_rejected", input: []byte{0x01}, limit: -1, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var dst bytes.Buffer
			src := bytes.NewReader(tc.input)
			n, err := copyBoundedToSandbox(&dst, src, tc.limit)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if n != tc.wantN {
				t.Errorf("n=%d, want %d", n, tc.wantN)
			}
			if int64(dst.Len()) != tc.wantN {
				t.Errorf("dst.Len=%d, want %d", dst.Len(), tc.wantN)
			}
		})
	}
}
