// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/chainguard-dev/malcontent/pkg/programkind"
)

const upxStandInPayload = "stand-in for a packed binary\n"

func TestUPXBoundedBufferRetention(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		limit  int
		writes []string
		want   string
	}{
		{name: "writes within capacity are kept whole", limit: 8, writes: []string{"abc", "de"}, want: "abcde"},
		{name: "write exactly filling capacity is kept whole", limit: 5, writes: []string{"abcde"}, want: "abcde"},
		{name: "single write past capacity keeps its leading bytes", limit: 4, writes: []string{"abcdef"}, want: "abcd"},
		{name: "later write is cut to the room that remains", limit: 5, writes: []string{"abc", "defg"}, want: "abcde"},
		{name: "writes after capacity is reached are dropped", limit: 3, writes: []string{"abc", "xyz"}, want: "abc"},
		{name: "zero capacity keeps nothing", limit: 0, writes: []string{"abc"}, want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			b := &boundedBuffer{cap: tt.limit}
			for _, w := range tt.writes {
				n, err := b.Write([]byte(w))
				if err != nil {
					t.Fatalf("Write(%q) error: got = %v, want = nil", w, err)
				}
				if n != len(w) {
					t.Errorf("Write(%q) count: got = %d, want = %d", w, n, len(w))
				}
			}
			if got := b.String(); got != tt.want {
				t.Errorf("retained: got = %q, want = %q", got, tt.want)
			}
		})
	}
}

// upxStandIn writes a shell script that stands in for upx: it ignores its
// arguments, prints stdout and stderr, and exits with code.
func upxStandIn(t *testing.T, stdout, stderr string, code int) string {
	t.Helper()
	return upxStandInScript(t, fmt.Sprintf("#!/bin/sh\necho %q\necho %q >&2\nexit %d\n", stdout, stderr, code))
}

// upxStandInScript writes script as an executable stand-in for upx, skipping
// the test when the temporary directory does not allow executing files.
func upxStandInScript(t *testing.T, script string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "upx")
	if err := os.WriteFile(p, []byte(script), 0o700); err != nil {
		t.Fatalf("write upx stand-in: %v", err)
	}
	if err := exec.CommandContext(t.Context(), p).Run(); errors.Is(err, fs.ErrPermission) {
		t.Skipf("temporary directory does not allow executing files: %v", err)
	}
	return p
}

// TestExtractUPXOperatorBinary runs ExtractUPX against a stand-in named by
// MALCONTENT_UPX_PATH, so every outcome of the upx run is deterministic and
// no real upx is needed. Setting the environment rules out t.Parallel.
func TestExtractUPXOperatorBinary(t *testing.T) {
	const unpacked = "Unpacked 1 file."

	// wantErr lists substrings the error must contain; an empty list means
	// success, after which the copied input must remain in the destination.
	// On failure the copied input must be gone.
	tests := []struct {
		name      string
		stdout    string
		stderr    string
		code      int
		fileName  string
		missing   bool
		wantErr   []string
		wantErrIs error
	}{
		{name: "stdout reporting unpacked succeeds and keeps the target", stdout: unpacked, fileName: "sample.bin"},
		{name: "stderr reporting decompressed succeeds and keeps the target", stderr: "Decompressed 1 file.", fileName: "sample.bin"},
		{name: "file name of exactly 255 bytes is accepted", stdout: unpacked, fileName: strings.Repeat("a", 255)},
		{
			name:     "clean exit without a decompression report fails and removes the target",
			stdout:   "nothing to do",
			fileName: "sample.bin",
			wantErr:  []string{"upx decompression might have failed"},
		},
		{
			name:     "nonzero exit fails with the stderr text and removes the target",
			stderr:   "NotPackedException: not packed by UPX",
			code:     2,
			fileName: "sample.bin",
			wantErr:  []string{"failed to decompress upx file", "NotPackedException"},
		},
		{
			name:      "missing input file fails before anything is copied",
			stdout:    unpacked,
			fileName:  "missing.bin",
			missing:   true,
			wantErr:   []string{"failed to stat file"},
			wantErrIs: fs.ErrNotExist,
		},
		{
			name:     "file name beginning with a hyphen is rejected",
			stdout:   unpacked,
			fileName: "-sample.bin",
			wantErr:  []string{"file name begins with '-'"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("MALCONTENT_UPX_PATH", upxStandIn(t, tt.stdout, tt.stderr, tt.code))

			src := filepath.Join(t.TempDir(), tt.fileName)
			if !tt.missing {
				if err := os.WriteFile(src, []byte(upxStandInPayload), 0o600); err != nil {
					t.Fatalf("write input: %v", err)
				}
			}
			d := filepath.Join(t.TempDir(), "out")
			target := filepath.Join(d, tt.fileName)

			err := ExtractUPX(t.Context(), d, src)
			if len(tt.wantErr) == 0 {
				if err != nil {
					t.Fatalf("ExtractUPX error: got = %v, want = nil", err)
				}
				got, readErr := os.ReadFile(target)
				if readErr != nil {
					t.Fatalf("read target: %v", readErr)
				}
				if string(got) != upxStandInPayload {
					t.Errorf("target contents: got = %q, want = %q", got, upxStandInPayload)
				}
				return
			}

			if err == nil {
				t.Fatalf("ExtractUPX error: got = nil, want = containing %q", tt.wantErr)
			}
			for _, want := range tt.wantErr {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("ExtractUPX error: got = %v, want = containing %q", err, want)
				}
			}
			if tt.wantErrIs != nil && !errors.Is(err, tt.wantErrIs) {
				t.Errorf("ExtractUPX error: got = %v, want = wrapping %v", err, tt.wantErrIs)
			}
			if _, statErr := os.Lstat(target); !errors.Is(statErr, fs.ErrNotExist) {
				t.Errorf("target after failure: got stat err = %v, want = %v", statErr, fs.ErrNotExist)
			}
		})
	}
}

func TestExtractUPXRealBinaryRejectsUnpackedInput(t *testing.T) {
	t.Parallel()
	if _, err := programkind.UPXInstalled(); err != nil {
		t.Skipf("upx unavailable: %v", err)
	}

	src := filepath.Join(t.TempDir(), "plain.bin")
	if err := os.WriteFile(src, []byte("plain text that upx never packed\n"), 0o600); err != nil {
		t.Fatalf("write input: %v", err)
	}
	d := filepath.Join(t.TempDir(), "out")

	const want = "failed to decompress upx file"
	err := ExtractUPX(t.Context(), d, src)
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("ExtractUPX error: got = %v, want = containing %q", err, want)
	}
	if _, statErr := os.Lstat(filepath.Join(d, "plain.bin")); !errors.Is(statErr, fs.ErrNotExist) {
		t.Errorf("target after failure: got stat err = %v, want = %v", statErr, fs.ErrNotExist)
	}
}

func TestUPXCopyBoundedToSandboxLimits(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		limit   int64
		want    string
		wantErr bool
	}{
		{name: "limit of one copies a single byte", limit: 1, want: "a"},
		{name: "limit equal to the input copies all of it", limit: 3, want: "abc"},
		{name: "limit above the input copies all of it", limit: 64, want: "abc"},
		{name: "zero limit is rejected without copying", limit: 0, wantErr: true},
		{name: "negative limit is rejected without copying", limit: -5, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var dst bytes.Buffer
			n, err := copyBoundedToSandbox(&dst, strings.NewReader("abc"), tt.limit)
			if (err != nil) != tt.wantErr {
				t.Fatalf("copyBoundedToSandbox error: got = %v, want error = %v", err, tt.wantErr)
			}
			if n != int64(len(tt.want)) {
				t.Errorf("copied count: got = %d, want = %d", n, len(tt.want))
			}
			if got := dst.String(); got != tt.want {
				t.Errorf("copied bytes: got = %q, want = %q", got, tt.want)
			}
		})
	}
}

// TestExtractUPXRunsInRemovedSandbox checks that upx runs inside a private
// sandbox directory, which is gone once ExtractUPX returns. Setting the
// environment rules out t.Parallel.
func TestExtractUPXRunsInRemovedSandbox(t *testing.T) {
	record := filepath.Join(t.TempDir(), "cwd")
	t.Setenv("MALCONTENT_UPX_PATH", upxStandInScript(t, fmt.Sprintf("#!/bin/sh\npwd > %q\necho 'Unpacked 1 file.'\n", record)))

	src := filepath.Join(t.TempDir(), "sample.bin")
	if err := os.WriteFile(src, []byte(upxStandInPayload), 0o600); err != nil {
		t.Fatalf("write input: %v", err)
	}
	if err := ExtractUPX(t.Context(), filepath.Join(t.TempDir(), "out"), src); err != nil {
		t.Fatalf("ExtractUPX error: got = %v, want = nil", err)
	}

	data, err := os.ReadFile(record)
	if err != nil {
		t.Fatalf("read recorded working directory: %v", err)
	}
	cwd := strings.TrimSpace(string(data))
	if !strings.HasPrefix(filepath.Base(cwd), "mal-upx-") {
		t.Errorf("upx working directory: got = %q, want = a mal-upx-* sandbox", cwd)
	}
	if _, err := os.Stat(cwd); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("sandbox after return: got stat err = %v, want = %v", err, fs.ErrNotExist)
	}
}

// TestExtractUPXSetupFailures checks failures that occur before upx runs.
// Setting the environment rules out t.Parallel.
func TestExtractUPXSetupFailures(t *testing.T) {
	tests := []struct {
		name          string
		missingUPX    bool
		destUnderFile bool
		wantErr       string
		wantErrIs     error
	}{
		{
			name:       "operator path to a missing binary is reported before anything is written",
			missingUPX: true,
			wantErr:    "MALCONTENT_UPX_PATH is invalid",
			wantErrIs:  programkind.ErrUPXPathInvalid,
		},
		{
			name:          "destination beneath a regular file is reported as an extraction directory failure",
			destUnderFile: true,
			wantErr:       "failed to create extraction directory",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			upx := filepath.Join(t.TempDir(), "missing-upx")
			if !tt.missingUPX {
				upx = upxStandIn(t, "Unpacked 1 file.", "", 0)
			}
			t.Setenv("MALCONTENT_UPX_PATH", upx)

			src := filepath.Join(t.TempDir(), "sample.bin")
			if err := os.WriteFile(src, []byte(upxStandInPayload), 0o600); err != nil {
				t.Fatalf("write input: %v", err)
			}
			d := filepath.Join(t.TempDir(), "out")
			if tt.destUnderFile {
				blocker := filepath.Join(t.TempDir(), "blocker")
				if err := os.WriteFile(blocker, nil, 0o600); err != nil {
					t.Fatalf("write blocker: %v", err)
				}
				d = filepath.Join(blocker, "out")
			}

			err := ExtractUPX(t.Context(), d, src)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("ExtractUPX error: got = %v, want = containing %q", err, tt.wantErr)
			}
			if errors.Is(err, ErrExtractorPanic) {
				t.Errorf("ExtractUPX error: got = %v, want = a setup error rather than a recovered panic", err)
			}
			if tt.wantErrIs != nil && !errors.Is(err, tt.wantErrIs) {
				t.Errorf("ExtractUPX error: got = %v, want = wrapping %v", err, tt.wantErrIs)
			}
			if _, statErr := os.Lstat(d); !errors.Is(statErr, fs.ErrNotExist) && !errors.Is(statErr, syscall.ENOTDIR) {
				t.Errorf("destination after failure: got stat err = %v, want = not created", statErr)
			}
		})
	}
}
