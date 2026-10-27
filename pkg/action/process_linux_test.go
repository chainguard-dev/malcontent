// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package action

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/shirou/gopsutil/v4/process"
)

// startDeletedHelper copies the test binary to a new directory, runs the copy
// as the processInfo helper with argv0 as its first argument, and deletes
// it, so that the running process's executable has no path left. It returns
// the process and the path the copy had.
func startDeletedHelper(t *testing.T, argv0 string) (*exec.Cmd, string) {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	copied := filepath.Join(t.TempDir(), "helper")
	in, err := os.Open(self)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer in.Close()
	out, err := os.OpenFile(copied, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o700)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := io.Copy(out, in); err != nil {
		t.Fatalf("copy: %v", err)
	}
	if err := out.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	var cmd *exec.Cmd
	var stdin io.WriteCloser
	// A process another test forks while the copy is still open for
	// writing holds it open briefly, which fails exec with ETXTBSY.
	for attempt := 0; ; attempt++ {
		cmd = exec.Command(copied, processHelperRunFlag)
		cmd.Args[0] = argv0
		cmd.Env = append(os.Environ(), processHelperEnv+"=1")
		if stdin, err = cmd.StdinPipe(); err != nil {
			t.Fatalf("StdinPipe: %v", err)
		}
		err = cmd.Start()
		if err == nil {
			break
		}
		_ = stdin.Close()
		if !errors.Is(err, syscall.ETXTBSY) || attempt == 50 {
			t.Fatalf("Start: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Cleanup(func() {
		_ = stdin.Close()
		_ = cmd.Wait()
	})
	if err := os.Remove(copied); err != nil {
		t.Fatalf("remove: %v", err)
	}
	return cmd, copied
}

// TestScanReadsProcessExecutablesThroughProc checks that a running process's
// executable is scanned through /proc/<pid>/exe, which reaches it even once
// deleted, and that argv[0] never stands in for it.
func TestScanReadsProcessExecutablesThroughProc(t *testing.T) {
	t.Parallel()
	yrs, rfs := scanTestRules(t)

	tests := []struct {
		name  string
		argv0 string
	}{
		{name: "a deleted executable is scanned", argv0: "helper"},
		{name: "an executable claiming another program's path is scanned as itself", argv0: "/bin/sh"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cmd, copied := startDeletedHelper(t, tt.argv0)
			pid := int32(cmd.Process.Pid)
			p, err := process.NewProcessWithContext(t.Context(), pid)
			if err != nil {
				t.Fatalf("NewProcessWithContext: %v", err)
			}
			pi, err := processInfo(t.Context(), pid, p)
			if err != nil {
				t.Fatalf("processInfo: %v", err)
			}
			if want := fmt.Sprintf("/proc/%d/exe", pid); pi.ScanPath != want {
				t.Fatalf("ScanPath: got = %q, want = %q", pi.ScanPath, want)
			}

			c := malcontent.Config{Concurrency: 1, IncludeDataFiles: true, Rules: yrs, RuleFS: rfs, ScanPaths: []string{pi.ScanPath}}
			r, err := Scan(t.Context(), c)
			if err != nil {
				t.Fatalf("Scan: %v", err)
			}
			want := fmt.Sprintf("%s (deleted) [pid %d]", copied, pid)
			fr, ok := r.Files.Load(want)
			if !ok || fr.Skipped != "" || fr.Path != want {
				t.Errorf("report: got keys %q (%+v), want %q scanned", scanTestKeys(r.Files), fr, want)
			}
		})
	}
}

// TestActiveProcessesScansScripts checks that a script an interpreter runs is
// listed, resolved against the process's working directory and read through
// its root, and scanned under its path and pid.
func TestActiveProcessesScansScripts(t *testing.T) {
	t.Parallel()
	shell, err := exec.LookPath("sh")
	if err != nil {
		t.Skipf("sh: %v", err)
	}
	yrs, rfs := scanTestRules(t)

	tests := []struct {
		name     string
		relative bool // run the script by a path relative to the working directory
	}{
		{name: "a script named by its absolute path"},
		{name: "a script named relative to the working directory", relative: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatalf("EvalSymlinks: %v", err)
			}
			script := scanTestWriteFile(t, filepath.Join(dir, "waits.sh"), []byte("#!/bin/sh\n# waits for its input to close\nread line\n"))
			arg := script
			if tt.relative {
				arg = "waits.sh"
			}
			cmd := exec.Command(shell, arg)
			cmd.Dir = dir
			stdin, err := cmd.StdinPipe()
			if err != nil {
				t.Fatalf("StdinPipe: %v", err)
			}
			if err := cmd.Start(); err != nil {
				t.Fatalf("Start: %v", err)
			}
			t.Cleanup(func() {
				_ = stdin.Close()
				_ = cmd.Wait()
			})
			pid := int32(cmd.Process.Pid)
			wantScanPath := fmt.Sprintf("/proc/%d/root%s", pid, script)

			var found bool
			// The shell may not have started reading the script yet; its
			// command line shows once it has.
			for range 50 {
				ps, err := ActiveProcesses(t.Context())
				if err != nil {
					t.Fatalf("ActiveProcesses: %v", err)
				}
				for _, p := range ps {
					found = found || p.ScanPath == wantScanPath
				}
				if found {
					break
				}
			}
			if !found {
				t.Fatalf("ActiveProcesses: got no entry for %q", wantScanPath)
			}

			c := malcontent.Config{Concurrency: 1, Rules: yrs, RuleFS: rfs, ScanPaths: []string{wantScanPath}}
			r, err := Scan(t.Context(), c)
			if err != nil {
				t.Fatalf("Scan: %v", err)
			}
			want := fmt.Sprintf("%s [pid %d]", script, pid)
			if fr, ok := r.Files.Load(want); !ok || fr.Skipped != "" {
				t.Errorf("report: got keys %q (%+v), want %q scanned", scanTestKeys(r.Files), fr, want)
			}
			for _, key := range scanTestKeys(r.Files) {
				if strings.HasPrefix(key, "/proc/") {
					t.Errorf("report key %q: want the script's own path, not its /proc path", key)
				}
			}
		})
	}
}
