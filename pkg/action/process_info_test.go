// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package action

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/shirou/gopsutil/v4/process"
)

const (
	// processHelperEnv marks a re-executed test binary that idles until its
	// stdin closes, giving the processInfo tests a child with a known argv.
	processHelperEnv     = "MALCONTENT_PROCESS_INFO_HELPER"
	processHelperRunFlag = "-test.run=^TestProcessInfoHelperProcess$"
)

// TestProcessInfoHelperProcess only does work when re-executed by
// startProcessInfoHelper; in a normal run it skips.
func TestProcessInfoHelperProcess(t *testing.T) {
	t.Parallel()
	if os.Getenv(processHelperEnv) != "1" {
		t.Skip("runs only as a child of the processInfo tests")
	}
	_, _ = io.Copy(io.Discard, os.Stdin)
}

// startProcessInfoHelper re-executes the test binary with argv0 as its first
// argument and keeps it running until the test ends.
func startProcessInfoHelper(t *testing.T, argv0 string) *exec.Cmd {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	// Not CommandContext: the test context is canceled before cleanup runs,
	// which would kill the helper instead of letting it exit cleanly.
	cmd := exec.Command(exe, processHelperRunFlag)
	cmd.Args[0] = argv0
	cmd.Env = append(os.Environ(), processHelperEnv+"=1")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("StdinPipe: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		_ = stdin.Close()
		if err := cmd.Wait(); err != nil {
			t.Errorf("helper process exit: got = %v, want nil", err)
		}
	})
	return cmd
}

// processTestSameFile reports whether two paths name the same file, failing
// the test when either path cannot be stat'd.
func processTestSameFile(t *testing.T, a, b string) bool {
	t.Helper()
	ai, err := os.Stat(a)
	if err != nil {
		t.Errorf("stat %q: %v", a, err)
		return false
	}
	bi, err := os.Stat(b)
	if err != nil {
		t.Errorf("stat %q: %v", b, err)
		return false
	}
	return os.SameFile(ai, bi)
}

func TestCanStat(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	present := filepath.Join(dir, "present")
	if err := os.WriteFile(present, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	tests := []struct {
		name string
		path string
		want bool
	}{
		{name: "existing file", path: present, want: true},
		{name: "existing directory", path: dir, want: true},
		{name: "missing file", path: filepath.Join(dir, "absent"), want: false},
		{name: "empty path", path: "", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := canStat(tt.path); got != tt.want {
				t.Errorf("canStat(%q): got = %v, want = %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestProcessInfoChildProcess(t *testing.T) {
	t.Parallel()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}

	tests := []struct {
		name           string
		argv0          string
		wantAdvertised string
	}{
		{name: "absolute argv0 is advertised", argv0: exe, wantAdvertised: exe},
		{name: "relative argv0 is not advertised", argv0: "relative-helper-name", wantAdvertised: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cmd := startProcessInfoHelper(t, tt.argv0)
			pid := int32(cmd.Process.Pid)
			p, err := process.NewProcessWithContext(t.Context(), pid)
			if err != nil {
				t.Fatalf("NewProcessWithContext(%d): %v", pid, err)
			}

			pi, err := processInfo(t.Context(), p)
			if err != nil {
				t.Fatalf("processInfo: got error = %v, want nil", err)
			}
			if pi == nil {
				t.Fatalf("processInfo: got = nil, want process info")
			}
			if pi.PID != pid {
				t.Errorf("PID: got = %d, want = %d", pi.PID, pid)
			}
			if want := int32(os.Getpid()); pi.PPID != want {
				t.Errorf("PPID: got = %d, want = %d", pi.PPID, want)
			}
			if pi.Name == "" || pi.Name == "<unknown>" {
				t.Errorf("Name: got = %q, want the executable name", pi.Name)
			}
			if want := []string{tt.argv0, processHelperRunFlag}; !slices.Equal(pi.CmdLine, want) {
				t.Errorf("CmdLine: got = %q, want = %q", pi.CmdLine, want)
			}
			if pi.AdvertisedPath != tt.wantAdvertised {
				t.Errorf("AdvertisedPath: got = %q, want = %q", pi.AdvertisedPath, tt.wantAdvertised)
			}
			// The executable reported by the process table is preferred over
			// the procfs alias, which would also resolve to the same file.
			if strings.HasPrefix(pi.ScanPath, "/proc/") {
				t.Errorf("ScanPath: got = %q, want the executable path rather than a procfs alias", pi.ScanPath)
			}
			if !processTestSameFile(t, pi.ScanPath, exe) {
				t.Errorf("ScanPath: got = %q, want the test executable %q", pi.ScanPath, exe)
			}
		})
	}
}

// processTestShell is a system shell started with a single-element argv; it
// reads commands from its stdin pipe, so it idles until that pipe closes.
const processTestShell = "/bin/sh"

// startProcessTestShell starts processTestShell and reaps it when the test ends.
func startProcessTestShell(t *testing.T) (*exec.Cmd, io.WriteCloser, io.ReadCloser) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("relies on Linux process accounting for a directly executed shell")
	}
	if _, err := os.Stat(processTestShell); err != nil {
		t.Skipf("%s unavailable: %v", processTestShell, err)
	}
	cmd := exec.Command(processTestShell)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("StdinPipe: %v", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		_ = stdin.Close()
		if err := cmd.Wait(); err != nil {
			t.Errorf("shell exit: got = %v, want nil", err)
		}
	})
	return cmd, stdin, stdout
}

func TestProcessInfoSingleArgumentCommandLine(t *testing.T) {
	t.Parallel()
	cmd, _, _ := startProcessTestShell(t)
	pid := int32(cmd.Process.Pid)
	p, err := process.NewProcessWithContext(t.Context(), pid)
	if err != nil {
		t.Fatalf("NewProcessWithContext(%d): %v", pid, err)
	}

	pi, err := processInfo(t.Context(), p)
	if err != nil {
		t.Fatalf("processInfo: got error = %v, want nil", err)
	}
	if pi == nil {
		t.Fatalf("processInfo: got = nil, want process info")
	}
	if want := []string{processTestShell}; !slices.Equal(pi.CmdLine, want) {
		t.Errorf("CmdLine: got = %q, want = %q", pi.CmdLine, want)
	}
	if pi.AdvertisedPath != processTestShell {
		t.Errorf("AdvertisedPath: got = %q, want = %q", pi.AdvertisedPath, processTestShell)
	}
	if !processTestSameFile(t, pi.ScanPath, processTestShell) {
		t.Errorf("ScanPath: got = %q, want the file behind %q", pi.ScanPath, processTestShell)
	}
}

func TestProcessInfoExitingProcess(t *testing.T) {
	t.Parallel()
	cmd, stdin, stdout := startProcessTestShell(t)
	pid := int32(cmd.Process.Pid)
	// Closing stdin makes the shell exit. Its stdout reaches EOF only once the
	// exiting process has closed its descriptors, which happens after it has
	// released its memory, so its command line and executable are gone.
	if err := stdin.Close(); err != nil {
		t.Fatalf("close stdin: %v", err)
	}
	if _, err := io.ReadAll(stdout); err != nil {
		t.Fatalf("read stdout: %v", err)
	}
	p := &process.Process{Pid: pid}
	if cmdline, err := p.CmdlineSliceWithContext(t.Context()); err != nil || len(cmdline) != 0 {
		t.Skipf("shell has not released its command line yet: got = (%q, %v)", cmdline, err)
	}

	pi, err := processInfo(t.Context(), p)
	if pi != nil {
		t.Errorf("processInfo: got = %+v, want nil", pi)
	}
	want := fmt.Sprintf("unable to stat %q", fmt.Sprintf("/proc/%d/exe", pid))
	if err == nil || !strings.HasSuffix(err.Error(), want) {
		t.Errorf("processInfo error: got = %v, want a message ending in %s", err, want)
	}
}

func TestProcessInfoSkipsLinuxKernelThreads(t *testing.T) {
	t.Parallel()
	if runtime.GOOS != "linux" {
		t.Skip("kernel thread filtering applies only on Linux")
	}
	// PID 2 is kthreadd, the parent of every kernel thread; it is skipped
	// whether or not it is visible in this PID namespace.
	pi, err := processInfo(t.Context(), &process.Process{Pid: 2})
	if err != nil || pi != nil {
		t.Errorf("processInfo(pid 2): got = (%v, %v), want = (nil, nil)", pi, err)
	}
}

func TestProcessInfoMissingProcess(t *testing.T) {
	t.Parallel()
	// No platform assigns PIDs this large, so the process never exists.
	const pid = math.MaxInt32
	scanPath := ""
	if runtime.GOOS == "linux" {
		scanPath = fmt.Sprintf("/proc/%d/exe", pid)
	}

	pi, err := processInfo(t.Context(), &process.Process{Pid: pid})
	if pi != nil {
		t.Errorf("processInfo: got = %+v, want nil", pi)
	}
	want := fmt.Sprintf("<unknown>: unable to stat %q", scanPath)
	if err == nil || err.Error() != want {
		t.Errorf("processInfo error: got = %v, want = %s", err, want)
	}
}

func TestActiveProcessesCanceledContext(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	ps, err := ActiveProcesses(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("ActiveProcesses error: got = %v, want = %v", err, context.Canceled)
	}
	if ps != nil {
		t.Errorf("ActiveProcesses: got = %v, want nil", ps)
	}
}

// TestActiveProcessesIncludesCurrentProcess asserts only properties that hold
// for any process table: entries are non-nil, unique by ScanPath, sorted, and
// include this test binary.
func TestActiveProcessesIncludesCurrentProcess(t *testing.T) {
	t.Parallel()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	exeInfo, err := os.Stat(exe)
	if err != nil {
		t.Fatalf("stat %q: %v", exe, err)
	}

	ps, err := ActiveProcesses(t.Context())
	if err != nil {
		t.Fatalf("ActiveProcesses: got error = %v, want nil", err)
	}

	seen := make(map[string]struct{}, len(ps))
	found := false
	for i, p := range ps {
		if p == nil {
			t.Fatalf("entry %d: got = nil, want process info", i)
		}
		if _, dup := seen[p.ScanPath]; dup {
			t.Errorf("ScanPath %q: got duplicate entries, want one", p.ScanPath)
		}
		seen[p.ScanPath] = struct{}{}
		// Other processes may exit after being listed, so a failed stat is not an error here.
		if fi, err := os.Stat(p.ScanPath); err == nil && os.SameFile(fi, exeInfo) {
			found = true
		}
	}
	if !found {
		t.Errorf("ActiveProcesses: got %d entries without %q, want it included", len(ps), exe)
	}
	if !slices.IsSortedFunc(ps, func(a, b *ProcessInfo) int { return strings.Compare(a.ScanPath, b.ScanPath) }) {
		t.Errorf("ActiveProcesses: got entries out of ScanPath order, want sorted")
	}
}
