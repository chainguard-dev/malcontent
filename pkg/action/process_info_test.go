// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package action

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"testing"

	"github.com/chainguard-dev/malcontent/pkg/file"
	"github.com/shirou/gopsutil/v4/common"
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
	ai, err := file.Stat(a)
	if err != nil {
		t.Errorf("stat %q: %v", a, err)
		return false
	}
	bi, err := file.Stat(b)
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
	if err := file.WriteFileIn(dir, "present", []byte("x"), 0o600); err != nil {
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

			pi, err := processInfo(t.Context(), pid, p)
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
			// Linux scans what the process runs through the kernel's link to
			// it; elsewhere the executable's path stands for it.
			if want := fmt.Sprintf("/proc/%d/exe", pid); (runtime.GOOS == "linux") != (pi.ScanPath == want) {
				t.Errorf("ScanPath: got = %q, want the procfs link %q only on Linux", pi.ScanPath, want)
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
	if _, err := file.Stat(processTestShell); err != nil {
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

	pi, err := processInfo(t.Context(), pid, p)
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

	pi, err := processInfo(t.Context(), pid, p)
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
	pi, err := processInfo(t.Context(), 2, &process.Process{Pid: 2})
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

	pi, err := processInfo(t.Context(), pid, &process.Process{Pid: pid})
	if pi != nil {
		t.Errorf("processInfo: got = %+v, want nil", pi)
	}
	want := fmt.Sprintf("<unknown>[%d]: unable to stat %q", pid, scanPath)
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
	exeInfo, err := file.Stat(exe)
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
		if fi, err := file.Stat(p.ScanPath); err == nil && os.SameFile(fi, exeInfo) {
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

// errProcessTestLookup is the error processTestSource returns for data it
// does not hold.
var errProcessTestLookup = errors.New("lookup failed")

// processTestSource reports fixed process data. An empty name or executable,
// or a nil command line, fails that lookup.
type processTestSource struct {
	name    string
	ppid    int32
	ppidErr error
	cmdline []string
	exe     string
}

func (p processTestSource) Name() (string, error) {
	if p.name == "" {
		return "", errProcessTestLookup
	}
	return p.name, nil
}

func (p processTestSource) PpidWithContext(context.Context) (int32, error) {
	return p.ppid, p.ppidErr
}

func (p processTestSource) CmdlineSliceWithContext(context.Context) ([]string, error) {
	if p.cmdline == nil {
		return nil, errProcessTestLookup
	}
	return p.cmdline, nil
}

func (p processTestSource) Exe() (string, error) {
	if p.exe == "" {
		return "", errProcessTestLookup
	}
	return p.exe, nil
}

func TestProcessInfoFromProcessData(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	exe := scanTestWriteFile(t, filepath.Join(dir, "tool"), []byte("#!/bin/sh\n"))
	missing := filepath.Join(dir, "removed-tool")
	self := int32(os.Getpid())
	// No platform assigns PIDs this large, so it has no procfs entry.
	const absent int32 = math.MaxInt32
	linux := runtime.GOOS == "linux"
	// scanned is the path processInfo scans for process pid running exe:
	// on Linux the kernel's link to what the process runs, elsewhere exe.
	scanned := func(pid int32, exe string) string {
		if linux {
			return fmt.Sprintf("/proc/%d/exe", pid)
		}
		return exe
	}
	// kernelThread is what processInfo returns for a kernel thread off Linux,
	// where kernel threads are not skipped.
	kernelThread := func(pid, ppid int32) *ProcessInfo {
		if linux {
			return nil
		}
		return &ProcessInfo{PID: pid, PPID: ppid, Name: "kthread", ScanPath: exe}
	}

	tests := []struct {
		name      string
		pid       int32
		src       processTestSource
		otherOnly bool // the process data is fake, which only the executable's path reports off Linux
		want      *ProcessInfo
		wantErr   string
	}{
		{
			name:      "executable that can be stat'd is scanned",
			pid:       100,
			src:       processTestSource{name: "tool", ppid: 1, cmdline: []string{exe, "-v"}, exe: exe},
			otherOnly: true,
			want:      &ProcessInfo{PID: 100, PPID: 1, Name: "tool", ScanPath: exe, AdvertisedPath: exe, CmdLine: []string{exe, "-v"}},
		},
		{
			name:      "relative argv0 is not advertised",
			pid:       100,
			src:       processTestSource{name: "tool", ppid: 1, cmdline: []string{"tool"}, exe: exe},
			otherOnly: true,
			want:      &ProcessInfo{PID: 100, PPID: 1, Name: "tool", ScanPath: exe, CmdLine: []string{"tool"}},
		},
		{
			name:      "failed name lookup is reported as unknown",
			pid:       100,
			src:       processTestSource{ppid: 1, exe: exe},
			otherOnly: true,
			want:      &ProcessInfo{PID: 100, PPID: 1, Name: "<unknown>", ScanPath: exe},
		},
		{
			name:      "failed parent lookup records parent -1",
			pid:       100,
			src:       processTestSource{name: "tool", ppidErr: errProcessTestLookup, exe: exe},
			otherOnly: true,
			want:      &ProcessInfo{PID: 100, PPID: -1, Name: "tool", ScanPath: exe},
		},
		{
			name:      "child of init is kept",
			pid:       100,
			src:       processTestSource{name: "kthread", ppid: 1, exe: exe},
			otherOnly: true,
			want:      &ProcessInfo{PID: 100, PPID: 1, Name: "kthread", ScanPath: exe},
		},
		{
			name: "child of kthreadd is skipped on Linux",
			pid:  100,
			src:  processTestSource{name: "kthread", ppid: 2, exe: exe},
			want: kernelThread(100, 2),
		},
		{
			name: "kthreadd is skipped on Linux",
			pid:  2,
			src:  processTestSource{name: "kthread", ppid: 0, exe: exe},
			want: kernelThread(2, 0),
		},
		{
			// On Linux the kernel's link reaches what the process runs, so the
			// path the executable once had does not matter.
			name: "the running executable is scanned whatever its path now names",
			pid:  self,
			src:  processTestSource{name: "tool", ppid: 1, cmdline: []string{exe}, exe: missing},
			want: func() *ProcessInfo {
				if !linux {
					return nil
				}
				return &ProcessInfo{PID: self, PPID: 1, Name: "tool", ScanPath: scanned(self, missing), AdvertisedPath: exe, CmdLine: []string{exe}}
			}(),
			wantErr: func() string {
				if linux {
					return ""
				}
				return fmt.Sprintf("tool[%d]: unable to stat %q", self, missing)
			}(),
		},
		{
			name:    "argv0 is never scanned in place of an executable that cannot be stat'd",
			pid:     absent,
			src:     processTestSource{name: "tool", ppid: 1, cmdline: []string{exe}, exe: missing},
			wantErr: fmt.Sprintf("tool[%d]: unable to stat %q", absent, scanned(absent, missing)),
		},
		{
			name:    "a process without an executable is named in the error",
			pid:     absent,
			src:     processTestSource{name: "tool", ppid: 1, cmdline: []string{missing}},
			wantErr: fmt.Sprintf("tool[%d]: unable to stat %q", absent, scanned(absent, "")),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if tt.otherOnly && linux {
				t.Skip("Linux reads executables through /proc, which fake process data has no entry in")
			}
			got, err := processInfo(t.Context(), tt.pid, tt.src)
			gotErr := ""
			if err != nil {
				gotErr = err.Error()
			}
			if gotErr != tt.wantErr {
				t.Errorf("error: got = %q, want = %q", gotErr, tt.wantErr)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("processInfo: got = %+v, want = %+v", got, tt.want)
			}
		})
	}
}

func TestActiveProcessesProcessTable(t *testing.T) {
	t.Parallel()
	if runtime.GOOS != "linux" {
		t.Skip("the process table location can be set only on Linux")
	}
	tests := []struct {
		name    string
		create  bool
		wantErr error
	}{
		{name: "missing process table reports the listing failure", wantErr: fs.ErrNotExist},
		{name: "empty process table lists no processes", create: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			table := filepath.Join(dir, "proc")
			if tt.create {
				if err := file.MkdirAllIn(dir, "proc", 0o700); err != nil {
					t.Fatalf("mkdir: %v", err)
				}
			}
			ctx := context.WithValue(t.Context(), common.EnvKey, common.EnvMap{common.HostProcEnvKey: table})
			ps, err := ActiveProcesses(ctx)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("ActiveProcesses error: got = %v, want = %v", err, tt.wantErr)
			}
			if len(ps) != 0 {
				t.Errorf("ActiveProcesses: got %d processes, want none", len(ps))
			}
			if tt.wantErr != nil && ps != nil {
				t.Errorf("ActiveProcesses: got = %v, want nil on failure", ps)
			}
		})
	}
}

func TestInterpreterOf(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		exe    string
		argv   []string
		want   string
		wantOK bool
	}{
		{name: "a shell", exe: "/bin/bash", want: "bash", wantOK: true},
		{name: "a busybox shell applet", exe: "/usr/bin/busybox", argv: []string{"sh", "x.sh"}, want: "sh", wantOK: true},
		{name: "a busybox applet that is no interpreter", exe: "/usr/bin/busybox", argv: []string{"/bin/sleep", "60"}, want: "sleep"},
		{name: "argv[0] names no interpreter for any other program", exe: "/usr/sbin/sshd", argv: []string{"bash"}, want: "sshd"},
		{name: "a versioned python", exe: "/usr/bin/python3.12", want: "python", wantOK: true},
		{name: "a deleted interpreter", exe: "/usr/bin/perl5.36 (deleted)", want: "perl", wantOK: true},
		{name: "node by its Debian name", exe: "/usr/bin/nodejs", want: "nodejs", wantOK: true},
		{name: "a compiled program is no interpreter", exe: "/usr/sbin/sshd", want: "sshd"},
		{name: "a program named like a prefix of an interpreter is none", exe: "/usr/bin/shred", want: "shred"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, ok := interpreterOf(tt.exe, tt.argv)
			if got != tt.want || ok != tt.wantOK {
				t.Errorf("interpreterOf(%q, %q): got = (%q, %t), want = (%q, %t)", tt.exe, tt.argv, got, ok, tt.want, tt.wantOK)
			}
		})
	}
}

func TestScriptOperand(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		interp string
		argv   []string
		want   string
	}{
		{name: "a shell script", interp: "sh", argv: []string{"sh", "/tmp/x.sh"}, want: "/tmp/x.sh"},
		{name: "a shell script after options", interp: "bash", argv: []string{"bash", "-x", "--norc", "run.sh", "arg"}, want: "run.sh"},
		{name: "inline shell code runs no script", interp: "bash", argv: []string{"bash", "-c", "curl x | sh"}},
		{name: "inline shell code among clustered options runs no script", interp: "sh", argv: []string{"sh", "-ec", "id"}},
		{name: "a python script", interp: "python", argv: []string{"python3", "-u", "app.py"}, want: "app.py"},
		{name: "a python module runs no script", interp: "python", argv: []string{"python3", "-m", "http.server"}},
		{name: "inline perl runs no script", interp: "perl", argv: []string{"perl", "-ne", "print"}},
		{name: "node evaluating code runs no script", interp: "node", argv: []string{"node", "--eval", "1"}},
		{name: "node after a long option", interp: "node", argv: []string{"node", "--inspect", "server.js"}, want: "server.js"},
		{name: "standard input runs no script", interp: "ruby", argv: []string{"ruby", "-"}},
		{name: "the operand after -- is the script", interp: "php", argv: []string{"php", "--", "-odd.php"}, want: "-odd.php"},
		{name: "no operand runs no script", interp: "dash", argv: []string{"dash"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := scriptOperand(tt.interp, tt.argv); got != tt.want {
				t.Errorf("scriptOperand(%q, %q): got = %q, want = %q", tt.interp, tt.argv, got, tt.want)
			}
		})
	}
}

func TestParseProcPath(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		path    string
		wantPID int32
		wantSub string
		wantOK  bool
	}{
		{name: "an executable link", path: "/proc/42/exe", wantPID: 42, wantSub: "exe", wantOK: true},
		{name: "a file below a process root", path: "/proc/42/root/app/x.py", wantPID: 42, wantSub: "root/app/x.py", wantOK: true},
		{name: "a process directory alone", path: "/proc/42"},
		{name: "a name in place of a pid", path: "/proc/self/exe"},
		{name: "a pid of zero", path: "/proc/0/exe"},
		{name: "a pid past 32 bits", path: "/proc/4294967296/exe"},
		{name: "a path outside /proc", path: "/usr/bin/ls"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			pid, sub, ok := parseProcPath(tt.path)
			if pid != tt.wantPID || sub != tt.wantSub || ok != tt.wantOK {
				t.Errorf("parseProcPath(%q): got = (%d, %q, %t), want = (%d, %q, %t)", tt.path, pid, sub, ok, tt.wantPID, tt.wantSub, tt.wantOK)
			}
		})
	}
}

// TestResolveInRoot checks that a process's file is found as the process
// would find it: an absolute symlink starts again at the process's root, and
// ".." goes no higher than it.
func TestResolveInRoot(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	scanTestWriteFile(t, filepath.Join(dir, "srv", "app", "x.py"), []byte("print(1)\n"))
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("open root: %v", err)
	}
	t.Cleanup(func() { _ = root.Close() })
	for _, link := range []struct{ target, name string }{
		{"/srv/app", "app"},             // absolute, as containers' files often are
		{"../../srv/app", "up"},         // climbs past the top
		{"srv/app/x.py", "relative.py"}, // relative
		{"/loop", "loop"},               // never resolves
		{"/srv/missing.py", "dangling"}, // leads nowhere
	} {
		if err := os.Symlink(link.target, filepath.Join(dir, link.name)); err != nil {
			t.Fatalf("symlink: %v", err)
		}
	}

	tests := []struct {
		name    string
		path    string
		want    string
		wantErr error
	}{
		{name: "a plain path", path: "srv/app/x.py", want: "srv/app/x.py"},
		{name: "an absolute symlink starts at the root", path: "app/x.py", want: "srv/app/x.py"},
		{name: "dot-dot stops at the root", path: "up/x.py", want: "srv/app/x.py"},
		{name: "a relative symlink", path: "relative.py", want: "srv/app/x.py"},
		{name: "a symlink loop is refused", path: "loop", wantErr: syscall.ELOOP},
		{name: "a dangling symlink is missing", path: "dangling", wantErr: fs.ErrNotExist},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := resolveInRoot(root, tt.path)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("resolveInRoot(%q): got = (%q, %v), want an error wrapping %v", tt.path, got, err, tt.wantErr)
				}
				return
			}
			if err != nil || got != tt.want {
				t.Errorf("resolveInRoot(%q): got = (%q, %v), want = %q", tt.path, got, err, tt.want)
			}
		})
	}
}
