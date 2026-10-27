// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package action

import (
	"cmp"
	"context"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/malcontent/pkg/file"
	"github.com/shirou/gopsutil/v4/process"
)

// ProcessInfo is a running process to scan. ScanPath names the file to scan:
// on Linux, /proc/<pid>/exe for the process's executable or
// /proc/<pid>/root/<path> for a script it runs, which Scan reads as the
// process sees them; elsewhere, the executable's path.
type ProcessInfo struct {
	PID            int32
	PPID           int32
	Name           string
	ScanPath       string
	AdvertisedPath string
	CmdLine        []string
}

// ActiveProcesses returns the running processes to scan, one for each
// distinct file, sorted by ScanPath. On Linux an executable is read through
// /proc/<pid>/exe, which reaches the bytes the process runs even when the
// file was deleted or lies in another mount namespace, such as a
// container's, and a process running a script under an interpreter also
// yields an entry for the script, read through /proc/<pid>/root. A process's
// own account of its path, argv[0], is never scanned: any process can set it.
func ActiveProcesses(ctx context.Context) ([]*ProcessInfo, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	// Retrieve all of the active PIDs
	procs, err := process.ProcessesWithContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("processes: %w", err)
	}
	// The lowest pid stands for each file that several processes share.
	slices.SortFunc(procs, func(a, b *process.Process) int { return cmp.Compare(a.Pid, b.Pid) })

	found := map[any]*ProcessInfo{}
	add := func(pi *ProcessInfo) {
		if pi == nil {
			return
		}
		if id := fileIdentity(pi.ScanPath); found[id] == nil {
			found[id] = pi
		}
	}
	for _, p := range procs {
		pi, err := processInfo(ctx, p.Pid, p)
		if err != nil {
			clog.Warnf("skipping pid %d: %v", p.Pid, err)
			continue
		}
		add(pi)
		if exe, err := p.Exe(); err == nil {
			add(scriptInfo(pi, exe))
		}
	}

	ps := slices.Collect(maps.Values(found))
	slices.SortFunc(ps, func(a, b *ProcessInfo) int {
		return cmp.Compare(a.ScanPath, b.ScanPath)
	})
	return ps, nil
}

// canStat checks if stat() works on a given path.
func canStat(name string) bool {
	_, err := file.Stat(name)
	return err == nil
}

// processSource is the process data that processInfo reads.
type processSource interface {
	Name() (string, error)
	PpidWithContext(ctx context.Context) (int32, error)
	CmdlineSliceWithContext(ctx context.Context) ([]string, error)
	Exe() (string, error)
}

var _ processSource = (*process.Process)(nil)

// processInfo returns information about process pid, whose data p reports,
// tuned for scanning.
func processInfo(ctx context.Context, pid int32, p processSource) (*ProcessInfo, error) {
	pi := &ProcessInfo{
		PID: pid,
	}
	name, err := p.Name()
	if err != nil {
		name = "<unknown>"
	}
	pi.Name = name

	parent, err := p.PpidWithContext(ctx)
	if err != nil {
		parent = -1
	}

	// Skip Linux kernel threads that have no backing executable
	if runtime.GOOS == "linux" && (pid == 2 || parent == 2) {
		return nil, nil
	}
	pi.PPID = parent

	cmd, err := p.CmdlineSliceWithContext(ctx)
	if err == nil {
		pi.CmdLine = cmd
		if len(cmd) > 0 && strings.HasPrefix(cmd[0], "/") {
			pi.AdvertisedPath = cmd[0]
		}
	}

	if runtime.GOOS == "linux" {
		// The kernel resolves the link to the file the process runs, which
		// no path of ours may name; a root would refuse to follow it.
		pi.ScanPath = procPath(pid, "exe")
		if _, err := os.Stat(pi.ScanPath); err == nil {
			return pi, nil
		}
		return nil, fmt.Errorf("%s[%d]: unable to stat %q", pi.Name, pid, pi.ScanPath)
	}

	if exe, err := p.Exe(); err == nil {
		pi.ScanPath = exe
		if canStat(exe) {
			return pi, nil
		}
	}
	return nil, fmt.Errorf("%s[%d]: unable to stat %q", pi.Name, pid, pi.ScanPath)
}

// procPath returns the path of name in the /proc directory of process pid.
func procPath(pid int32, name string) string {
	return "/proc/" + strconv.Itoa(int(pid)) + "/" + name
}

// deletedSuffix ends the target of a /proc/<pid>/exe link whose file was
// deleted.
const deletedSuffix = " (deleted)"

// interpreters lists the programs, by name without a version, whose first
// operand is a script they run.
var interpreters = map[string]string{
	// The value lists the short options that pass code inline, after which
	// no operand names a script.
	"sh":     "cs",
	"ash":    "cs",
	"bash":   "cs",
	"dash":   "cs",
	"python": "cm",
	"perl":   "eE",
	"ruby":   "e",
	"node":   "ep",
	"nodejs": "ep",
	"php":    "r",
}

// interpreterOf returns the interpreter that a process running exe, the
// target of its executable link, with command line argv, is, and whether it
// is one. A multi-call binary such as busybox runs the applet its argv[0]
// names, which only selects how the command line is read: the script is
// still read from the file the command line names.
func interpreterOf(exe string, argv []string) (string, bool) {
	name := path.Base(strings.TrimSuffix(exe, deletedSuffix))
	if name == "busybox" && len(argv) > 0 {
		name = path.Base(argv[0])
	}
	name = strings.TrimRight(name, "0123456789.")
	_, ok := interpreters[name]
	return name, ok
}

// scriptOperand returns the script that argv, the command line of the
// interpreter named interp, runs: its first operand, unless options before
// it pass code inline or a lone "-" reads standard input. It returns "" when
// there is none.
func scriptOperand(interp string, argv []string) string {
	inline := interpreters[interp]
	for i := 1; i < len(argv); i++ {
		arg := argv[i]
		switch {
		case arg == "-":
			return ""
		case arg == "--":
			if i+1 < len(argv) {
				return argv[i+1]
			}
			return ""
		case arg == "--eval" || arg == "--print":
			return ""
		case strings.HasPrefix(arg, "--"):
		case strings.HasPrefix(arg, "-"):
			if strings.ContainsAny(arg[1:], inline) {
				return ""
			}
		default:
			return arg
		}
	}
	return ""
}

// scriptInfo returns the entry for the script that pi's process, running
// exe, runs under an interpreter, or nil when it runs none from a file. A
// relative script is resolved against the process's working directory, and
// the script is read through the process's root, as the process reads it.
// Only Linux exposes either.
func scriptInfo(pi *ProcessInfo, exe string) *ProcessInfo {
	if runtime.GOOS != "linux" || pi == nil {
		return nil
	}
	interp, ok := interpreterOf(exe, pi.CmdLine)
	if !ok {
		return nil
	}
	script := scriptOperand(interp, pi.CmdLine)
	if script == "" {
		return nil
	}
	if !path.IsAbs(script) {
		cwd, err := os.Readlink(procPath(pi.PID, "cwd"))
		if err != nil || !path.IsAbs(cwd) || strings.HasSuffix(cwd, deletedSuffix) {
			return nil
		}
		script = path.Join(cwd, script)
	}
	scanPath := procPath(pi.PID, "root") + path.Clean(script)
	// An operand that names no regular file, such as the value of an
	// option, is passed over.
	if fi, err := statProcessFile(scanPath); err != nil || !fi.Mode().IsRegular() {
		return nil
	}
	return &ProcessInfo{PID: pi.PID, PPID: pi.PPID, Name: pi.Name, ScanPath: scanPath, CmdLine: pi.CmdLine}
}

// statProcessFile returns the FileInfo of the process file that scanPath
// names, reached as Scan reaches it.
func statProcessFile(scanPath string) (fs.FileInfo, error) {
	t, ok := procTargetFor(scanPath)
	if !ok || t == nil {
		return file.Stat(scanPath)
	}
	f, err := t.open()
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return f.Stat()
}

// fileIdentity returns a key that the scan paths naming one file share: its
// device and inode where the platform reports them, its scan path otherwise.
func fileIdentity(scanPath string) any {
	fi, err := statProcessFile(scanPath)
	if err != nil {
		return scanPath
	}
	if dev, ino, ok := file.Inode(fi); ok {
		return [2]uint64{dev, ino}
	}
	return scanPath
}

// procTarget is a file of a running process, named by a /proc path and read
// through the kernel's view of the process, which reaches a deleted
// executable, or a file in another mount namespace, that no path of ours
// names.
type procTarget struct {
	path string // the file's path as the process names it, for detection
	key  string // the report key: path as the process names it, and the pid
	open func() (*os.File, error)
}

// parseProcPath splits scanPath, a path in /proc, into the process's pid and
// the rest of the path, and reports whether scanPath has that form.
func parseProcPath(scanPath string) (int32, string, bool) {
	rest, ok := strings.CutPrefix(scanPath, "/proc/")
	if !ok {
		return 0, "", false
	}
	id, sub, ok := strings.Cut(rest, "/")
	if !ok {
		return 0, "", false
	}
	pid, err := strconv.ParseInt(id, 10, 32)
	if err != nil || pid <= 0 {
		return 0, "", false
	}
	return int32(pid), sub, true
}

// procTargetFor returns the process file that scanPath names, in the forms
// ActiveProcesses reports on Linux, and whether scanPath has such a form:
// /proc/<pid>/exe for the process's executable, or /proc/<pid>/root/<path>
// for a file as the process sees it. The target is nil when the process has
// exited or its executable cannot be read.
func procTargetFor(scanPath string) (*procTarget, bool) {
	if runtime.GOOS != "linux" {
		return nil, false
	}
	pid, sub, ok := parseProcPath(scanPath)
	if !ok {
		return nil, false
	}
	if sub == "exe" {
		exe := procPath(pid, "exe")
		link, err := os.Readlink(exe)
		if err != nil {
			return nil, true
		}
		return &procTarget{
			path: strings.TrimSuffix(link, deletedSuffix),
			key:  processKey(link, pid),
			// The link names a file outside /proc/<pid>, even a deleted one,
			// which a root on that directory refuses to follow.
			open: func() (*os.File, error) { return os.Open(exe) }, // #nosec G304 -- /proc/<pid>/exe built from a parsed pid
		}, true
	}
	name, ok := strings.CutPrefix(sub, "root/")
	if !ok || name == "" {
		return nil, false
	}
	root := procPath(pid, "root")
	return &procTarget{
		path: "/" + name,
		key:  processKey("/"+name, pid),
		open: func() (*os.File, error) { return openInProcessRoot(root, name) },
	}, true
}

// processKey returns the report key of the file at name, as process pid
// names it.
func processKey(name string, pid int32) string {
	return fmt.Sprintf("%s [pid %d]", name, pid)
}

// openInProcessRoot opens name, a slash-separated path, beneath rootDir, a
// process's root directory, resolving its symlinks as the process would.
func openInProcessRoot(rootDir, name string) (*os.File, error) {
	r, err := os.OpenRoot(rootDir)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	resolved, err := resolveInRoot(r, name)
	if err != nil {
		return nil, err
	}
	return r.OpenFile(resolved, os.O_RDONLY|syscall.O_NONBLOCK, 0)
}

// maxSymlinks bounds the symlinks resolveInRoot follows, as Linux does.
const maxSymlinks = 40

// resolveInRoot returns name, a slash-separated path from the top of r, with
// its symlinks resolved as a process whose root r is would resolve them: an
// absolute target starts again from r's top, and ".." goes no higher. A
// root refuses absolute symlinks, which a process's own files often hold.
func resolveInRoot(r *os.Root, name string) (string, error) {
	pending := strings.Split(name, "/")
	var done []string
	for links := 0; len(pending) > 0; {
		elem := pending[0]
		pending = pending[1:]
		switch elem {
		case "", ".":
			continue
		case "..":
			done = done[:max(len(done)-1, 0)]
			continue
		}
		cur := path.Join(path.Join(done...), elem)
		fi, err := r.Lstat(cur)
		if err != nil {
			return "", err
		}
		if fi.Mode()&fs.ModeSymlink == 0 {
			done = append(done, elem)
			continue
		}
		if links++; links > maxSymlinks {
			return "", &fs.PathError{Op: "open", Path: name, Err: syscall.ELOOP}
		}
		target, err := r.Readlink(cur)
		if err != nil {
			return "", err
		}
		if path.IsAbs(target) {
			done = done[:0]
		}
		pending = slices.Concat(strings.Split(target, "/"), pending)
	}
	return cmp.Or(path.Join(done...), "."), nil
}
