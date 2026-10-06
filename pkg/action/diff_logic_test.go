// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package action

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	orderedmap "github.com/wk8/go-ordered-map/v2"
)

// diffTestKeys returns the keys of a diff report section in insertion order.
func diffTestKeys(m *orderedmap.OrderedMap[string, *malcontent.FileReport]) []string {
	keys := make([]string, 0, m.Len())
	for pair := m.Oldest(); pair != nil; pair = pair.Next() {
		keys = append(keys, pair.Key)
	}
	return keys
}

// diffTestTempDir returns a temporary directory with symlinks resolved, so the
// paths a scan reports match the paths a test builds (macOS links /var to /private/var).
func diffTestTempDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	return dir
}

func diffTestWriteFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("MkdirAll(%q): %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile(%q): %v", path, err)
	}
}

// diffTestSymlinkedDir returns a resolved directory and a symlink to it, both
// inside a fresh temporary directory.
func diffTestSymlinkedDir(t *testing.T) (string, string) {
	t.Helper()
	root := diffTestTempDir(t)
	realDir, linkDir := filepath.Join(root, "real"), filepath.Join(root, "link")
	if err := os.MkdirAll(realDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(%q): %v", realDir, err)
	}
	if err := os.Symlink(realDir, linkDir); err != nil {
		t.Fatalf("Symlink(%q, %q): %v", realDir, linkDir, err)
	}
	return realDir, linkDir
}

func TestRelPathResolvesRelativePaths(t *testing.T) {
	t.Parallel()
	root := diffTestTempDir(t)
	appPath := filepath.Join(root, "sub", "app.sh")
	diffTestWriteFile(t, appPath, "#!/bin/sh\necho app\n")
	archivePath := filepath.Join(root, "pkg.tar")

	tests := []struct {
		name      string
		from      string
		fr        *malcontent.FileReport
		isArchive bool
		wantRel   string
		wantBase  string
	}{
		{
			name:     "directory scan path yields the path below the directory",
			from:     root,
			fr:       &malcontent.FileReport{Path: appPath},
			wantRel:  filepath.Join("sub", "app.sh"),
			wantBase: root,
		},
		{
			name:     "file scan path yields the path relative to its parent",
			from:     appPath,
			fr:       &malcontent.FileReport{Path: appPath},
			wantRel:  "app.sh",
			wantBase: appPath,
		},
		{
			name: "archive nested in a directory keeps the archive path below the directory",
			from: root,
			fr: &malcontent.FileReport{
				Path:        filepath.Join(root, "sub", "pkg.tar") + " ∴ /bin/tool",
				ArchiveRoot: "/tmp/mal-extract",
				FullPath:    "/tmp/mal-extract/bin/tool",
			},
			wantRel:  filepath.Join("sub", "pkg.tar") + " ∴ /bin/tool",
			wantBase: root,
		},
		{
			name: "archive scan path yields the path within the archive",
			from: archivePath,
			fr: &malcontent.FileReport{
				Path:        archivePath + " ∴ /bin/tool",
				ArchiveRoot: "/tmp/mal-extract",
				FullPath:    "/tmp/mal-extract/bin/tool",
			},
			isArchive: true,
			wantRel:   "/bin/tool",
			wantBase:  archivePath,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rel, base, err := relPath(tt.from, tt.fr, tt.isArchive)
			if err != nil {
				t.Fatalf("relPath: got error = %v, want nil", err)
			}
			if rel != tt.wantRel {
				t.Errorf("rel: got = %q, want = %q", rel, tt.wantRel)
			}
			if base != tt.wantBase {
				t.Errorf("base: got = %q, want = %q", base, tt.wantBase)
			}
		})
	}
}

func TestRelPathSymlinkedRoots(t *testing.T) {
	t.Parallel()
	realDir, linkDir := diffTestSymlinkedDir(t)
	diffTestWriteFile(t, filepath.Join(realDir, "src", "app.sh"), "#!/bin/sh\necho app\n")

	tests := []struct {
		name    string
		from    string
		path    string
		wantRel string
	}{
		{
			name:    "scan path through the symlink with a resolved file path",
			from:    filepath.Join(linkDir, "src"),
			path:    filepath.Join(realDir, "src", "app.sh"),
			wantRel: "app.sh",
		},
		{
			name:    "resolved scan path with a file path through the symlink",
			from:    filepath.Join(realDir, "src"),
			path:    filepath.Join(linkDir, "src", "app.sh"),
			wantRel: "app.sh",
		},
		{
			name:    "archive entry spelled through the symlink",
			from:    filepath.Join(linkDir, "src"),
			path:    filepath.Join(linkDir, "src", "pkg.tar") + " ∴ /bin/tool",
			wantRel: "pkg.tar ∴ /bin/tool",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rel, base, err := relPath(tt.from, &malcontent.FileReport{Path: tt.path}, false)
			if err != nil {
				t.Fatalf("relPath: got error = %v, want nil", err)
			}
			if rel != tt.wantRel {
				t.Errorf("rel: got = %q, want = %q", rel, tt.wantRel)
			}
			if base != tt.from {
				t.Errorf("base: got = %q, want = %q", base, tt.from)
			}
		})
	}
}

func TestRelPathFileInWorkingDirectory(t *testing.T) {
	// Not parallel: changes the working directory so the scan path is a bare
	// file name whose parent directory is ".".
	dir := diffTestTempDir(t)
	diffTestWriteFile(t, filepath.Join(dir, "app.sh"), "#!/bin/sh\necho app\n")
	t.Chdir(dir)

	rel, base, err := relPath("app.sh", &malcontent.FileReport{Path: "app.sh"}, false)
	if err != nil {
		t.Fatalf("relPath: got error = %v, want nil", err)
	}
	if rel != "app.sh" {
		t.Errorf("rel: got = %q, want = %q", rel, "app.sh")
	}
	if want := filepath.Join(dir, "app.sh"); base != want {
		t.Errorf("base: got = %q, want = %q", base, want)
	}
}

func TestRelPathMissingScanPath(t *testing.T) {
	t.Parallel()
	missing := filepath.Join(diffTestTempDir(t), "missing")
	rel, base, err := relPath(missing, &malcontent.FileReport{Path: filepath.Join(missing, "app")}, false)
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("relPath error: got = %v, want = %v", err, fs.ErrNotExist)
	}
	if rel != "" || base != "" {
		t.Errorf("paths on error: got = (%q, %q), want empty strings", rel, base)
	}
}

func TestArchiveEntryPath(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		fr   *malcontent.FileReport
		want string
	}{
		{
			name: "entry below its extraction root",
			fr:   &malcontent.FileReport{ArchiveRoot: "/tmp/mal-src1", FullPath: "/tmp/mal-src1/bin/tool", Path: "/scan/a.tar ∴ /bin/tool"},
			want: "/bin/tool",
		},
		{
			name: "same entry below a different extraction root",
			fr:   &malcontent.FileReport{ArchiveRoot: "/var/tmp/mal-dst22", FullPath: "/var/tmp/mal-dst22/bin/tool", Path: "/scan/b.tar ∴ /bin/tool"},
			want: "/bin/tool",
		},
		{
			name: "entry in nested directories",
			fr:   &malcontent.FileReport{ArchiveRoot: "/tmp/mal-src1", FullPath: "/tmp/mal-src1/usr/lib/libfoo.so.1"},
			want: "/usr/lib/libfoo.so.1",
		},
		{
			name: "entry without extraction paths uses the path after the separator",
			fr:   &malcontent.FileReport{Path: "/scan/a.tar ∴ /bin/tool"},
			want: "/bin/tool",
		},
		{
			name: "entry with a root but no full path uses the path after the separator",
			fr:   &malcontent.FileReport{ArchiveRoot: "/", Path: "/scan/a.tar ∴ /bin/tool"},
			want: "/bin/tool",
		},
		{
			name: "entry with a full path but no root uses the path after the separator",
			fr:   &malcontent.FileReport{FullPath: "bin/other", Path: "/scan/a.tar ∴ /bin/tool"},
			want: "/bin/tool",
		},
		{
			name: "entry outside its extraction root uses the path after the separator",
			fr:   &malcontent.FileReport{ArchiveRoot: "/mal-test-missing-root/x", FullPath: "/mal-test-other-root/bin/tool", Path: "/scan/a.tar ∴ /bin/tool"},
			want: "/bin/tool",
		},
		{
			name: "path without a separator is returned unchanged",
			fr:   &malcontent.FileReport{Path: "/plain/file"},
			want: "/plain/file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := archiveEntryPath(tt.fr); got != tt.want {
				t.Errorf("archiveEntryPath: got = %q, want = %q", got, tt.want)
			}
		})
	}
}

func TestArchiveEntryPathSymlinkedRoots(t *testing.T) {
	t.Parallel()
	realDir, linkDir := diffTestSymlinkedDir(t)
	// The extraction directory itself is gone by the time a diff runs.
	resolvedEntry := filepath.Join(realDir, "pkg.tar123", "bin", "tool.sh")
	linkedEntry := filepath.Join(linkDir, "pkg.tar123", "bin", "tool.sh")

	tests := []struct {
		name string
		fr   *malcontent.FileReport
	}{
		{
			name: "extraction root through the symlink",
			fr:   &malcontent.FileReport{ArchiveRoot: filepath.Join(linkDir, "pkg.tar123"), FullPath: resolvedEntry, Path: "/scan/a.tar ∴ " + resolvedEntry},
		},
		{
			name: "entry through the symlink",
			fr:   &malcontent.FileReport{ArchiveRoot: filepath.Join(realDir, "pkg.tar123"), FullPath: linkedEntry, Path: "/scan/a.tar ∴ " + linkedEntry},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := archiveEntryPath(tt.fr); got != "/bin/tool.sh" {
				t.Errorf("archiveEntryPath: got = %q, want = %q", got, "/bin/tool.sh")
			}
		})
	}
}

func TestResolvePath(t *testing.T) {
	t.Parallel()
	realDir, linkDir := diffTestSymlinkedDir(t)
	diffTestWriteFile(t, filepath.Join(realDir, "file"), "x")
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	resolvedWD, err := filepath.EvalSymlinks(wd)
	if err != nil {
		t.Fatalf("EvalSymlinks(%q): %v", wd, err)
	}

	tests := []struct {
		name string
		path string
		want string
	}{
		{name: "existing file through a symlink", path: filepath.Join(linkDir, "file"), want: filepath.Join(realDir, "file")},
		{name: "removed path below a symlink", path: filepath.Join(linkDir, "gone", "child"), want: filepath.Join(realDir, "gone", "child")},
		{name: "symlink itself", path: linkDir, want: realDir},
		{name: "relative missing path is made absolute", path: "mal-test-missing-entry", want: filepath.Join(resolvedWD, "mal-test-missing-entry")},
		{name: "filesystem root", path: "/", want: "/"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := resolvePath(tt.path); got != tt.want {
				t.Errorf("resolvePath(%q): got = %q, want = %q", tt.path, got, tt.want)
			}
		})
	}
}

func TestPathWithin(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		path string
		root string
		want bool
	}{
		{name: "child of the root", path: "/a/b", root: "/a", want: true},
		{name: "the root itself", path: "/a", root: "/a", want: true},
		{name: "sibling sharing a name prefix", path: "/ab", root: "/a", want: false},
		{name: "unrelated path", path: "/b/c", root: "/a", want: false},
		{name: "root with a trailing separator", path: "/a/b", root: "/a/", want: true},
		{name: "filesystem root", path: "/a/b", root: "/", want: true},
		{name: "local path under the current directory", path: "a/b", root: ".", want: true},
		{name: "parent path under the current directory", path: "../a", root: ".", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := pathWithin(tt.path, tt.root); got != tt.want {
				t.Errorf("pathWithin(%q, %q): got = %v, want = %v", tt.path, tt.root, got, tt.want)
			}
		})
	}
}

func TestSelectPrimaryFilePrefersNonBackup(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		files map[string]*malcontent.FileReport
		want  string
	}{
		{
			name: "backup sorting first is passed over for the primary file",
			files: map[string]*malcontent.FileReport{
				"/a.~": {Path: "/a.~"},
				"/b":   {Path: "/b"},
			},
			want: "/b",
		},
		{
			name: "several primary files selects the first in sorted order",
			files: map[string]*malcontent.FileReport{
				"/c":   {Path: "/c"},
				"/b.~": {Path: "/b.~"},
				"/b":   {Path: "/b"},
			},
			want: "/b",
		},
		{
			name: "only backups selects the first in sorted order",
			files: map[string]*malcontent.FileReport{
				"/b.~": {Path: "/b.~"},
				"/a.~": {Path: "/a.~"},
			},
			want: "/a.~",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := selectPrimaryFile(tt.files)
			if got == nil {
				t.Fatalf("selectPrimaryFile: got = nil, want path %q", tt.want)
			}
			if got.Path != tt.want {
				t.Errorf("selectPrimaryFile: got = %q, want = %q", got.Path, tt.want)
			}
		})
	}
}

func TestParseBehaviorID(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		id   string
		want behavior
	}{
		{name: "empty ID", id: "", want: behavior{}},
		{name: "objective only", id: "anti-static", want: behavior{objective: "anti-static"}},
		{name: "objective and resource", id: "anti-static/base64", want: behavior{objective: "anti-static", resource: "base64"}},
		{name: "objective, resource, and technique", id: "anti-static/base64/eval", want: behavior{objective: "anti-static", resource: "base64", technique: "eval"}},
		{name: "deeper paths join into the technique", id: "anti-static/base64/eval/nested", want: behavior{objective: "anti-static", resource: "base64", technique: "eval/nested"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := parseBehaviorID(tt.id); got != tt.want {
				t.Errorf("parseBehaviorID(%q): got = %+v, want = %+v", tt.id, got, tt.want)
			}
		})
	}
}

func TestExtractBehaviors(t *testing.T) {
	t.Parallel()
	behaviors := []*malcontent.Behavior{
		{ID: "anti-static/base64/eval"},
		nil,
		{ID: "c2/addr/ip"},
		{ID: "exfil"},
		{ID: ""},
		{ID: "/addr"},
		{ID: "anti-static/base64/eval"},
	}

	tests := []struct {
		name        string
		sensitivity int
		want        map[string]struct{}
	}{
		{
			name:        "objective level keeps top-level categories",
			sensitivity: OBJECTIVE,
			want:        map[string]struct{}{"anti-static": {}, "c2": {}, "exfil": {}},
		},
		{
			name:        "resource level keeps objective and resource, or the objective alone, and needs an objective",
			sensitivity: RESOURCE,
			want:        map[string]struct{}{"anti-static/base64": {}, "c2/addr": {}, "exfil": {}},
		},
		{
			name:        "technique level keeps full non-empty IDs",
			sensitivity: TECHNIQUE,
			want:        map[string]struct{}{"anti-static/base64/eval": {}, "c2/addr/ip": {}, "exfil": {}, "/addr": {}},
		},
		{
			name:        "risk-change level extracts nothing",
			sensitivity: CHANGE,
			want:        map[string]struct{}{},
		},
		{
			name:        "all level extracts nothing",
			sensitivity: ALL,
			want:        map[string]struct{}{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := extractBehaviors(behaviors, tt.sensitivity); !maps.Equal(got, tt.want) {
				t.Errorf("extractBehaviors: got = %v, want = %v", got, tt.want)
			}
		})
	}
}

func TestFilterDiffSensitivity(t *testing.T) {
	t.Parallel()
	withRisk := func(risk int, ids ...string) *malcontent.FileReport {
		bs := make([]*malcontent.Behavior, 0, len(ids))
		for _, id := range ids {
			bs = append(bs, &malcontent.Behavior{ID: id})
		}
		return &malcontent.FileReport{Path: "/bin/app", RiskScore: risk, Behaviors: bs}
	}
	const base = "anti-static/base64/eval"

	// Sensitivity values are the integers the CLI's --sensitivity flag passes
	// through (1-5); zero means the flag was not set.
	tests := []struct {
		name string
		c    malcontent.Config
		src  *malcontent.FileReport
		dest *malcontent.FileReport
		want bool
	}{
		{name: "unset sensitivity keeps identical files", c: malcontent.Config{}, src: withRisk(2, base), dest: withRisk(2, base), want: false},
		{name: "unset sensitivity keeps a risk decrease", c: malcontent.Config{}, src: withRisk(3, base), dest: withRisk(2, base), want: false},
		{name: "unset sensitivity keeps a risk increase", c: malcontent.Config{}, src: withRisk(2, base), dest: withRisk(3, base), want: false},
		{name: "sensitivity 1 drops unchanged risk", c: malcontent.Config{Sensitivity: 1}, src: withRisk(2, base), dest: withRisk(2, "c2/addr/ip"), want: true},
		{name: "sensitivity 1 keeps changed risk", c: malcontent.Config{Sensitivity: 1}, src: withRisk(2, base), dest: withRisk(3, base), want: false},
		{name: "sensitivity 2 drops a resource-only change", c: malcontent.Config{Sensitivity: 2}, src: withRisk(2, base), dest: withRisk(3, "anti-static/hex/eval"), want: true},
		{name: "sensitivity 2 keeps an objective change", c: malcontent.Config{Sensitivity: 2}, src: withRisk(2, base), dest: withRisk(2, "c2/base64/eval"), want: false},
		{name: "sensitivity 3 drops a technique-only change", c: malcontent.Config{Sensitivity: 3}, src: withRisk(2, base), dest: withRisk(3, "anti-static/base64/exec"), want: true},
		{name: "sensitivity 3 keeps a resource change", c: malcontent.Config{Sensitivity: 3}, src: withRisk(2, base), dest: withRisk(2, "anti-static/hex/eval"), want: false},
		{name: "sensitivity 4 drops identical behaviors despite a risk change", c: malcontent.Config{Sensitivity: 4}, src: withRisk(2, base), dest: withRisk(3, base), want: true},
		{name: "sensitivity 4 keeps an added technique", c: malcontent.Config{Sensitivity: 4}, src: withRisk(2, base), dest: withRisk(2, base, "anti-static/base64/exec"), want: false},
		{name: "sensitivity 4 keeps a removed technique", c: malcontent.Config{Sensitivity: 4}, src: withRisk(2, base, "anti-static/base64/exec"), dest: withRisk(2, base), want: false},
		{name: "sensitivity 5 keeps identical files even with the risk-change flag", c: malcontent.Config{Sensitivity: 5, FileRiskChange: true}, src: withRisk(2, base), dest: withRisk(2, base), want: false},
		{name: "risk-change flag drops unchanged risk", c: malcontent.Config{FileRiskChange: true}, src: withRisk(2, base), dest: withRisk(2, base), want: true},
		{name: "risk-change flag keeps changed risk", c: malcontent.Config{FileRiskChange: true}, src: withRisk(2, base), dest: withRisk(1, base), want: false},
		{name: "risk-increase flag drops unchanged risk", c: malcontent.Config{FileRiskIncrease: true}, src: withRisk(2, base), dest: withRisk(2, base), want: true},
		{name: "risk-increase flag drops decreased risk", c: malcontent.Config{FileRiskIncrease: true}, src: withRisk(3, base), dest: withRisk(2, base), want: true},
		{name: "risk-increase flag keeps increased risk", c: malcontent.Config{FileRiskIncrease: true}, src: withRisk(2, base), dest: withRisk(3, base), want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := filterDiff(t.Context(), tt.c, tt.src, tt.dest); got != tt.want {
				t.Errorf("filterDiff: got = %v, want = %v", got, tt.want)
			}
		})
	}
}

func TestExtractPath(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name           string
		rel            string
		path           string
		res            ScanResult
		archiveOrImage bool
		isReport       bool
		want           string
	}{
		{
			name:     "report path with an image separator keeps the in-image path",
			rel:      "unused",
			path:     "cgr.dev/org/img:1 ∴ /usr/bin/app",
			isReport: true,
			want:     "/usr/bin/app",
		},
		{
			name:     "report path with nested separators keeps everything after the first",
			rel:      "unused",
			path:     "cgr.dev/org/img:1 ∴ /lib/pkg.tar ∴ /bin/app",
			isReport: true,
			want:     "/lib/pkg.tar ∴ /bin/app",
		},
		{
			name:     "report path under a temp root is trimmed",
			rel:      "unused",
			path:     "/tmp/mal-1/usr/bin/app",
			res:      ScanResult{tmpRoot: "/tmp/mal-1"},
			isReport: true,
			want:     "/usr/bin/app",
		},
		{
			name:     "relative report path gains a leading slash",
			rel:      "unused",
			path:     "usr/bin/app",
			isReport: true,
			want:     "/usr/bin/app",
		},
		{
			name:           "archive path under the temp root is trimmed",
			rel:            "bin/app",
			path:           "/tmp/extract/bin/app",
			res:            ScanResult{tmpRoot: "/tmp/extract"},
			archiveOrImage: true,
			want:           "/bin/app",
		},
		{
			name:           "archive path without a temp root keeps the relative path",
			rel:            "bin/app",
			path:           "/scan/bin/app",
			archiveOrImage: true,
			want:           "bin/app",
		},
		{
			name: "plain path ignores the temp root",
			rel:  "bin/app",
			path: "/tmp/extract/bin/app",
			res:  ScanResult{tmpRoot: "/tmp/extract"},
			want: "bin/app",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := extractPath(tt.rel, &malcontent.FileReport{Path: tt.path}, tt.res, tt.archiveOrImage, tt.isReport)
			if got != tt.want {
				t.Errorf("extractPath: got = %q, want = %q", got, tt.want)
			}
		})
	}
}

func TestFormatKeyPrefixes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		res  ScanResult
		want string
	}{
		{name: "scan base prefixes the name", res: ScanResult{base: "/scan/root"}, want: "/scan/root ∴ /bin/ls"},
		{name: "image reference takes precedence over the scan base", res: ScanResult{base: "/scan/root", imageURI: "cgr.dev/org/img:1"}, want: "cgr.dev/org/img:1 ∴ /bin/ls"},
		{name: "no prefix returns the name", res: ScanResult{}, want: "/bin/ls"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := formatKey(tt.res, "/bin/ls"); got != tt.want {
				t.Errorf("formatKey: got = %q, want = %q", got, tt.want)
			}
		})
	}
}

func TestHandleDirSkipsBackupsAndEmptyKeys(t *testing.T) {
	t.Parallel()
	// Enough entries that stopping at the first skipped key, rather than
	// moving past it, leaves files out regardless of map iteration order.
	build := func() (map[string]*malcontent.FileReport, []string) {
		frs := map[string]*malcontent.FileReport{
			"":          {Path: "/scan/unnamed"},
			"bin/app":   {Path: "/scan/bin/app"},
			"bin/app.~": {Path: "/scan/bin/app.~"},
		}
		want := make([]string, 0, 13)
		want = append(want, "/scan/bin/app")
		for i := range 12 {
			rel := fmt.Sprintf("lib/mod%02d.sh", i)
			frs[rel] = &malcontent.FileReport{Path: "/scan/" + rel}
			want = append(want, "/scan/"+rel)
		}
		return frs, want
	}

	t.Run("source-only files are removed", func(t *testing.T) {
		t.Parallel()
		frs, want := build()
		d := runHandleDir(t, malcontent.Config{}, frs, nil)
		if got := diffTestKeys(d.Removed); !slices.Equal(got, want) {
			t.Errorf("Removed keys: got = %q, want = %q", got, want)
		}
		if n := d.Added.Len() + d.Modified.Len(); n != 0 {
			t.Errorf("added and modified entries: got = %d, want = 0", n)
		}
	})

	t.Run("destination-only files are added", func(t *testing.T) {
		t.Parallel()
		frs, want := build()
		d := runHandleDir(t, malcontent.Config{}, nil, frs)
		if got := diffTestKeys(d.Added); !slices.Equal(got, want) {
			t.Errorf("Added keys: got = %q, want = %q", got, want)
		}
		if n := d.Removed.Len() + d.Modified.Len(); n != 0 {
			t.Errorf("removed and modified entries: got = %d, want = 0", n)
		}
	})
}

func TestHandleDirReconcilesMatchingFiles(t *testing.T) {
	t.Parallel()
	build := func() (map[string]*malcontent.FileReport, map[string]*malcontent.FileReport) {
		src := map[string]*malcontent.FileReport{
			"bin/riskier":     {Path: "/old/bin/riskier", RiskScore: 1},
			"bin/same":        {Path: "/old/bin/same", RiskScore: 1},
			"lib/libfoo.so.1": {Path: "/old/lib/libfoo.so.1", RiskScore: 1},
		}
		dest := map[string]*malcontent.FileReport{
			"bin/riskier":     {Path: "/new/bin/riskier", RiskScore: 3},
			"bin/same":        {Path: "/new/bin/same", RiskScore: 1},
			"lib/libfoo.so.2": {Path: "/new/lib/libfoo.so.2", RiskScore: 2},
		}
		return src, dest
	}

	tests := []struct {
		name string
		c    malcontent.Config
		want []string
	}{
		{
			name: "default configuration reports every matched pair",
			c:    malcontent.Config{},
			want: []string{"/new/bin/riskier", "/new/bin/same", "/new/lib/libfoo.so.2"},
		},
		{
			name: "risk-change filter skips an unchanged pair and keeps later pairs",
			c:    malcontent.Config{FileRiskChange: true},
			want: []string{"/new/bin/riskier", "/new/lib/libfoo.so.2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			src, dest := build()
			d := runHandleDir(t, tt.c, src, dest)
			if got := diffTestKeys(d.Modified); !slices.Equal(got, tt.want) {
				t.Fatalf("Modified keys: got = %q, want = %q", got, tt.want)
			}
			if n := d.Added.Len() + d.Removed.Len(); n != 0 {
				t.Errorf("added and removed entries: got = %d, want = 0", n)
			}
			moved, ok := d.Modified.Get("/new/lib/libfoo.so.2")
			if !ok {
				t.Fatalf("Modified: got no entry for the versioned library, want one")
			}
			if moved.PreviousPath != "/old/lib/libfoo.so.1" {
				t.Errorf("moved PreviousPath: got = %q, want = %q", moved.PreviousPath, "/old/lib/libfoo.so.1")
			}
			changed, ok := d.Modified.Get("/new/bin/riskier")
			if !ok {
				t.Fatalf("Modified: got no entry for the changed file, want one")
			}
			if changed.PreviousPath != "" {
				t.Errorf("changed PreviousPath: got = %q, want empty", changed.PreviousPath)
			}
		})
	}
}

func TestFileDiffMinFileRisk(t *testing.T) {
	t.Parallel()
	// A pair is dropped only when both sides fall below the minimum file risk.
	tests := []struct {
		name      string
		src, dest int
		want      bool
	}{
		{name: "both sides below the minimum are dropped", src: 1, dest: 1, want: false},
		{name: "source at the minimum is kept", src: 2, dest: 1, want: true},
		{name: "destination at the minimum is kept", src: 1, dest: 2, want: true},
		{name: "source above the minimum is kept", src: 3, dest: 0, want: true},
		{name: "destination above the minimum is kept", src: 0, dest: 3, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			d := newDiffReportForTest()
			fr := &malcontent.FileReport{Path: "/old/app", RiskScore: tt.src}
			tr := &malcontent.FileReport{Path: "/new/app", RiskScore: tt.dest}
			fileDiff(t.Context(), malcontent.Config{MinFileRisk: 2}, fr, tr, "/old/app", "/new/app", d, ScanResult{}, ScanResult{}, false, false, false)
			if _, got := d.Modified.Get("/new/app"); got != tt.want {
				t.Errorf("Modified entry present: got = %v, want = %v", got, tt.want)
			}
		})
	}
}

func TestFileDiffBehaviorChanges(t *testing.T) {
	t.Parallel()
	src := &malcontent.FileReport{
		Path:            "/old/app",
		PreviousRelPath: "app",
		RiskScore:       2,
		RiskLevel:       "MEDIUM",
		Behaviors: []*malcontent.Behavior{
			{ID: "net/socket/listen"},
			{ID: "c2/addr/ip"},
		},
	}
	dest := &malcontent.FileReport{
		Path:      "/new/app",
		RiskScore: 3,
		RiskLevel: "HIGH",
		Behaviors: []*malcontent.Behavior{
			{ID: "net/socket/listen"},
			{ID: "exec/shell/command"},
			{ID: "anti-static/base64/eval"},
		},
	}

	d := newDiffReportForTest()
	d.Removed.Set("/old/app", src)
	d.Added.Set("/new/app", dest)
	fileDiff(t.Context(), malcontent.Config{}, src, dest, "/old/app", "/new/app", d, ScanResult{}, ScanResult{}, false, false, false)

	if n := d.Removed.Len() + d.Added.Len(); n != 0 {
		t.Errorf("added and removed entries after pairing: got = %d, want = 0", n)
	}
	mod, ok := d.Modified.Get("/new/app")
	if !ok {
		t.Fatalf("Modified keys: got = %q, want [/new/app]", diffTestKeys(d.Modified))
	}

	fields := []struct {
		name      string
		got, want any
	}{
		{"Path", mod.Path, "/new/app"},
		{"PreviousPath", mod.PreviousPath, ""},
		{"PreviousRelPath", mod.PreviousRelPath, "app"},
		{"PreviousRiskScore", mod.PreviousRiskScore, 2},
		{"PreviousRiskLevel", mod.PreviousRiskLevel, "MEDIUM"},
		{"RiskScore", mod.RiskScore, 3},
		{"RiskLevel", mod.RiskLevel, "HIGH"},
	}
	for _, f := range fields {
		if f.got != f.want {
			t.Errorf("%s: got = %v, want = %v", f.name, f.got, f.want)
		}
	}

	type change struct {
		id             string
		added, removed bool
	}
	want := []change{
		{id: "anti-static/base64/eval", added: true},
		{id: "c2/addr/ip", removed: true},
		{id: "exec/shell/command", added: true},
	}
	got := make([]change, 0, len(mod.Behaviors))
	for _, b := range mod.Behaviors {
		got = append(got, change{id: b.ID, added: b.DiffAdded, removed: b.DiffRemoved})
	}
	if !slices.Equal(got, want) {
		t.Errorf("Behaviors: got = %+v, want = %+v", got, want)
	}
}

func TestFileDiffPathFormatting(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name           string
		srcPath        string
		destPath       string
		rpath, apath   string
		src, dest      ScanResult
		archiveOrImage bool
		isReport       bool
		isMoved        bool
		wantPath       string
		wantPrevious   string
	}{
		{
			name:     "plain change keeps the destination path",
			srcPath:  "/old/bin/app",
			destPath: "/new/bin/app",
			rpath:    "/old ∴ /old/bin/app",
			apath:    "/new ∴ /new/bin/app",
			wantPath: "/new/bin/app",
		},
		{
			name:         "plain move records the source path",
			srcPath:      "/old/lib/libfoo.so.1",
			destPath:     "/new/lib/libfoo.so.2",
			rpath:        "/old ∴ /old/lib/libfoo.so.1",
			apath:        "/new ∴ /new/lib/libfoo.so.2",
			isMoved:      true,
			wantPath:     "/new/lib/libfoo.so.2",
			wantPrevious: "/old/lib/libfoo.so.1",
		},
		{
			name:           "archive or image move reports both report keys",
			srcPath:        "/tmp/img1/usr/lib/libfoo.so.1",
			destPath:       "/tmp/img2/usr/lib/libfoo.so.2",
			rpath:          "cgr.dev/org/img:1 ∴ /usr/lib/libfoo.so.1",
			apath:          "cgr.dev/org/img:2 ∴ /usr/lib/libfoo.so.2",
			archiveOrImage: true,
			isMoved:        true,
			wantPath:       "cgr.dev/org/img:2 ∴ /usr/lib/libfoo.so.2",
			wantPrevious:   "cgr.dev/org/img:1 ∴ /usr/lib/libfoo.so.1",
		},
		{
			name:           "archive or image change reports the destination key only",
			srcPath:        "/tmp/a1/bin/tool",
			destPath:       "/tmp/a2/bin/tool",
			rpath:          "/scan/a-1.tar ∴ /bin/tool",
			apath:          "/scan/a-2.tar ∴ /bin/tool",
			archiveOrImage: true,
			wantPath:       "/scan/a-2.tar ∴ /bin/tool",
		},
		{
			name:         "report move removes temp roots from both paths",
			srcPath:      "/tmp/a1/b1/T/mal1/usr/lib/libfoo.so.1",
			destPath:     "/tmp/a2/b2/T/mal2/usr/lib/libfoo.so.2",
			rpath:        "/usr/lib/libfoo.so.1",
			apath:        "/usr/lib/libfoo.so.2",
			src:          ScanResult{tmpRoot: "/tmp/a1/b1/T/mal1"},
			dest:         ScanResult{tmpRoot: "/tmp/a2/b2/T/mal2"},
			isReport:     true,
			isMoved:      true,
			wantPath:     "/usr/lib/libfoo.so.2",
			wantPrevious: "/usr/lib/libfoo.so.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			d := newDiffReportForTest()
			fr := &malcontent.FileReport{Path: tt.srcPath}
			tr := &malcontent.FileReport{Path: tt.destPath}
			fileDiff(t.Context(), malcontent.Config{}, fr, tr, tt.rpath, tt.apath, d, tt.src, tt.dest, tt.archiveOrImage, tt.isReport, tt.isMoved)
			mod, ok := d.Modified.Get(tt.apath)
			if !ok {
				t.Fatalf("Modified keys: got = %q, want [%s]", diffTestKeys(d.Modified), tt.apath)
			}
			if mod.Path != tt.wantPath {
				t.Errorf("Path: got = %q, want = %q", mod.Path, tt.wantPath)
			}
			if mod.PreviousPath != tt.wantPrevious {
				t.Errorf("PreviousPath: got = %q, want = %q", mod.PreviousPath, tt.wantPrevious)
			}
		})
	}
}

func TestHandleDirArchiveAndImageKeys(t *testing.T) {
	t.Parallel()
	type modified struct {
		key, path, previous string
	}
	tests := []struct {
		name         string
		src, dest    ScanResult
		wantRemoved  []string
		wantAdded    []string
		wantModified []modified
	}{
		{
			name: "image files pair by their path below the extraction root",
			src: ScanResult{
				imageURI: "cgr.dev/org/img:1",
				tmpRoot:  "/tmp/img1",
				files: map[string]*malcontent.FileReport{
					"usr/bin/app":         {Path: "/tmp/img1/usr/bin/app"},
					"usr/sbin/app":        {Path: "/tmp/img1/usr/sbin/app"},
					"usr/lib/libfoo.so.1": {Path: "/tmp/img1/usr/lib/libfoo.so.1"},
					"etc/gone":            {Path: "/tmp/img1/etc/gone"},
				},
			},
			dest: ScanResult{
				imageURI: "cgr.dev/org/img:2",
				tmpRoot:  "/tmp/img2",
				files: map[string]*malcontent.FileReport{
					"usr/bin/app":         {Path: "/tmp/img2/usr/bin/app"},
					"usr/sbin/app":        {Path: "/tmp/img2/usr/sbin/app"},
					"usr/lib/libfoo.so.2": {Path: "/tmp/img2/usr/lib/libfoo.so.2"},
					"etc/new":             {Path: "/tmp/img2/etc/new"},
				},
			},
			wantRemoved: []string{"cgr.dev/org/img:1 ∴ /etc/gone"},
			wantAdded:   []string{"cgr.dev/org/img:2 ∴ /etc/new"},
			wantModified: []modified{
				{key: "cgr.dev/org/img:2 ∴ /usr/bin/app", path: "cgr.dev/org/img:2 ∴ /usr/bin/app"},
				{key: "cgr.dev/org/img:2 ∴ /usr/lib/libfoo.so.2", path: "cgr.dev/org/img:2 ∴ /usr/lib/libfoo.so.2", previous: "cgr.dev/org/img:1 ∴ /usr/lib/libfoo.so.1"},
				{key: "cgr.dev/org/img:2 ∴ /usr/sbin/app", path: "cgr.dev/org/img:2 ∴ /usr/sbin/app"},
			},
		},
		{
			name: "archive entries pair by their path within the archive",
			src: ScanResult{
				base:      "/scan/pkg-1.0.tar",
				isArchive: true,
				files: map[string]*malcontent.FileReport{
					"/bin/tool": {Path: "/scan/pkg-1.0.tar ∴ /bin/tool", ArchiveRoot: "/tmp/pkg-1.0.tar1", FullPath: "/tmp/pkg-1.0.tar1/bin/tool"},
					"/bin/gone": {Path: "/scan/pkg-1.0.tar ∴ /bin/gone"},
				},
			},
			dest: ScanResult{
				base:      "/scan/pkg-1.1.tar",
				isArchive: true,
				files: map[string]*malcontent.FileReport{
					"/bin/tool": {Path: "/scan/pkg-1.1.tar ∴ /bin/tool"},
					"/bin/new":  {Path: "/scan/pkg-1.1.tar ∴ /bin/new", ArchiveRoot: "/tmp/pkg-1.1.tar2", FullPath: "/tmp/pkg-1.1.tar2/bin/new"},
				},
			},
			wantRemoved: []string{"/scan/pkg-1.0.tar ∴ /bin/gone"},
			wantAdded:   []string{"/scan/pkg-1.1.tar ∴ /bin/new"},
			wantModified: []modified{
				{key: "/scan/pkg-1.1.tar ∴ /bin/tool", path: "/scan/pkg-1.1.tar ∴ /bin/tool"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			d := newDiffReportForTest()
			handleDir(t.Context(), malcontent.Config{}, tt.src, tt.dest, d, true, false)
			if got := diffTestKeys(d.Removed); !slices.Equal(got, tt.wantRemoved) {
				t.Errorf("Removed keys: got = %q, want = %q", got, tt.wantRemoved)
			}
			if got := diffTestKeys(d.Added); !slices.Equal(got, tt.wantAdded) {
				t.Errorf("Added keys: got = %q, want = %q", got, tt.wantAdded)
			}
			got := make([]modified, 0, d.Modified.Len())
			for pair := d.Modified.Oldest(); pair != nil; pair = pair.Next() {
				got = append(got, modified{key: pair.Key, path: pair.Value.Path, previous: pair.Value.PreviousPath})
			}
			if !slices.Equal(got, tt.wantModified) {
				t.Errorf("Modified: got = %+v, want = %+v", got, tt.wantModified)
			}
		})
	}
}

func TestHandleDirOrdersModifiedByDestinationPath(t *testing.T) {
	t.Parallel()
	// The versioned library moves past its unchanged sibling:
	// lib/libfoo.so.1 sorts before lib/libfoo.so.10, but lib/libfoo.so.2
	// sorts after it.
	src := map[string]*malcontent.FileReport{
		"lib/libfoo.so.1":  {Path: "/old/lib/libfoo.so.1"},
		"lib/libfoo.so.10": {Path: "/old/lib/libfoo.so.10"},
	}
	dest := map[string]*malcontent.FileReport{
		"lib/libfoo.so.10": {Path: "/new/lib/libfoo.so.10"},
		"lib/libfoo.so.2":  {Path: "/new/lib/libfoo.so.2"},
	}
	d := runHandleDir(t, malcontent.Config{}, src, dest)
	if want := []string{"/new/lib/libfoo.so.10", "/new/lib/libfoo.so.2"}; !slices.Equal(diffTestKeys(d.Modified), want) {
		t.Errorf("Modified keys: got = %q, want = %q", diffTestKeys(d.Modified), want)
	}
	moved, ok := d.Modified.Get("/new/lib/libfoo.so.2")
	if !ok || moved.PreviousPath != "/old/lib/libfoo.so.1" {
		t.Errorf("moved library: got = %+v, want it paired with /old/lib/libfoo.so.1", moved)
	}
}

func TestDiffStepsStopOnCanceledContext(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	pair := func() (*malcontent.FileReport, *malcontent.FileReport) {
		return &malcontent.FileReport{Path: "/old/bin/app", RiskScore: 2}, &malcontent.FileReport{Path: "/new/bin/app", RiskScore: 2}
	}

	t.Run("handleDir records nothing", func(t *testing.T) {
		t.Parallel()
		fr, tr := pair()
		src := ScanResult{files: map[string]*malcontent.FileReport{"bin/app": fr, "bin/gone": {Path: "/old/bin/gone"}}}
		dest := ScanResult{files: map[string]*malcontent.FileReport{"bin/app": tr, "bin/new": {Path: "/new/bin/new"}}}
		d := newDiffReportForTest()
		handleDir(ctx, malcontent.Config{}, src, dest, d, false, false)
		if n := d.Added.Len() + d.Removed.Len() + d.Modified.Len(); n != 0 {
			t.Errorf("entries: got = %d, want = 0", n)
		}
	})
	t.Run("fileDiff records nothing", func(t *testing.T) {
		t.Parallel()
		fr, tr := pair()
		d := newDiffReportForTest()
		fileDiff(ctx, malcontent.Config{}, fr, tr, fr.Path, tr.Path, d, ScanResult{}, ScanResult{}, false, false, false)
		if n := d.Modified.Len(); n != 0 {
			t.Errorf("modified entries: got = %d, want = 0", n)
		}
	})
	t.Run("filterDiff drops nothing", func(t *testing.T) {
		t.Parallel()
		fr, tr := pair()
		if filterDiff(ctx, malcontent.Config{FileRiskChange: true}, fr, tr) {
			t.Errorf("filterDiff: got = true, want = false")
		}
	})
}

// TestPathHelpersWithoutWorkingDirectory covers relative paths that cannot be
// made absolute because the working directory was removed.
func TestPathHelpersWithoutWorkingDirectory(t *testing.T) {
	// Not parallel: changes and removes the working directory.
	if runtime.GOOS != "linux" {
		t.Skip("relies on Linux failing to name a removed working directory")
	}
	gone := filepath.Join(t.TempDir(), "gone")
	if err := os.Mkdir(gone, 0o700); err != nil {
		t.Fatalf("Mkdir(%q): %v", gone, err)
	}
	t.Chdir(gone)
	if err := os.Remove(gone); err != nil {
		t.Fatalf("Remove(%q): %v", gone, err)
	}
	if wd, err := os.Getwd(); err == nil {
		t.Fatalf("fixture precondition: Getwd after removal: got = %q, want an error", wd)
	}
	root := filepath.Join(t.TempDir(), "root")
	entry := filepath.Join(root, "bin", "tool")

	t.Run("relPath reports the failure for an archive scan path", func(t *testing.T) {
		if _, _, err := relPath("pkg.tar", &malcontent.FileReport{Path: "pkg.tar ∴ /bin/tool"}, true); err == nil {
			t.Errorf("relPath error: got = nil, want the working directory failure")
		}
	})
	t.Run("resolvePath cleans a path it cannot make absolute", func(t *testing.T) {
		if got, want := resolvePath("lib/../bin/tool"), filepath.Join("bin", "tool"); got != want {
			t.Errorf("resolvePath: got = %q, want = %q", got, want)
		}
	})
	t.Run("archivePaths reports the failure for a relative entry path", func(t *testing.T) {
		if _, _, err := archivePaths(&malcontent.FileReport{}, malcontent.Config{}, filepath.Join("bin", "tool"), "/scans/pkg.tar", root); err == nil {
			t.Errorf("archivePaths error: got = nil, want the working directory failure")
		}
	})
	t.Run("archivePaths reports the failure for a relative archive root", func(t *testing.T) {
		if _, _, err := archivePaths(&malcontent.FileReport{}, malcontent.Config{}, entry, "/scans/pkg.tar", "root"); err == nil {
			t.Errorf("archivePaths error: got = nil, want the working directory failure")
		}
	})
}
