// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package action

import (
	"bytes"
	"context"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"

	yarax "github.com/VirusTotal/yara-x/go"
	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/malcontent/pkg/file"
	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/chainguard-dev/malcontent/pkg/programkind"
	"github.com/chainguard-dev/malcontent/pkg/report"
	"github.com/chainguard-dev/malcontent/rules"
	thirdparty "github.com/chainguard-dev/malcontent/third_party"
	"github.com/puzpuzpuz/xsync/v4"
)

// scanTestLocaleScript is a shell profile fragment the bundled rules do not
// match, so scanning it yields a report without behaviors.
const scanTestLocaleScript = "export CHARSET=UTF-8\nexport LANG=C.UTF-8\nexport LC_COLLATE=C\n"

// scanTestNPMFixture is a package.json whose install script reads npm
// credentials and posts them over HTTP, which the bundled rules rate HIGH.
var scanTestNPMFixture = filepath.Join("testdata", "npm-token-exfil", "package.json")

// scanTestRules returns the bundled rules. Parallel tests share them so their
// scans reuse one scanner pool instead of rebuilding it for each rule set.
func scanTestRules(t *testing.T) (*yarax.Rules, []fs.FS) {
	t.Helper()
	rfs := []fs.FS{rules.FS, thirdparty.FS}
	yrs, err := CachedRules(t.Context(), rfs)
	if err != nil {
		t.Fatalf("CachedRules: %v", err)
	}
	return yrs, rfs
}

// scanTestLogBuffer collects log output written from concurrent goroutines.
type scanTestLogBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *scanTestLogBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *scanTestLogBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// scanTestLogger returns a logger that records warnings and errors.
func scanTestLogger() (*clog.Logger, *scanTestLogBuffer) {
	logs := &scanTestLogBuffer{}
	return clog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelWarn})), logs
}

// scanTestRenderer records the calls a scan makes to its renderer. onFile, if
// set, runs inside File with the context File received.
type scanTestRenderer struct {
	name    string
	fileErr error
	onFile  func(context.Context)

	mu       sync.Mutex
	scanning []string
	files    []*malcontent.FileReport
}

var _ malcontent.Renderer = (*scanTestRenderer)(nil)

func (r *scanTestRenderer) Scanning(_ context.Context, path string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.scanning = append(r.scanning, path)
}

func (r *scanTestRenderer) File(ctx context.Context, fr *malcontent.FileReport) error {
	r.mu.Lock()
	r.files = append(r.files, fr)
	r.mu.Unlock()
	if r.onFile != nil {
		r.onFile(ctx)
	}
	return r.fileErr
}

func (r *scanTestRenderer) Full(context.Context, *malcontent.Config, *malcontent.Report) error {
	return nil
}

func (r *scanTestRenderer) Name() string {
	return r.name
}

func (r *scanTestRenderer) scanned() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.scanning)
}

func (r *scanTestRenderer) rendered() []*malcontent.FileReport {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.files)
}

// scanTestWriteFile writes data to path, creating parent directories, and
// returns path.
func scanTestWriteFile(t *testing.T, path string, data []byte) string {
	t.Helper()
	dir := filepath.Dir(path)
	if err := file.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("create %s: %v", dir, err)
	}
	if err := file.WriteFileIn(dir, filepath.Base(path), data, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

// scanTestOpenRoot opens dir as an os.Root that is closed when tb finishes.
func scanTestOpenRoot(tb testing.TB, dir string) *os.Root {
	tb.Helper()
	root, err := os.OpenRoot(dir)
	if err != nil {
		tb.Fatalf("open root %s: %v", dir, err)
	}
	tb.Cleanup(func() { _ = root.Close() })
	return root
}

// scanTestReadDir returns the entries of dir, sorted by name, read through a
// root on dir.
func scanTestReadDir(dir string) ([]fs.DirEntry, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	return fs.ReadDir(root.FS(), ".")
}

// scanTestSniff sniffs the file at path through a root on its directory. The
// root stays open, and the contents read, until the test ends.
func scanTestSniff(t *testing.T, path string) *sniffed {
	t.Helper()
	root := scanTestOpenRoot(t, filepath.Dir(path))
	name := filepath.Base(path)
	fi, err := root.Stat(name)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	s := sniffFile(t.Context(), root, name, path, fi)
	t.Cleanup(s.close)
	return s
}

// scanTestHighestRisk returns the highest rule risk that scanSinglePath
// compares against the scan threshold for path.
func scanTestHighestRisk(t *testing.T, yrs *yarax.Rules, path, archiveRoot string, c malcontent.Config) int {
	t.Helper()
	kind, err := programkind.File(t.Context(), path)
	if err != nil {
		t.Fatalf("detect file type of %s: %v", path, err)
	}
	fc, err := file.ReadFileIn(filepath.Dir(path), filepath.Base(path))
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	scanner := yarax.NewScanner(yrs)
	defer scanner.Destroy()
	mrs, err := scanner.Scan(fc)
	if err != nil {
		t.Fatalf("scan %s: %v", path, err)
	}
	return report.HighestMatchRisk(mrs, kind, path, archiveRoot, c)
}

// scanTestFixture is a scan root holding one file the bundled rules match
// (hit) and one they do not (clean).
type scanTestFixture struct {
	root    string
	hit     string
	clean   string
	hitRisk int
}

func newScanTestFixture(t *testing.T, yrs *yarax.Rules, rfs []fs.FS) scanTestFixture {
	t.Helper()
	root := t.TempDir()
	fx := scanTestFixture{
		root:  root,
		hit:   scanTestWriteFile(t, filepath.Join(root, "app", "package.json"), readTestFile(t, scanTestNPMFixture)),
		clean: scanTestWriteFile(t, filepath.Join(root, "app", "locale.sh"), []byte(scanTestLocaleScript)),
	}

	c := malcontent.Config{Rules: yrs, RuleFS: rfs}
	hit, err := scanSinglePath(t.Context(), c, fx.hit, rfs, root, "", nil)
	if err != nil {
		t.Fatalf("scan %s: %v", fx.hit, err)
	}
	if len(hit.Behaviors) == 0 || hit.RiskScore < 1 {
		t.Fatalf("fixture precondition: %s: got behaviors = %d, risk = %d, want behaviors and risk >= 1", fx.hit, len(hit.Behaviors), hit.RiskScore)
	}
	clean, err := scanSinglePath(t.Context(), c, fx.clean, rfs, root, "", nil)
	if err != nil {
		t.Fatalf("scan %s: %v", fx.clean, err)
	}
	if len(clean.Behaviors) > 0 || clean.Skipped != "" {
		t.Fatalf("fixture precondition: %s: got behaviors = %d, skipped = %q, want a scanned file without behaviors", fx.clean, len(clean.Behaviors), clean.Skipped)
	}
	fx.hitRisk = hit.RiskScore
	return fx
}

// scanTestKeys returns the sorted keys of a report map.
func scanTestKeys(m *xsync.Map[string, *malcontent.FileReport]) []string {
	var keys []string
	m.Range(func(key string, _ *malcontent.FileReport) bool {
		keys = append(keys, key)
		return true
	})
	slices.Sort(keys)
	return keys
}

// scanTestMatchReport returns a report with one behavior per ID, each at risk.
func scanTestMatchReport(risk int, ids ...string) *malcontent.FileReport {
	fr := &malcontent.FileReport{Path: "/scan/match", RiskScore: risk}
	for _, id := range ids {
		fr.Behaviors = append(fr.Behaviors, &malcontent.Behavior{ID: id, RiskScore: risk})
	}
	return fr
}

// scanTestCaptureStdout runs fn with os.Stdout redirected to a file and
// returns what fn wrote. Callers must not run in parallel.
func scanTestCaptureStdout(t *testing.T, fn func()) string {
	t.Helper()
	root := scanTestOpenRoot(t, t.TempDir())
	f, name, err := file.CreateTemp(root, "stdout-*")
	if err != nil {
		t.Fatalf("create stdout capture: %v", err)
	}
	orig := os.Stdout
	os.Stdout = f
	func() {
		defer func() { os.Stdout = orig }()
		fn()
	}()
	if err := f.Close(); err != nil {
		t.Fatalf("close stdout capture: %v", err)
	}
	out, err := root.ReadFile(name)
	if err != nil {
		t.Fatalf("read stdout capture: %v", err)
	}
	return string(out)
}

// processTestPaths runs processPaths over paths, files found beneath
// scanInfo.effectivePath, through a walk root on it.
func processTestPaths(t *testing.T, paths []string, scanInfo scanPathInfo, c malcontent.Config, r *malcontent.Report, matchChan chan matchResult, once *sync.Once, logger *clog.Logger) error {
	t.Helper()
	w, _, err := openWalkRoot(scanInfo.effectivePath)
	if err != nil {
		t.Fatalf("openWalkRoot(%q): %v", scanInfo.effectivePath, err)
	}
	defer w.close()
	return processPaths(t.Context(), w, walkedFiles(w, paths), scanInfo, c, r, matchChan, once, logger)
}
