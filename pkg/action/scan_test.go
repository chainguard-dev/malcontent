// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package action

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/chainguard-dev/malcontent/rules"
	thirdparty "github.com/chainguard-dev/malcontent/third_party"
	"github.com/puzpuzpuz/xsync/v4"

	yarax "github.com/VirusTotal/yara-x/go"
)

// countOpenFDs returns the number of open file descriptors for the current process.
// Returns -1 if unable to count (e.g., on unsupported platforms).
func countOpenFDs(t *testing.T) int {
	t.Helper()

	// Linux: count entries in /proc/self/fd
	if entries, err := scanTestReadDir("/proc/self/fd"); err == nil {
		return len(entries)
	}

	// macOS: count entries in /dev/fd
	if entries, err := scanTestReadDir("/dev/fd"); err == nil {
		return len(entries)
	}

	return -1
}

// TestScanSinglePathNoFDLeak verifies that early return paths in scanSinglePath
// properly close file handles and don't leak file descriptors.
func TestScanSinglePathNoFDLeak(t *testing.T) {
	ctx := t.Context()

	fdsBefore := countOpenFDs(t)
	if fdsBefore == -1 {
		t.Skip("cannot count file descriptors on this platform")
	}

	rfs := []fs.FS{rules.FS, thirdparty.FS}
	yrs, err := CachedRules(ctx, rfs)
	if err != nil {
		t.Fatalf("rules: %v", err)
	}

	cfg := malcontent.Config{
		Concurrency:      runtime.NumCPU(),
		IgnoreSelf:       false,
		IncludeDataFiles: false,
		MinFileRisk:      0,
		MinRisk:          0,
		Rules:            yrs,
		RuleFS:           rfs,
	}

	testFiles := []string{
		filepath.Join("testdata", "empty"),
		filepath.Join("testdata", "rando"),
		filepath.Join("testdata", "short"),
	}

	iterations := runtime.GOMAXPROCS(0) * 10
	for range iterations {
		for _, tf := range testFiles {
			_, _ = scanSinglePath(ctx, cfg, tf, rfs, tf, "", nil)
		}
	}

	runtime.GC()

	fdsAfter := countOpenFDs(t)

	maxAllowedGrowth := 0
	leaked := fdsAfter - fdsBefore
	if leaked > maxAllowedGrowth {
		t.Errorf("file descriptor leak detected: before=%d after=%d leaked=%d (ran %d iterations)",
			fdsBefore, fdsAfter, leaked, iterations*len(testFiles))
	}
}

// TestScanSinglePathNonExistentFile verifies that scanning a non-existent file
// returns an error without leaking resources.
func TestScanSinglePathNonExistentFile(t *testing.T) {
	ctx := t.Context()

	fdsBefore := countOpenFDs(t)
	if fdsBefore == -1 {
		t.Skip("cannot count file descriptors on this platform")
	}

	rfs := []fs.FS{rules.FS, thirdparty.FS}
	yrs, err := CachedRules(ctx, rfs)
	if err != nil {
		t.Fatalf("rules: %v", err)
	}

	cfg := malcontent.Config{
		Rules:  yrs,
		RuleFS: rfs,
	}

	iterations := runtime.GOMAXPROCS(0) * 10
	for range iterations {
		_, err := scanSinglePath(ctx, cfg, "/nonexistent/path/to/file", rfs, "", "", nil)
		if err == nil {
			t.Error("error for a nonexistent file: got = nil, want = non-nil")
		}
	}

	runtime.GC()

	fdsAfter := countOpenFDs(t)
	maxAllowedGrowth := 0
	leaked := fdsAfter - fdsBefore
	if leaked > maxAllowedGrowth {
		t.Errorf("file descriptor leak on error path: before=%d after=%d leaked=%d",
			fdsBefore, fdsAfter, leaked)
	}
}

// TestScanRepeatedScansNoResourceExhaustion verifies that repeated scans
// don't exhaust scanner pool or buffer pool resources.
func TestScanRepeatedScansNoResourceExhaustion(t *testing.T) {
	ctx := t.Context()

	rfs := []fs.FS{rules.FS, thirdparty.FS}
	yrs, err := CachedRules(ctx, rfs)
	if err != nil {
		t.Fatalf("rules: %v", err)
	}

	cfg := malcontent.Config{
		Concurrency:      runtime.NumCPU(),
		IgnoreSelf:       false,
		IncludeDataFiles: false,
		MinFileRisk:      0,
		MinRisk:          0,
		Rules:            yrs,
		RuleFS:           rfs,
	}

	testFiles := []string{
		filepath.Join("testdata", "empty"), // zero-sized, early return before scanner
		filepath.Join("testdata", "rando"), // data file, early return before scanner
		filepath.Join("testdata", "shell"), // actual script, full scan path
	}

	iterations := runtime.GOMAXPROCS(0) * 10

	for range iterations {
		for _, tf := range testFiles {
			_, _ = scanSinglePath(ctx, cfg, tf, rfs, tf, "", nil)
		}
	}
}

func TestNPMCredentialExfiltrationRule(t *testing.T) {
	ctx := t.Context()

	rfs := []fs.FS{rules.FS, thirdparty.FS}
	yrs, err := CachedRules(ctx, rfs)
	if err != nil {
		t.Fatalf("rules: %v", err)
	}

	cfg := malcontent.Config{
		Concurrency:      runtime.NumCPU(),
		IgnoreSelf:       false,
		IncludeDataFiles: false,
		MinFileRisk:      0,
		MinRisk:          0,
		Rules:            yrs,
		RuleFS:           rfs,
	}

	tests := []struct {
		name     string
		path     string
		wantRule bool
	}{
		{
			name:     "postinstall credential exfiltration",
			path:     filepath.Join("testdata", "npm-token-exfil", "package.json"),
			wantRule: true,
		},
		{
			name:     "release script token reference",
			path:     filepath.Join("testdata", "npm-token-release", "package.json"),
			wantRule: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fr, err := scanSinglePath(ctx, cfg, tt.path, rfs, tt.path, "", nil)
			if err != nil {
				t.Fatalf("scan: %v", err)
			}

			gotRule := hasRuleName(fr, "npm_install_credential_exfiltration")
			if gotRule != tt.wantRule {
				t.Fatalf("npm_install_credential_exfiltration match = %t, want %t", gotRule, tt.wantRule)
			}
		})
	}
}

func hasRuleName(fr *malcontent.FileReport, ruleName string) bool {
	if fr == nil {
		return false
	}
	for _, b := range fr.Behaviors {
		if b.RuleName == ruleName {
			return true
		}
	}
	return false
}

func TestExitIfHitOrMiss(t *testing.T) {
	t.Parallel()

	buildMap := func(entries map[string]*malcontent.FileReport) *xsync.Map[string, *malcontent.FileReport] {
		m := xsync.NewMap[string, *malcontent.FileReport]()
		for k, v := range entries {
			m.Store(k, v)
		}
		return m
	}

	frWithBehaviors := &malcontent.FileReport{
		Path:      "/bin/malware",
		Behaviors: []*malcontent.Behavior{{ID: "net/http"}, {ID: "fs/write"}},
	}
	frNoBehaviors := &malcontent.FileReport{Path: "/bin/clean"}
	frSkipped := &malcontent.FileReport{Path: "/bin/skipped", Skipped: "data file"}

	tests := []struct {
		name      string
		frs       *xsync.Map[string, *malcontent.FileReport]
		scanPath  string
		errIfHit  bool
		errIfMiss bool
		wantFR    bool
		wantErr   bool
	}{
		{"nil map", nil, "/scan", true, true, false, false},
		{"empty map", xsync.NewMap[string, *malcontent.FileReport](), "/scan", true, true, false, false},
		{"behaviors errIfHit", buildMap(map[string]*malcontent.FileReport{"/bin/malware": frWithBehaviors}), "/scan", true, false, true, true},
		{"behaviors no errIfHit", buildMap(map[string]*malcontent.FileReport{"/bin/malware": frWithBehaviors}), "/scan", false, false, false, false},
		{"no behaviors errIfMiss", buildMap(map[string]*malcontent.FileReport{"/bin/clean": frNoBehaviors}), "/scan", false, true, false, true},
		{"no behaviors no errIfMiss", buildMap(map[string]*malcontent.FileReport{"/bin/clean": frNoBehaviors}), "/scan", false, false, false, false},
		{"only skipped zero scanned", buildMap(map[string]*malcontent.FileReport{"/bin/skipped": frSkipped}), "/scan", true, true, false, false},
		{"skipped+real errIfHit", buildMap(map[string]*malcontent.FileReport{"/s": frSkipped, "/m": frWithBehaviors}), "/scan", true, false, true, true},
		{"nil value skipped", buildMap(map[string]*malcontent.FileReport{"/nil": nil, "/m": frWithBehaviors}), "/scan", true, false, true, true},
		{"both false always nil", buildMap(map[string]*malcontent.FileReport{"/m": frWithBehaviors}), "/scan", false, false, false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fr, err := exitIfHitOrMiss(tt.frs, tt.scanPath, tt.errIfHit, tt.errIfMiss, 0)

			if tt.wantErr {
				if err == nil {
					t.Fatal("error: got = nil, want = non-nil")
				}
				if !errors.Is(err, ErrMatchedCondition) {
					t.Errorf("error: got = %v, want = %v", err, ErrMatchedCondition)
				}
				if !strings.Contains(err.Error(), tt.scanPath) {
					t.Errorf("error: got = %v, want it to contain scan path %q", err, tt.scanPath)
				}
			} else if err != nil {
				t.Errorf("error: got = %v, want = nil", err)
			}

			if tt.wantFR {
				if fr == nil {
					t.Fatal("FileReport: got = nil, want = non-nil")
				}
			} else if fr != nil {
				t.Errorf("FileReport: got = %+v, want = nil", fr)
			}
		})
	}
}

func TestExitIfHitOrMiss_NilNilContract(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		frs       *xsync.Map[string, *malcontent.FileReport]
		scanPath  string
		errIfHit  bool
		errIfMiss bool
	}{
		{
			name:      "empty map returns nil report and nil error",
			frs:       xsync.NewMap[string, *malcontent.FileReport](),
			scanPath:  "/tmp/test",
			errIfHit:  false,
			errIfMiss: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fr, err := exitIfHitOrMiss(tt.frs, tt.scanPath, tt.errIfHit, tt.errIfMiss, 0)
			if fr != nil {
				t.Errorf("FileReport: got = %+v, want = nil", fr)
			}
			if err != nil {
				t.Errorf("error: got = %v, want = nil", err)
			}
		})
	}
}

func TestGetMaxConcurrency(t *testing.T) {
	t.Parallel()
	procs := runtime.GOMAXPROCS(0)
	tests := []struct {
		input int
		want  int
	}{
		{0, 1},
		{-1, 1},
		{-100, 1},
		{1, 1},
		{min(4, procs), min(4, procs)},
		{128, procs},
	}
	for _, tt := range tests {
		got := getMaxConcurrency(tt.input)
		if got != tt.want {
			t.Errorf("getMaxConcurrency(%d) = %d, want %d", tt.input, got, tt.want)
		}
		if got < 1 {
			t.Errorf("getMaxConcurrency(%d) = %d, must be >= 1", tt.input, got)
		}
		if got > procs {
			t.Errorf("getMaxConcurrency(%d) = %d, exceeds GOMAXPROCS %d", tt.input, got, procs)
		}
	}
}

func TestFileReportError(t *testing.T) {
	t.Parallel()

	t.Run("NewFileReportError fields", func(t *testing.T) {
		t.Parallel()
		inner := errors.New("inner")
		fre := NewFileReportError(inner, "/bin/test", TypeScanError)
		if fre.Path() != "/bin/test" {
			t.Errorf("Path() = %q", fre.Path())
		}
		if fre.Type() != TypeScanError {
			t.Errorf("Type() = %d", fre.Type())
		}
		if !errors.Is(fre.Unwrap(), inner) {
			t.Errorf("Unwrap() = %v", fre.Unwrap())
		}
	})

	t.Run("Error includes path", func(t *testing.T) {
		t.Parallel()
		fre := NewFileReportError(errors.New("fail"), "/bin/x", TypeGenerateError)
		if !strings.Contains(fre.Error(), "/bin/x") {
			t.Errorf("Error() = %q, should contain path", fre.Error())
		}
	})

	t.Run("Is matches same path and type", func(t *testing.T) {
		t.Parallel()
		a := NewFileReportError(errors.New("a"), "/p", TypeScanError)
		b := NewFileReportError(errors.New("b"), "/p", TypeScanError)
		if !a.Is(b) {
			t.Error("Is() should match same path+type")
		}
	})

	t.Run("Is rejects different type", func(t *testing.T) {
		t.Parallel()
		a := NewFileReportError(errors.New("a"), "/p", TypeScanError)
		b := NewFileReportError(errors.New("b"), "/p", TypeGenerateError)
		if a.Is(b) {
			t.Error("Is() should reject different type")
		}
	})

	t.Run("all error types", func(t *testing.T) {
		t.Parallel()
		for _, et := range []ErrorType{TypeUnknown, TypeScanError, TypeGenerateError} {
			fre := NewFileReportError(errors.New("test"), "/p", et)
			if fre.Error() == "" {
				t.Errorf("Error() empty for type %d", et)
			}
		}
	})
}

func TestHandleFileReportError(t *testing.T) {
	t.Parallel()
	logger := clog.FromContext(t.Context())

	tests := []struct {
		name        string
		err         error
		wantErr     error  // an error that ends the scan, returned as is
		wantSkipped string // the skipped report's reason, which it begins with
	}{
		{name: "a plain error skips the file", err: errors.New("plain"), wantSkipped: errMsgScanFailed + ": plain"},
		{name: "a scan error skips the file", err: NewFileReportError(errors.New("scan"), "/bin/x", TypeScanError), wantSkipped: errMsgScanFailed + ": "},
		{name: "an unknown error skips the file", err: NewFileReportError(errors.New("unknown"), "/bin/x", TypeUnknown), wantSkipped: errMsgScanFailed + ": "},
		{name: "a report that cannot be generated is skipped as such", err: NewFileReportError(errors.New("gen"), "/bin/x", TypeGenerateError), wantSkipped: errMsgGenerateFailed},
		{name: "cancellation ends the scan", err: fmt.Errorf("wait: %w", context.Canceled), wantErr: context.Canceled},
		{name: "a deadline ends the scan", err: context.DeadlineExceeded, wantErr: context.DeadlineExceeded},
		{name: "rules that do not compile end the scan", err: fmt.Errorf("%w: %w", errRules, errors.New("syntax")), wantErr: errRules},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fr, err := handleFileReportError(tt.err, "/bin/x", logger)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) || fr != nil {
					t.Errorf("handleFileReportError: got = (%+v, %v), want = (nil, %v)", fr, err, tt.wantErr)
				}
				return
			}
			if err != nil || fr == nil {
				t.Fatalf("handleFileReportError: got = (%+v, %v), want a skipped report", fr, err)
			}
			if fr.Path != "/bin/x" || !strings.HasPrefix(fr.Skipped, tt.wantSkipped) {
				t.Errorf("report: got = %+v, want path /bin/x skipped as %q", fr, tt.wantSkipped)
			}
		})
	}
}

// TestScanRunsScanPathsConcurrently checks that many scan paths share one
// queue, so that single-file scan paths, as --processes produces, are scanned
// by every worker rather than one at a time.
func TestScanRunsScanPathsConcurrently(t *testing.T) {
	// Not parallel: replaces scanBytes.
	if runtime.GOMAXPROCS(0) < 4 {
		t.Skip("needs four workers")
	}
	yrs, rfs := scanTestRules(t)
	dir := t.TempDir()
	paths := make([]string, 8)
	for i := range paths {
		paths[i] = scanTestWriteFile(t, filepath.Join(dir, fmt.Sprintf("f%d.sh", i)), fmt.Appendf(nil, "%s# %d\n", scanTestLocaleScript, i))
	}
	orig := scanBytes
	t.Cleanup(func() { scanBytes = orig })

	tests := []struct {
		name      string
		scanPaths []string
	}{
		{name: "one directory of eight files", scanPaths: []string{dir}},
		{name: "eight file scan paths", scanPaths: paths},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Each scan waits until a second one is under way, so two workers
			// overlap. A lone worker waits out the bound once, then the rest
			// run, and the peak stays at one.
			var active, peak atomic.Int64
			overlap := make(chan struct{})
			var opened sync.Once
			scanBytes = func(yrs *yarax.Rules, fc []byte, sum [sha256.Size]byte) (*yarax.ScanResults, error) {
				n := active.Add(1)
				defer active.Add(-1)
				for {
					if p := peak.Load(); n <= p || peak.CompareAndSwap(p, n) {
						break
					}
				}
				if n >= 2 {
					opened.Do(func() { close(overlap) })
				}
				select {
				case <-overlap:
				case <-time.After(10 * time.Second):
					opened.Do(func() { close(overlap) })
				}
				return orig(yrs, fc, sum)
			}
			c := malcontent.Config{Concurrency: 4, Rules: yrs, RuleFS: rfs, ScanPaths: tt.scanPaths}
			r, err := Scan(t.Context(), c)
			if err != nil {
				t.Fatalf("Scan: %v", err)
			}
			if got := r.Files.Size(); got != len(paths) {
				t.Errorf("reports: got = %d, want = %d", got, len(paths))
			}
			if got := peak.Load(); got < 2 {
				t.Errorf("concurrent scans: got = %d, want more than one of four workers busy", got)
			}
		})
	}
}
