// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package action

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/chainguard-dev/malcontent/rules"
	thirdparty "github.com/chainguard-dev/malcontent/third_party"
)

// countOpenFDs returns the number of open file descriptors for the current process.
// Returns -1 if unable to count (e.g., on unsupported platforms).
func countOpenFDs(t *testing.T) int {
	t.Helper()

	// Linux: count entries in /proc/self/fd
	if entries, err := os.ReadDir("/proc/self/fd"); err == nil {
		return len(entries)
	}

	// macOS: count entries in /dev/fd
	if entries, err := os.ReadDir("/dev/fd"); err == nil {
		return len(entries)
	}

	return -1
}

// TestScanSinglePathNoFDLeak verifies that early return paths in scanSinglePath
// properly close file handles and don't leak file descriptors.
func TestScanSinglePathNoFDLeak(t *testing.T) {
	ctx := context.Background()

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
	ctx := context.Background()

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
			t.Error("expected error for non-existent file")
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
	ctx := context.Background()

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

func TestExitIfHitOrMiss(t *testing.T) {
	t.Parallel()

	buildMap := func(entries ...any) *sync.Map {
		m := &sync.Map{}
		for i := 0; i < len(entries); i += 2 {
			m.Store(entries[i], entries[i+1])
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
		frs       *sync.Map
		scanPath  string
		errIfHit  bool
		errIfMiss bool
		wantFR    bool
		wantErr   bool
	}{
		{"nil map", nil, "/scan", true, true, false, false},
		{"empty map", &sync.Map{}, "/scan", true, true, false, false},
		{"behaviors errIfHit", buildMap("/bin/malware", frWithBehaviors), "/scan", true, false, true, true},
		{"behaviors no errIfHit", buildMap("/bin/malware", frWithBehaviors), "/scan", false, false, false, false},
		{"no behaviors errIfMiss", buildMap("/bin/clean", frNoBehaviors), "/scan", false, true, false, true},
		{"no behaviors no errIfMiss", buildMap("/bin/clean", frNoBehaviors), "/scan", false, false, false, false},
		{"only skipped zero scanned", buildMap("/bin/skipped", frSkipped), "/scan", true, true, false, false},
		{"skipped+real errIfHit", buildMap("/s", frSkipped, "/m", frWithBehaviors), "/scan", true, false, true, true},
		{"nil value skipped", buildMap("/nil", nil, "/m", frWithBehaviors), "/scan", true, false, true, true},
		{"both false always nil", buildMap("/m", frWithBehaviors), "/scan", false, false, false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fr, err := exitIfHitOrMiss(tt.frs, tt.scanPath, tt.errIfHit, tt.errIfMiss)

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				if !errors.Is(err, ErrMatchedCondition) {
					t.Errorf("expected ErrMatchedCondition, got: %v", err)
				}
				if !strings.Contains(err.Error(), tt.scanPath) {
					t.Errorf("error should contain scan path %q: %v", tt.scanPath, err)
				}
			} else if err != nil {
				t.Errorf("expected nil error, got: %v", err)
			}

			if tt.wantFR {
				if fr == nil {
					t.Fatal("expected non-nil FileReport")
				}
			} else if fr != nil {
				t.Errorf("expected nil FileReport, got: %+v", fr)
			}
		})
	}
}

func TestGetMaxConcurrency(t *testing.T) {
	t.Parallel()
	tests := []struct {
		input int
		want  int
	}{
		{0, 1}, {-1, 1}, {-100, 1}, {1, 1}, {4, 4}, {128, 128},
	}
	for _, tt := range tests {
		got := getMaxConcurrency(tt.input)
		if got != tt.want {
			t.Errorf("getMaxConcurrency(%d) = %d, want %d", tt.input, got, tt.want)
		}
		if got < 1 {
			t.Errorf("getMaxConcurrency(%d) = %d, must be >= 1", tt.input, got)
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
	logger := clog.FromContext(context.Background())

	t.Run("non-FileReportError returns error", func(t *testing.T) {
		t.Parallel()
		_, err := handleFileReportError(errors.New("plain"), "/bin/x", logger)
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "/bin/x") {
			t.Errorf("error should contain path: %v", err)
		}
	})

	t.Run("TypeGenerateError returns FileReport with Skipped", func(t *testing.T) {
		t.Parallel()
		fre := NewFileReportError(errors.New("gen"), "/bin/x", TypeGenerateError)
		fr, err := handleFileReportError(fre, "/bin/x", logger)
		if err != nil {
			t.Errorf("expected nil error, got: %v", err)
		}
		if fr == nil {
			t.Fatal("expected FileReport")
		}
		if fr.Skipped != errMsgGenerateFailed {
			t.Errorf("Skipped = %q, want %q", fr.Skipped, errMsgGenerateFailed)
		}
	})

	t.Run("TypeScanError returns error", func(t *testing.T) {
		t.Parallel()
		fre := NewFileReportError(errors.New("scan"), "/bin/x", TypeScanError)
		fr, err := handleFileReportError(fre, "/bin/x", logger)
		if err == nil {
			t.Fatal("expected error")
		}
		if fr != nil {
			t.Errorf("expected nil FileReport, got: %+v", fr)
		}
	})

	t.Run("TypeUnknown returns error", func(t *testing.T) {
		t.Parallel()
		fre := NewFileReportError(errors.New("unknown"), "/bin/x", TypeUnknown)
		_, err := handleFileReportError(fre, "/bin/x", logger)
		if err == nil {
			t.Fatal("expected error")
		}
	})
}
