// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package action

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/chainguard-dev/malcontent/pkg/report"
)

func TestScanSinglePathMaxScanFiles(t *testing.T) {
	t.Parallel()
	yrs, rfs := scanTestRules(t)

	const maxFilesSkipped = "max file count exceeded"
	tests := []struct {
		name        string
		maxFiles    int
		counted     int64
		inArchive   bool
		wantSkipped bool
	}{
		{name: "zero limit scans every file", maxFiles: 0, counted: 1000},
		{name: "file reaching the limit is scanned", maxFiles: 3, counted: 2},
		{name: "file past the limit is skipped", maxFiles: 3, counted: 3, wantSkipped: true},
		{name: "archive entry past the limit is skipped and removed", maxFiles: 1, counted: 1, inArchive: true, wantSkipped: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			path := scanTestWriteFile(t, filepath.Join(root, "locale.sh"), []byte(scanTestLocaleScript))
			archiveRoot := ""
			if tt.inArchive {
				archiveRoot = root
			}
			var count atomic.Int64
			count.Store(tt.counted)
			c := malcontent.Config{MaxScanFiles: tt.maxFiles, Rules: yrs, RuleFS: rfs}

			fr, err := scanSinglePath(t.Context(), c, path, rfs, path, archiveRoot, &count)
			if err != nil {
				t.Fatalf("scanSinglePath: %v", err)
			}
			if got := fr.Skipped == maxFilesSkipped; got != tt.wantSkipped {
				t.Errorf("skipped for file count: got = %t (Skipped = %q), want = %t", got, fr.Skipped, tt.wantSkipped)
			}
			if got, want := count.Load(), tt.counted+1; got != want {
				t.Errorf("file count: got = %d, want = %d", got, want)
			}
			_, statErr := os.Stat(path)
			wantRemoved := tt.inArchive && tt.wantSkipped
			if got := errors.Is(statErr, fs.ErrNotExist); got != wantRemoved {
				t.Errorf("entry removed: got = %t, want = %t", got, wantRemoved)
			}
		})
	}
}

func TestScanSinglePathScanRiskThreshold(t *testing.T) {
	t.Parallel()
	yrs, rfs := scanTestRules(t)
	content := readTestFile(t, scanTestNPMFixture)

	const earlySkip = "overall risk too low for scan"
	tests := []struct {
		name          string
		scan          bool
		minRiskOffset int
		quantity      bool
		inArchive     bool
		wantEarlySkip bool
	}{
		{name: "scan reports a file whose risk equals the threshold", scan: true},
		{name: "scan skips a file whose risk is below the threshold", scan: true, minRiskOffset: 1, wantEarlySkip: true},
		{name: "scan with quantity-increases-risk defers to report generation", scan: true, minRiskOffset: 1, quantity: true},
		{name: "analyze ignores the scan threshold", minRiskOffset: 1},
		{name: "scan removes an archive entry below the threshold", scan: true, minRiskOffset: 1, inArchive: true, wantEarlySkip: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			path := scanTestWriteFile(t, filepath.Join(root, "app", "package.json"), content)
			archiveRoot, absPath := "", path
			if tt.inArchive {
				archiveRoot, absPath = root, filepath.Join(t.TempDir(), "bundle.tgz")
			}
			c := malcontent.Config{QuantityIncreasesRisk: tt.quantity, Rules: yrs, RuleFS: rfs, Scan: tt.scan}
			risk := scanTestHighestRisk(t, yrs, path, archiveRoot, c)
			if risk < report.HIGH {
				t.Fatalf("fixture precondition: highest match risk: got = %d, want >= %d", risk, report.HIGH)
			}
			// The scan threshold never drops below HIGH, so MinFileRisk moves
			// it onto the file's own risk.
			c.MinFileRisk = risk + tt.minRiskOffset

			logger, logs := scanTestLogger()
			fr, err := scanSinglePath(clog.WithLogger(t.Context(), logger), c, path, rfs, absPath, archiveRoot, nil)
			if err != nil {
				t.Fatalf("scanSinglePath: %v", err)
			}
			// Only the early return yields this skip reason without a checksum.
			gotEarlySkip := fr.Skipped == earlySkip && fr.SHA256 == ""
			if gotEarlySkip != tt.wantEarlySkip {
				t.Errorf("skipped before report generation: got = %t (Skipped = %q), want = %t", gotEarlySkip, fr.Skipped, tt.wantEarlySkip)
			}
			_, statErr := os.Stat(path)
			wantRemoved := tt.inArchive && tt.wantEarlySkip
			if got := errors.Is(statErr, fs.ErrNotExist); got != wantRemoved {
				t.Errorf("entry removed: got = %t, want = %t", got, wantRemoved)
			}
			if got := logs.String(); strings.Contains(got, "remove skipped archive entry") {
				t.Errorf("logs: got = %q, want no removal failure", got)
			}
		})
	}
}

func TestScanSinglePathTypeDetectionFailureLog(t *testing.T) {
	t.Parallel()
	yrs, rfs := scanTestRules(t)

	tests := []struct {
		name        string
		unreadable  bool
		interactive bool
		wantLogged  bool
	}{
		{name: "readable file logs no failure"},
		{name: "unreadable file logs the failure", unreadable: true, wantLogged: true},
		{name: "interactive renderer suppresses the failure log", unreadable: true, interactive: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			path := scanTestWriteFile(t, filepath.Join(t.TempDir(), "locale.sh"), []byte(scanTestLocaleScript))
			if tt.unreadable {
				if os.Geteuid() == 0 {
					t.Skip("file permissions do not restrict root")
				}
				if err := os.Chmod(path, 0); err != nil {
					t.Fatalf("chmod %s: %v", path, err)
				}
			}
			c := malcontent.Config{Rules: yrs, RuleFS: rfs}
			if tt.interactive {
				c.Renderer = &scanTestRenderer{name: "Interactive"}
			}

			logger, logs := scanTestLogger()
			fr, err := scanSinglePath(clog.WithLogger(t.Context(), logger), c, path, rfs, path, "", nil)
			if err != nil {
				t.Fatalf("scanSinglePath: %v", err)
			}
			if want := "data file or empty"; tt.unreadable && fr.Skipped != want {
				t.Errorf("Skipped: got = %q, want = %q", fr.Skipped, want)
			}
			if got := strings.Contains(logs.String(), "file type failure"); got != tt.wantLogged {
				t.Errorf("type detection failure logged: got = %t, want = %t (logs: %q)", got, tt.wantLogged, logs.String())
			}
		})
	}
}

func TestScanSinglePathReportPath(t *testing.T) {
	t.Parallel()
	yrs, rfs := scanTestRules(t)
	npm := readTestFile(t, scanTestNPMFixture)
	locale := []byte(scanTestLocaleScript)

	// In absPath, trimPrefixes, and want, "<root>" expands to the scan root
	// and "<path>" to the scanned file.
	const archivePath = "/scans/bundle.tgz"
	tests := []struct {
		name          string
		file          string
		content       []byte
		inArchive     bool
		absPath       string
		trimPrefixes  []string
		wantBehaviors bool
		want          string
	}{
		{
			name: "archive entry with behaviors joins archive and entry paths",
			file: "package.json", content: npm, inArchive: true, absPath: archivePath,
			wantBehaviors: true, want: "/scans/bundle.tgz ∴ /app/package.json",
		},
		{
			name: "archive entry with behaviors trims the archive path",
			file: "package.json", content: npm, inArchive: true, absPath: archivePath, trimPrefixes: []string{"/scans"},
			wantBehaviors: true, want: "bundle.tgz ∴ /app/package.json",
		},
		{
			name: "archive entry without behaviors joins archive and entry paths",
			file: "locale.sh", content: locale, inArchive: true, absPath: archivePath,
			want: "/scans/bundle.tgz ∴ /app/locale.sh",
		},
		{
			name: "archive entry without behaviors trims the archive path",
			file: "locale.sh", content: locale, inArchive: true, absPath: archivePath, trimPrefixes: []string{"/scans"},
			want: "bundle.tgz ∴ /app/locale.sh",
		},
		{
			name: "archive entry without behaviors trims the archive path once",
			file: "locale.sh", content: locale, inArchive: true, absPath: "a/a/bundle.tgz", trimPrefixes: []string{"a"},
			want: "a/bundle.tgz ∴ /app/locale.sh",
		},
		{
			name: "archive entry with behaviors trims the archive path once",
			file: "package.json", content: npm, inArchive: true, absPath: "a/a/bundle.tgz", trimPrefixes: []string{"a"},
			wantBehaviors: true, want: "a/bundle.tgz ∴ /app/package.json",
		},
		{
			name: "archive path loses the macOS /private prefix",
			file: "package.json", content: npm, inArchive: true, absPath: "/private/scans/bundle.tgz",
			wantBehaviors: true, want: "/scans/bundle.tgz ∴ /app/package.json",
		},
		{
			name: "archive entry without an archive path keeps the entry path",
			file: "package.json", content: npm, inArchive: true, absPath: "",
			wantBehaviors: true, want: "<path>",
		},
		{
			name: "archive entry whose archive path is the entry keeps the entry path",
			file: "package.json", content: npm, inArchive: true, absPath: "<path>",
			wantBehaviors: true, want: "<path>",
		},
		{
			name: "directory file with behaviors keeps its own path",
			file: "package.json", content: npm, absPath: "<root>",
			wantBehaviors: true, want: "<path>",
		},
		{
			name: "directory file without behaviors keeps its own path",
			file: "locale.sh", content: locale, absPath: "<root>",
			want: "<path>",
		},
		{
			name: "directory file with behaviors trims its own path",
			file: "package.json", content: npm, absPath: "<root>", trimPrefixes: []string{"<root>"},
			wantBehaviors: true, want: "app/package.json",
		},
		{
			name: "directory file without behaviors trims its own path",
			file: "locale.sh", content: locale, absPath: "<root>", trimPrefixes: []string{"<root>"},
			want: "app/locale.sh",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			path := scanTestWriteFile(t, filepath.Join(root, "app", tt.file), tt.content)
			expand := strings.NewReplacer("<root>", root, "<path>", path).Replace
			var trim []string
			for _, p := range tt.trimPrefixes {
				trim = append(trim, expand(p))
			}
			archiveRoot := ""
			if tt.inArchive {
				archiveRoot = root
			}
			c := malcontent.Config{Rules: yrs, RuleFS: rfs, TrimPrefixes: trim}

			fr, err := scanSinglePath(t.Context(), c, path, rfs, expand(tt.absPath), archiveRoot, nil)
			if err != nil {
				t.Fatalf("scanSinglePath: %v", err)
			}
			if got := len(fr.Behaviors) > 0; got != tt.wantBehaviors {
				t.Fatalf("fixture precondition: has behaviors: got = %t, want = %t", got, tt.wantBehaviors)
			}
			if want := expand(tt.want); fr.Path != want {
				t.Errorf("Path: got = %q, want = %q", fr.Path, want)
			}
		})
	}
}

func TestScanSinglePathZeroSizedFile(t *testing.T) {
	t.Parallel()
	yrs, rfs := scanTestRules(t)
	const zeroSized = "zero-sized file"

	tests := []struct {
		name        string
		content     []byte
		includeData bool
		inArchive   bool
		wantZero    bool
	}{
		{name: "empty file is skipped as zero-sized", wantZero: true},
		{name: "empty archive entry is skipped as zero-sized and removed", inArchive: true, wantZero: true},
		{name: "one-byte file is not treated as zero-sized", content: []byte("#"), includeData: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			path := scanTestWriteFile(t, filepath.Join(root, "file"), tt.content)
			archiveRoot := ""
			if tt.inArchive {
				archiveRoot = root
			}
			c := malcontent.Config{IncludeDataFiles: tt.includeData, Rules: yrs, RuleFS: rfs}

			fr, err := scanSinglePath(t.Context(), c, path, rfs, path, archiveRoot, nil)
			if err != nil {
				t.Fatalf("scanSinglePath: %v", err)
			}
			if got := fr.Skipped == zeroSized; got != tt.wantZero {
				t.Errorf("skipped as zero-sized: got = %t (Skipped = %q), want = %t", got, fr.Skipped, tt.wantZero)
			}
			_, statErr := os.Stat(path)
			if got := errors.Is(statErr, fs.ErrNotExist); got != tt.inArchive {
				t.Errorf("file removed: got = %t, want = %t", got, tt.inArchive)
			}
		})
	}
}

func TestScanSinglePathRecordsArchiveEntryLocation(t *testing.T) {
	t.Parallel()
	yrs, rfs := scanTestRules(t)
	root := t.TempDir()
	path := scanTestWriteFile(t, filepath.Join(root, "app", "package.json"), readTestFile(t, scanTestNPMFixture))

	fr, err := scanSinglePath(t.Context(), malcontent.Config{Rules: yrs, RuleFS: rfs}, path, rfs, "/scans/bundle.tgz", root, nil)
	if err != nil {
		t.Fatalf("scanSinglePath: %v", err)
	}
	if len(fr.Behaviors) == 0 {
		t.Fatal("fixture precondition: behaviors: got = 0, want > 0")
	}
	if fr.ArchiveRoot != root {
		t.Errorf("ArchiveRoot: got = %q, want = %q", fr.ArchiveRoot, root)
	}
	if fr.FullPath != path {
		t.Errorf("FullPath: got = %q, want = %q", fr.FullPath, path)
	}
}

// scanTestCancelAfterContext reports no error for its first n Err calls and
// context.Canceled after that, standing in for a cancellation that lands
// between two of the scan's checks.
type scanTestCancelAfterContext struct {
	context.Context
	n     int64
	calls atomic.Int64
}

func (c *scanTestCancelAfterContext) Err() error {
	if c.calls.Add(1) > c.n {
		return context.Canceled
	}
	return nil
}

func TestScanSinglePathReportGenerationFailure(t *testing.T) {
	t.Parallel()
	yrs, rfs := scanTestRules(t)
	path := scanTestWriteFile(t, filepath.Join(t.TempDir(), "app", "package.json"), readTestFile(t, scanTestNPMFixture))
	// The scan's first check passes; report generation then sees the cancellation.
	ctx := &scanTestCancelAfterContext{Context: t.Context(), n: 1}

	fr, err := scanSinglePath(ctx, malcontent.Config{Rules: yrs, RuleFS: rfs}, path, rfs, path, "", nil)
	if fr != nil {
		t.Errorf("FileReport: got = %+v, want = nil", fr)
	}
	var fre *FileReportError
	if !errors.As(err, &fre) || fre.Type() != TypeGenerateError {
		t.Fatalf("error: got = %v, want a FileReportError of type %v", err, TypeGenerateError)
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("error: got = %v, want = %v", err, context.Canceled)
	}
}
