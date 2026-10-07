// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package action

import (
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"testing/fstest"

	"github.com/chainguard-dev/malcontent/pkg/compile"
	"github.com/chainguard-dev/malcontent/pkg/file"
	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/chainguard-dev/malcontent/pkg/programkind"
	"github.com/minio/sha256-simd"

	yarax "github.com/VirusTotal/yara-x/go"
)

// countScans replaces scanBytes for the duration of the test with one that
// counts calls and runs before, when set, ahead of each scan.
func countScans(t *testing.T, before func(call int64) error) *atomic.Int64 {
	t.Helper()
	orig := scanBytes
	var calls atomic.Int64
	scanBytes = func(yrs *yarax.Rules, fc []byte, sum [sha256.Size]byte) (*yarax.ScanResults, error) {
		n := calls.Add(1)
		if before != nil {
			if err := before(n); err != nil {
				return nil, err
			}
		}
		return orig(yrs, fc, sum)
	}
	t.Cleanup(func() { scanBytes = orig })
	return &calls
}

func TestScanContentReusesResultsForIdenticalContent(t *testing.T) {
	// Not parallel: replaces scanBytes.
	yrs, _ := scanTestRules(t)
	calls := countScans(t, nil)
	ctx := withResultCache(t.Context())
	fc := []byte(scanTestLocaleScript)
	sum := sha256.Sum256(fc)

	first, err := scanContent(ctx, yrs, fc, sum)
	if err != nil {
		t.Fatalf("first scan: %v", err)
	}
	second, err := scanContent(ctx, yrs, append([]byte(nil), fc...), sum)
	if err != nil {
		t.Fatalf("second scan: %v", err)
	}
	if first != second {
		t.Errorf("results: got distinct results, want the first scan's results reused")
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("scans: got = %d, want = 1", got)
	}

	other := []byte("export PATH=/usr/bin\n")
	if _, err := scanContent(ctx, yrs, other, sha256.Sum256(other)); err != nil {
		t.Fatalf("other content: %v", err)
	}
	if got := calls.Load(); got != 2 {
		t.Errorf("scans after different content: got = %d, want = 2", got)
	}
}

func TestScanContentWithoutCacheScansEachTime(t *testing.T) {
	// Not parallel: replaces scanBytes.
	yrs, _ := scanTestRules(t)
	calls := countScans(t, nil)
	fc := []byte(scanTestLocaleScript)
	for range 2 {
		if _, err := scanContent(t.Context(), yrs, fc, sha256.Sum256(fc)); err != nil {
			t.Fatalf("scan: %v", err)
		}
	}
	if got := calls.Load(); got != 2 {
		t.Errorf("scans: got = %d, want = 2", got)
	}
}

func TestScanContentWaitsForScanInProgress(t *testing.T) {
	// Not parallel: replaces scanBytes.
	yrs, _ := scanTestRules(t)
	release := make(chan struct{})
	started := make(chan struct{})
	calls := countScans(t, func(call int64) error {
		if call == 1 {
			close(started)
			<-release
		}
		return nil
	})
	ctx := withResultCache(t.Context())
	fc := []byte(scanTestLocaleScript)
	sum := sha256.Sum256(fc)

	var wg sync.WaitGroup
	results := make([]*yarax.ScanResults, 2)
	wg.Go(func() {
		results[0], _ = scanContent(ctx, yrs, fc, sum)
	})
	<-started
	waiting := make(chan struct{})
	wg.Go(func() {
		close(waiting)
		results[1], _ = scanContent(ctx, yrs, fc, sum)
	})
	<-waiting
	close(release)
	wg.Wait()

	if results[0] == nil || results[0] != results[1] {
		t.Errorf("results: got = %p and %p, want one shared result", results[0], results[1])
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("scans: got = %d, want = 1", got)
	}
}

func TestScanContentRescansAfterFailedScanInProgress(t *testing.T) {
	// Not parallel: replaces scanBytes.
	yrs, _ := scanTestRules(t)
	errScan := errors.New("scan failed")
	release := make(chan struct{})
	started := make(chan struct{})
	calls := countScans(t, func(call int64) error {
		if call == 1 {
			close(started)
			<-release
			return errScan
		}
		return nil
	})
	ctx := withResultCache(t.Context())
	fc := []byte(scanTestLocaleScript)
	sum := sha256.Sum256(fc)

	var wg sync.WaitGroup
	var firstErr, secondErr error
	var second *yarax.ScanResults
	wg.Go(func() {
		_, firstErr = scanContent(ctx, yrs, fc, sum)
	})
	<-started
	wg.Go(func() {
		second, secondErr = scanContent(ctx, yrs, fc, sum)
	})
	close(release)
	wg.Wait()

	if !errors.Is(firstErr, errScan) {
		t.Errorf("first error: got = %v, want = %v", firstErr, errScan)
	}
	if secondErr != nil || second == nil {
		t.Errorf("second scan: got = %v, %v, want results without error", second, secondErr)
	}
	if got := calls.Load(); got != 2 {
		t.Errorf("scans: got = %d, want = 2", got)
	}
	// A failed scan is not cached.
	if _, ok := resultCacheFrom(ctx).m.Load(resultKey{rules: yrs, sum: sum, size: int64(len(fc))}); !ok {
		t.Errorf("cache: got no entry, want the successful rescan cached")
	}
}

func TestScanContentAfterScanInProgressFinishes(t *testing.T) {
	// Not parallel: replaces scanBytes.
	yrs, _ := scanTestRules(t)
	fc := []byte(scanTestLocaleScript)
	sum := sha256.Sum256(fc)
	key := resultKey{rules: yrs, sum: sum, size: int64(len(fc))}
	prior, err := scanBytes(yrs, fc, sum)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	errScan := errors.New("scan failed")
	errRescan := errors.New("rescan failed")

	tests := []struct {
		name      string
		prevErr   error
		rescanErr error
		wantPrior bool
		wantScans int64
		wantErr   error
		wantCache bool
	}{
		{
			name:      "results of the finished scan are shared without scanning",
			wantPrior: true,
		},
		{
			name:      "after the scan failed the content is scanned again and cached",
			prevErr:   errScan,
			wantScans: 1,
			wantCache: true,
		},
		{
			name:      "a failed rescan is reported and not cached",
			prevErr:   errScan,
			rescanErr: errRescan,
			wantScans: 1,
			wantErr:   errRescan,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calls := countScans(t, func(int64) error { return tt.rescanErr })
			ctx := withResultCache(t.Context())
			rc := resultCacheFrom(ctx)
			// Another worker registered a scan of the same content and has
			// finished it.
			prev := &pendingScan{done: make(chan struct{}), err: tt.prevErr}
			if tt.prevErr == nil {
				prev.mrs = prior
			}
			close(prev.done)
			rc.inflight.Store(key, prev)

			got, err := scanContent(ctx, yrs, fc, sum)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("error: got = %v, want = %v", err, tt.wantErr)
			}
			if tt.wantErr == nil && got == nil {
				t.Errorf("results: got = nil, want results")
			}
			if gotPrior := got == prior; gotPrior != tt.wantPrior {
				t.Errorf("shared the finished scan's results: got = %t, want = %t", gotPrior, tt.wantPrior)
			}
			if n := calls.Load(); n != tt.wantScans {
				t.Errorf("scans: got = %d, want = %d", n, tt.wantScans)
			}
			if _, ok := rc.m.Load(key); ok != tt.wantCache {
				t.Errorf("cached: got = %t, want = %t", ok, tt.wantCache)
			}
		})
	}
}

func TestScanContentRetainsNothingAfterUncachedScan(t *testing.T) {
	// Not parallel: replaces scanBytes.
	yrs, _ := scanTestRules(t)
	errScan := errors.New("scan failed")
	fc := []byte(scanTestLocaleScript)
	sum := sha256.Sum256(fc)

	tests := []struct {
		name         string
		budget       int64
		failFirst    bool
		wantFirstErr error
	}{
		{name: "a result the budget does not admit is scanned again"},
		{name: "a failed scan is scanned again", budget: resultCacheBudget, failFirst: true, wantFirstErr: errScan},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calls := countScans(t, func(call int64) error {
				if tt.failFirst && call == 1 {
					return errScan
				}
				return nil
			})
			ctx := withResultCache(t.Context())
			rc := resultCacheFrom(ctx)
			rc.budget.Store(tt.budget)

			first, err := scanContent(ctx, yrs, fc, sum)
			if !errors.Is(err, tt.wantFirstErr) {
				t.Errorf("first error: got = %v, want = %v", err, tt.wantFirstErr)
			}
			if n := rc.inflight.Size(); n != 0 {
				t.Errorf("scans in progress after the first scan: got = %d, want = 0", n)
			}
			second, err := scanContent(ctx, yrs, fc, sum)
			if err != nil || second == nil {
				t.Fatalf("second scan: got = %v, %v, want results without error", second, err)
			}
			if second == first {
				t.Errorf("results: got the first scan's results again, want a new scan")
			}
			if n := calls.Load(); n != 2 {
				t.Errorf("scans: got = %d, want = 2", n)
			}
			if n := rc.inflight.Size(); n != 0 {
				t.Errorf("scans in progress after the second scan: got = %d, want = 0", n)
			}
		})
	}
}

func TestResultCacheStoreRespectsBudget(t *testing.T) {
	t.Parallel()
	yrs, _ := scanTestRules(t)
	fc := []byte(scanTestLocaleScript)
	mrs, err := scanBytes(yrs, fc, sha256.Sum256(fc))
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	cost := resultCost(mrs)

	tests := []struct {
		name      string
		budget    int64
		wantCache bool
	}{
		{name: "result within the budget is cached", budget: cost, wantCache: true},
		{name: "result within a budget with room for two is cached once", budget: 2 * cost, wantCache: true},
		{name: "result over the budget is not cached", budget: cost - 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rc := resultCacheFrom(withResultCache(t.Context()))
			rc.budget.Store(tt.budget)
			key := resultKey{rules: yrs, sum: sha256.Sum256(fc), size: int64(len(fc))}
			rc.store(key, mrs)
			if _, ok := rc.m.Load(key); ok != tt.wantCache {
				t.Errorf("cached: got = %t, want = %t", ok, tt.wantCache)
			}
			wantBudget := tt.budget
			if tt.wantCache {
				wantBudget -= cost
			}
			if got := rc.budget.Load(); got != wantBudget {
				t.Errorf("budget: got = %d, want = %d", got, wantBudget)
			}
			// Storing the same key again does not spend the budget twice.
			rc.store(key, mrs)
			if got := rc.budget.Load(); got != wantBudget {
				t.Errorf("budget after a repeated store: got = %d, want = %d", got, wantBudget)
			}
		})
	}
}

func TestResultCostCountsRulesAndMatches(t *testing.T) {
	t.Parallel()
	yrs, _ := scanTestRules(t)
	none, err := scanBytes(yrs, []byte("zz"), sha256.Sum256([]byte("zz")))
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	npm := readTestFile(t, scanTestNPMFixture)
	hit, err := scanBytes(yrs, npm, sha256.Sum256(npm))
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(none.MatchingRules()) != 0 {
		t.Fatalf("fixture precondition: got %d matching rules for a two-byte input, want 0", len(none.MatchingRules()))
	}
	if got := resultCost(none); got != 128 {
		t.Errorf("cost without matches: got = %d, want = 128", got)
	}
	want := int64(128)
	for _, r := range hit.MatchingRules() {
		want += 512
		for _, p := range r.Patterns() {
			want += 64 + 16*int64(len(p.Matches()))
		}
	}
	if got := resultCost(hit); got != want || got <= 128 {
		t.Errorf("cost with matches: got = %d, want = %d", got, want)
	}
}

func TestSniffFileMatchesProgramkindFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	scanTestWriteFile(t, filepath.Join(dir, "run"), []byte("#!/bin/sh\necho hi\n"))
	scanTestWriteFile(t, filepath.Join(dir, "empty.sh"), nil)
	scanTestWriteFile(t, filepath.Join(dir, "notes.txt"), []byte("plain words\n"))
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("open root: %v", err)
	}
	// Subtests run in parallel after this function returns.
	t.Cleanup(func() { _ = root.Close() })
	if err := root.Mkdir("sub", 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	tests := []struct {
		name        string
		file        string // beneath dir
		wantContent bool
	}{
		{name: "script is read and detected", file: "run", wantContent: true},
		{name: "data file is read and detected as nothing", file: "notes.txt", wantContent: true},
		{name: "empty file is not read", file: "empty.sh"},
		{name: "directory is left to programkind.File", file: "sub"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(dir, tt.file)
			fi, err := root.Stat(tt.file)
			if err != nil {
				t.Fatalf("stat: %v", err)
			}
			s := sniffFile(t.Context(), root, tt.file, path, fi)
			defer s.close()
			want, wantErr := programkind.File(t.Context(), path)
			if fi.Size() == 0 {
				want, wantErr = nil, nil
			}
			if !reflect.DeepEqual(s.kind, want) || (s.err == nil) != (wantErr == nil) {
				t.Errorf("kind: got = %+v (%v), want = %+v (%v)", s.kind, s.err, want, wantErr)
			}
			if got := s.content != nil; got != tt.wantContent {
				t.Errorf("read: got = %t, want = %t", got, tt.wantContent)
			}
			if tt.wantContent {
				b, _ := root.ReadFile(tt.file)
				if string(s.content.Bytes()) != string(b) {
					t.Errorf("contents: got = %q, want = %q", s.content.Bytes(), b)
				}
				// close releases the contents.
				s.close()
				if n := len(s.content.Bytes()); n != 0 {
					t.Errorf("contents after close: got %d bytes, want none", n)
				}
			}
		})
	}
}

func TestSniffFileFileChangedAfterStat(t *testing.T) {
	t.Parallel()
	// replace stats a file of the given kind at name beneath root, then
	// replaces it with one of the other kind, returning the stale stat result.
	replace := func(t *testing.T, root *os.Root, name string, dirFirst bool) fs.FileInfo {
		t.Helper()
		path := filepath.Join(root.Name(), name)
		if dirFirst {
			scanTestWriteFile(t, filepath.Join(path, "entry"), []byte("x"))
		} else {
			scanTestWriteFile(t, path, []byte("#!/bin/sh\necho hi\n"))
		}
		fi, err := root.Stat(name)
		if err != nil {
			t.Fatalf("stat: %v", err)
		}
		if fi.Size() == 0 {
			t.Fatalf("fixture precondition: got a zero size for %q, want a size", path)
		}
		if err := root.RemoveAll(name); err != nil {
			t.Fatalf("remove: %v", err)
		}
		if dirFirst {
			scanTestWriteFile(t, path, []byte("#!/bin/sh\necho hi\n"))
		} else if err := root.Mkdir(name, 0o700); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		return fi
	}

	tests := []struct {
		name       string
		dirFirst   bool
		lockParent bool // remove access to the parent directory after the stat
		wantKind   bool
		wantErr    error
	}{
		{name: "directory replaced by a script is detected as programkind.File detects it", dirFirst: true, wantKind: true},
		{name: "directory that can no longer be reached reports the stat error", dirFirst: true, lockParent: true, wantErr: fs.ErrPermission},
		{name: "regular file replaced by a directory reports the read error", wantErr: syscall.EISDIR},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if tt.lockParent && os.Geteuid() == 0 {
				t.Skip("root reaches files regardless of permissions")
			}
			base := t.TempDir()
			root, err := os.OpenRoot(base)
			if err != nil {
				t.Fatalf("open root: %v", err)
			}
			// Closed after the parent's permissions are restored.
			t.Cleanup(func() { _ = root.Close() })
			name := filepath.Join("parent", "target")
			path := filepath.Join(base, name)
			fi := replace(t, root, name, tt.dirFirst)
			if tt.lockParent {
				if err := root.Chmod("parent", 0); err != nil {
					t.Fatalf("chmod: %v", err)
				}
				t.Cleanup(func() { _ = root.Chmod("parent", 0o700) })
			}

			s := sniffFile(t.Context(), root, name, path, fi)
			defer s.close()
			if !errors.Is(s.err, tt.wantErr) {
				t.Errorf("error: got = %v, want = %v", s.err, tt.wantErr)
			}
			if s.content != nil {
				t.Errorf("read: got contents, want none")
			}
			if got := s.kind != nil; got != tt.wantKind {
				t.Errorf("kind detected: got = %t (%+v), want = %t", got, s.kind, tt.wantKind)
			}
			if tt.wantKind {
				want, err := programkind.File(t.Context(), path)
				if err != nil || !reflect.DeepEqual(s.kind, want) {
					t.Errorf("kind: got = %+v, want = %+v (%v)", s.kind, want, err)
				}
			}
		})
	}
}

func TestSniffFileReportsUnreadableFile(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("root reads files regardless of permissions")
	}
	dir := t.TempDir()
	path := scanTestWriteFile(t, filepath.Join(dir, "locked.sh"), []byte("#!/bin/sh\n"))
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("open root: %v", err)
	}
	defer root.Close()
	if err := root.Chmod("locked.sh", 0); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	fi, err := root.Stat("locked.sh")
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	s := sniffFile(t.Context(), root, "locked.sh", path, fi)
	defer s.close()
	if !errors.Is(s.err, fs.ErrPermission) || s.content != nil || s.kind != nil {
		t.Errorf("sniff: got kind %+v, content %v, err %v; want a permission error from open and nothing read", s.kind, s.content != nil, s.err)
	}
}

func TestScanContentSetsFileSHA256(t *testing.T) {
	t.Parallel()
	hello := []byte("hello\n")
	digest := sha256.Sum256(hello)
	src := `rule digest_match { condition: file_sha256 == "` + hex.EncodeToString(digest[:]) + `" }`
	yrs, err := compile.Recursive(t.Context(), []fs.FS{fstest.MapFS{"digest.yara": {Data: []byte(src)}}})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	matched := func(mrs *yarax.ScanResults) bool {
		for _, m := range mrs.MatchingRules() {
			if m.Identifier() == "digest_match" {
				return true
			}
		}
		return false
	}

	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{name: "content with the digest matches", data: hello, want: true},
		{name: "other content does not match", data: []byte("goodbye\n")},
		{name: "the same content matches again on a reused scanner", data: hello, want: true},
	}
	for _, tt := range tests {
		mrs, err := scanContent(t.Context(), yrs, tt.data, sha256.Sum256(tt.data))
		if err != nil {
			t.Fatalf("%s: scan: %v", tt.name, err)
		}
		if got := matched(mrs); got != tt.want {
			t.Errorf("%s: matched: got = %t, want = %t", tt.name, got, tt.want)
		}
	}

	// A scan without a digest must not inherit the digest the scanner was
	// given for the previous file.
	if _, err := scanContent(t.Context(), yrs, hello, digest); err != nil {
		t.Fatalf("scan: %v", err)
	}
	dir := t.TempDir()
	scanTestWriteFile(t, filepath.Join(dir, "other"), []byte("other\n"))
	other, err := file.ReadFileIn(dir, "other")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	mrs, err := withScanner(yrs, int64(len(other)), func(s *yarax.Scanner) (*yarax.ScanResults, error) {
		setFileSHA256(s, "")
		return s.Scan(other)
	})
	if err != nil {
		t.Fatalf("scan without a digest: %v", err)
	}
	if matched(mrs) {
		t.Errorf("scan without a digest after a matching scan: got a match, want none")
	}
}

func TestScanFileScansContentsReadOnce(t *testing.T) {
	t.Parallel()
	hello := []byte("hello\n")
	digest := sha256.Sum256(hello)
	src := `rule digest_match { condition: file_sha256 == "` + hex.EncodeToString(digest[:]) + `" }`
	yrs, err := compile.Recursive(t.Context(), []fs.FS{fstest.MapFS{"digest.yara": {Data: []byte(src)}}})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	dir := t.TempDir()
	path := scanTestWriteFile(t, filepath.Join(dir, "hello"), hello)
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("open root: %v", err)
	}
	defer root.Close()
	fi, err := root.Stat("hello")
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	s := sniffFile(t.Context(), root, "hello", path, fi)
	defer s.close()
	if s.content == nil {
		t.Fatalf("fixture precondition: got no contents read, want %q", hello)
	}

	// The contents are scanned with their digest.
	fc := s.content.Bytes()
	matching, err := scanFile(t.Context(), malcontent.Config{Rules: yrs}, s, path, "", fc, sha256.Sum256(capContents(fc)))
	if err != nil {
		t.Fatalf("scanFile: %v", err)
	}
	got := make([]string, 0, len(matching))
	for _, r := range matching {
		got = append(got, r.Identifier())
	}
	if want := []string{"digest_match"}; !slices.Equal(got, want) {
		t.Errorf("matching rules: got = %q, want = %q", got, want)
	}
}

func TestSniffedCloseReleasesItsRootOnce(t *testing.T) {
	t.Parallel()
	releases := 0
	s := &sniffed{release: func() { releases++ }}
	s.close()
	s.close()
	if releases != 1 {
		t.Errorf("releases: got = %d, want = 1", releases)
	}
}
