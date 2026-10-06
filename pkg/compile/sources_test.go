// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package compile

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	yarax "github.com/VirusTotal/yara-x/go"
)

// compileDeniedFS is an fs.FS whose every Open fails with fs.ErrPermission.
type compileDeniedFS struct{}

func (compileDeniedFS) Open(name string) (fs.File, error) {
	return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrPermission}
}

// compileIsolateCache points the user cache directory at a fresh temporary
// directory and returns the malcontent cache directory beneath it.
func compileIsolateCache(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", root)
	t.Setenv("HOME", root)

	dir, err := getCacheDir()
	if err != nil {
		t.Fatalf("getCacheDir(): %v", err)
	}
	if !strings.HasPrefix(dir, root) {
		t.Skipf("user cache directory %q is outside the test root on %s", dir, runtime.GOOS)
	}
	return dir
}

// compileLogRecorder holds the messages RecursiveCached logged, each prefixed
// with its level.
type compileLogRecorder struct {
	mu   sync.Mutex
	msgs []string
}

func (r *compileLogRecorder) add(level, msg string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.msgs = append(r.msgs, level+" "+msg)
}

// has reports whether entry, a level and message such as "WARN text", was
// logged.
func (r *compileLogRecorder) has(entry string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Contains(r.msgs, entry)
}

// reset discards the messages recorded so far.
func (r *compileLogRecorder) reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.msgs = nil
}

// String lists the recorded messages for failure output.
func (r *compileLogRecorder) String() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return strings.Join(r.msgs, "; ")
}

// compileRecordLogs swaps the rule cache's log functions for a recorder for
// the rest of the test. Callers must not run in parallel because the log
// functions are package variables.
func compileRecordLogs(t *testing.T) *compileLogRecorder {
	t.Helper()
	rec := &compileLogRecorder{}
	prevDebug, prevWarn := logDebug, logWarn
	logDebug = func(msg string, _ ...any) { rec.add("DEBUG", msg) }
	logWarn = func(msg string, _ ...any) { rec.add("WARN", msg) }
	t.Cleanup(func() { logDebug, logWarn = prevDebug, prevWarn })
	return rec
}

func TestRemoveRulesSkipsInvalidUTF8Names(t *testing.T) {
	t.Parallel()
	data := []byte("rule remove_me {\n\tcondition: true\n}\n\nrule keep_me {\n\tcondition: true\n}\n")

	tests := []struct {
		name        string
		remove      []string
		wantRemoved bool
	}{
		{"invalid name before a valid name", []string{"\xff\xfe", "remove_me"}, true},
		{"invalid name after a valid name", []string{"remove_me", "\xff\xfe"}, true},
		{"only invalid names", []string{"\xff\xfe"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := string(removeRules(data, tt.remove))
			if removed := !strings.Contains(got, "rule remove_me"); removed != tt.wantRemoved {
				t.Errorf("remove_me removed: got = %v, want = %v (output %q)", removed, tt.wantRemoved, got)
			}
			if !strings.Contains(got, "rule keep_me") {
				t.Errorf("keep_me retained: got = false, want = true (output %q)", got)
			}
		})
	}
}

func TestRecursiveReturnsFirstFilesystemError(t *testing.T) {
	t.Parallel()
	good := fstest.MapFS{"ok.yara": {Data: []byte("rule ok { condition: true }")}}

	got, err := Recursive(t.Context(), []fs.FS{compileDeniedFS{}, good})
	if !errors.Is(err, fs.ErrPermission) {
		t.Errorf("Recursive() error: got = %v, want = %v", err, fs.ErrPermission)
	}
	if got != nil {
		got.Destroy()
		t.Error("Recursive() rules: got = non-nil, want = nil")
	}
}

func TestGetRulesHashTracksRuleSources(t *testing.T) {
	t.Parallel()
	newFS := func() fstest.MapFS {
		return fstest.MapFS{
			"a.yara":       {Data: []byte("rule a { condition: true }")},
			"nested/b.yar": {Data: []byte("rule b { condition: true }")},
			"notes.txt":    {Data: []byte("notes")},
		}
	}
	hashOf := func(t *testing.T, fsys fs.FS) string {
		t.Helper()
		h, err := getRulesHash(t.Context(), []fs.FS{fsys})
		if err != nil {
			t.Fatalf("getRulesHash(): %v", err)
		}
		return h
	}
	base := hashOf(t, newFS())

	tests := []struct {
		name       string
		change     func(fstest.MapFS)
		wantChange bool
	}{
		{
			name:       ".yara content change alters the hash",
			change:     func(m fstest.MapFS) { m["a.yara"] = &fstest.MapFile{Data: []byte("rule a { condition: false }")} },
			wantChange: true,
		},
		{
			name:       ".yar content change alters the hash",
			change:     func(m fstest.MapFS) { m["nested/b.yar"] = &fstest.MapFile{Data: []byte("rule b { condition: false }")} },
			wantChange: true,
		},
		{
			name: "renaming a rule file alters the hash",
			change: func(m fstest.MapFS) {
				m["c.yara"] = m["a.yara"]
				delete(m, "a.yara")
			},
			wantChange: true,
		},
		{
			name:       "non-rule content change keeps the hash",
			change:     func(m fstest.MapFS) { m["notes.txt"] = &fstest.MapFile{Data: []byte("other notes")} },
			wantChange: false,
		},
		{
			name:       "added non-rule file keeps the hash",
			change:     func(m fstest.MapFS) { m["README.md"] = &fstest.MapFile{Data: []byte("readme")} },
			wantChange: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fsys := newFS()
			tt.change(fsys)
			if changed := hashOf(t, fsys) != base; changed != tt.wantChange {
				t.Errorf("hash changed: got = %v, want = %v", changed, tt.wantChange)
			}
		})
	}

	t.Run("walk errors are returned", func(t *testing.T) {
		t.Parallel()
		if _, err := getRulesHash(t.Context(), []fs.FS{compileDeniedFS{}}); !errors.Is(err, fs.ErrPermission) {
			t.Errorf("getRulesHash() error: got = %v, want = %v", err, fs.ErrPermission)
		}
	})
}

func TestGetYaraXVersionMatchesGoMod(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile(filepath.Join("..", "..", "go.mod"))
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}

	var want string
	for line := range strings.Lines(string(data)) {
		if f := strings.Fields(line); len(f) >= 2 && f[0] == "github.com/VirusTotal/yara-x/go" {
			want = f[1]
			break
		}
	}
	if want == "" {
		t.Fatal("go.mod does not require github.com/VirusTotal/yara-x/go")
	}

	if got := getYaraXVersion(); got != want {
		t.Errorf("getYaraXVersion(): got = %q, want = %q", got, want)
	}
}

func TestSweepStaleTempFilesSkipsUnreadableEntries(t *testing.T) {
	t.Parallel()
	cacheDir := t.TempDir()

	// Glob returns matches in sorted order, so the dangling link is visited
	// before the stale temp file.
	dangling := filepath.Join(cacheDir, ".rules-0-dangling.tmp")
	if err := os.Symlink(filepath.Join(cacheDir, "missing-target"), dangling); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	stale := filepath.Join(cacheDir, ".rules-stale.cache.tmp")
	if err := os.WriteFile(stale, []byte("x"), 0o600); err != nil {
		t.Fatalf("write %s: %v", stale, err)
	}
	old := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(stale, old, old); err != nil {
		t.Fatalf("chtimes %s: %v", stale, err)
	}

	sweepStaleTempFiles(cacheDir)

	if _, err := os.Stat(stale); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("stale temp file stat error: got = %v, want = %v", err, fs.ErrNotExist)
	}
	if _, err := os.Lstat(dangling); err != nil {
		t.Errorf("dangling link lstat error: got = %v, want = nil", err)
	}
}

func TestRecursiveCachedStoresAndReusesRules(t *testing.T) {
	// Not parallel: t.Setenv redirects the user cache directory and the
	// package log functions are swapped for a recorder.
	cacheDir := compileIsolateCache(t)
	logs := compileRecordLogs(t)
	fss := []fs.FS{fstest.MapFS{"cache.yara": {Data: []byte("rule cached { condition: true }")}}}

	hash, err := getRulesHash(t.Context(), fss)
	if err != nil {
		t.Fatalf("getRulesHash(): %v", err)
	}
	cacheFile := filepath.Join(cacheDir, "rules-"+hash+".cache")

	first, err := RecursiveCached(t.Context(), fss)
	if err != nil || first == nil {
		t.Fatalf("first RecursiveCached(): got rules = %v, error = %v, want rules and nil error", first, err)
	}
	first.Destroy()

	for _, p := range []string{cacheFile, cacheFile + ".sha256"} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("cache artifact %s stat error: got = %v, want = nil", filepath.Base(p), err)
		}
	}
	if !logs.has("DEBUG Saved rules to cache") || logs.has("WARN Failed to save rules to cache") {
		t.Errorf("cache miss log: got = %q, want a saved entry and no save failure", logs)
	}

	logs.reset()
	second, err := RecursiveCached(t.Context(), fss)
	if err != nil || second == nil {
		t.Fatalf("second RecursiveCached(): got rules = %v, error = %v, want rules and nil error", second, err)
	}
	second.Destroy()

	if !logs.has("DEBUG Loaded rules from cache") {
		t.Errorf("cache hit log: got = %q, want a loaded-from-cache entry", logs)
	}
}

func TestRecursiveCachedCompilesWhenCacheIsUnwritable(t *testing.T) {
	// Not parallel: t.Setenv redirects the user cache directory and the
	// package log functions are swapped for a recorder.
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory write permissions")
	}
	cacheDir := compileIsolateCache(t)
	if err := os.Chmod(cacheDir, 0o500); err != nil {
		t.Fatalf("chmod %s: %v", cacheDir, err)
	}
	t.Cleanup(func() { _ = os.Chmod(cacheDir, 0o700) })
	logs := compileRecordLogs(t)
	fss := []fs.FS{fstest.MapFS{"readonly.yara": {Data: []byte("rule readonly_cache { condition: true }")}}}

	got, err := RecursiveCached(t.Context(), fss)
	if err != nil || got == nil {
		t.Fatalf("RecursiveCached(): got rules = %v, error = %v, want rules and nil error", got, err)
	}
	got.Destroy()

	if !logs.has("WARN Failed to save rules to cache") || logs.has("DEBUG Saved rules to cache") {
		t.Errorf("cache save log: got = %q, want a save failure and no saved entry", logs)
	}
}

// compileOpenFilesUnder counts this process's open file descriptors that refer
// to paths beneath dir. It reads /proc/self/fd and skips the test where that
// is unavailable.
func compileOpenFilesUnder(t *testing.T, dir string) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skipf("open file descriptors are not listable: %v", err)
	}
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatalf("EvalSymlinks(%q): %v", dir, err)
	}
	prefix := resolved + string(filepath.Separator)
	n := 0
	for _, e := range entries {
		target, err := os.Readlink(filepath.Join("/proc/self/fd", e.Name()))
		if err == nil && strings.HasPrefix(target, prefix) {
			n++
		}
	}
	return n
}

func TestRemoveRulesNameCount(t *testing.T) {
	t.Parallel()
	data := []byte("rule a {\n\tcondition: true\n}\n\n\n\nrule b {\n\tcondition: true\n}\n")

	t.Run("no names leaves the data untouched", func(t *testing.T) {
		t.Parallel()
		if got := removeRules(data, nil); !bytes.Equal(got, data) {
			t.Errorf("removeRules(data, nil): got = %q, want = %q", got, data)
		}
	})

	t.Run("one name removes that rule", func(t *testing.T) {
		t.Parallel()
		got := string(removeRules(data, []string{"a"}))
		if strings.Contains(got, "rule a") {
			t.Errorf("removeRules(data, [a]): got = %q, want rule a removed", got)
		}
		if !strings.Contains(got, "rule b {") {
			t.Errorf("removeRules(data, [a]): got = %q, want rule b kept", got)
		}
	})
}

func TestRecursiveSkipsDirectoriesNamedLikeRules(t *testing.T) {
	t.Parallel()
	fsys := fstest.MapFS{"bundle.yara/inner.yara": {Data: []byte("rule inner { condition: true }")}}

	got, err := Recursive(t.Context(), []fs.FS{fsys})
	if err != nil {
		t.Fatalf("Recursive() error: got = %v, want = nil", err)
	}
	if got == nil {
		t.Fatal("Recursive() rules: got = nil, want = compiled rules")
	}
	if n := got.Count(); n != 1 {
		t.Errorf("compiled rule count: got = %d, want = 1", n)
	}
}

func TestLoadCachedRulesMissingCacheFile(t *testing.T) {
	t.Parallel()
	cacheFile := filepath.Join(t.TempDir(), "rules.cache")
	if err := os.WriteFile(cacheFile+".sha256", []byte(strings.Repeat("0", 64)+"\n"), 0o600); err != nil {
		t.Fatalf("write sidecar: %v", err)
	}

	got, err := loadCachedRules(cacheFile)
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("loadCachedRules() error: got = %v, want = %v", err, fs.ErrNotExist)
	}
	if got != nil {
		t.Error("loadCachedRules() rules: got = non-nil, want = nil")
	}
}

func TestSaveCachedRulesCleansUp(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		// blocked names a path, relative to the cache file, that is created as
		// a directory so renaming onto it fails; empty for none.
		blocked   string
		wantErr   string
		wantCache bool
	}{
		{"successful save", "", "", true},
		{"cache path taken by a directory", "rules.cache", "rename cache file", false},
		{"sidecar path taken by a directory", "rules.cache.sha256", "rename sidecar file", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			yrs, err := yarax.Compile("rule cache_cleanup { condition: true }")
			if err != nil {
				t.Fatalf("compile test rule: %v", err)
			}
			dir := t.TempDir()
			cacheFile := filepath.Join(dir, "rules.cache")
			if tt.blocked != "" {
				if err := os.Mkdir(filepath.Join(dir, tt.blocked), 0o700); err != nil {
					t.Fatalf("mkdir %s: %v", tt.blocked, err)
				}
			}

			err = saveCachedRules(yrs, cacheFile)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("saveCachedRules() error: got = %v, want = nil", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("saveCachedRules() error: got = %v, want one containing %q", err, tt.wantErr)
			}

			leftovers, err := filepath.Glob(filepath.Join(dir, ".rules-*.tmp"))
			if err != nil {
				t.Fatalf("glob temp files: %v", err)
			}
			if len(leftovers) != 0 {
				t.Errorf("temp files left behind: got = %v, want none", leftovers)
			}

			fi, err := os.Lstat(cacheFile)
			gotCache := err == nil && fi.Mode().IsRegular()
			if gotCache != tt.wantCache {
				t.Errorf("cache file present: got = %v, want = %v (stat error %v)", gotCache, tt.wantCache, err)
			}

			if n := compileOpenFilesUnder(t, dir); n != 0 {
				t.Errorf("open files under the cache directory: got = %d, want = 0", n)
			}
		})
	}
}

func TestRecursiveCachedFallsBackWhenCacheDirIsUnsafe(t *testing.T) {
	// Not parallel: t.Setenv redirects the user cache directory and t.Chdir
	// moves the working directory.
	root := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", root)
	t.Setenv("HOME", root)
	userCache, err := os.UserCacheDir()
	if err != nil || !strings.HasPrefix(userCache, root) {
		t.Skipf("user cache directory %q (error %v) is outside the test root on %s", userCache, err, runtime.GOOS)
	}

	// A cache directory others can read is refused, so compilation must fall
	// back to an uncached build and write no cache anywhere.
	cacheDir := filepath.Join(userCache, "malcontent")
	if err := os.MkdirAll(cacheDir, 0o700); err != nil {
		t.Fatalf("MkdirAll(%q): %v", cacheDir, err)
	}
	if err := os.Chmod(cacheDir, 0o755); err != nil {
		t.Fatalf("Chmod(%q): %v", cacheDir, err)
	}
	if _, err := getCacheDir(); err == nil {
		t.Fatal("getCacheDir() error: got = nil, want an unsafe permissions error")
	}
	work := t.TempDir()
	t.Chdir(work)

	fss := []fs.FS{fstest.MapFS{"fallback.yara": {Data: []byte("rule fallback { condition: true }")}}}
	got, err := RecursiveCached(t.Context(), fss)
	if err != nil || got == nil {
		t.Fatalf("RecursiveCached(): got rules = %v, error = %v, want rules and nil error", got, err)
	}

	for _, dir := range []string{work, cacheDir} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("ReadDir(%q): %v", dir, err)
		}
		if len(entries) != 0 {
			t.Errorf("entries in %s: got = %d, want none", dir, len(entries))
		}
	}
}
