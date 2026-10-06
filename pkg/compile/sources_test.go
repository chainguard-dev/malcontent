// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package compile

import (
	"bytes"
	"context"
	"errors"
	"fmt"
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
			got := string(newRuleRemover(tt.remove).remove(data))
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

// compileOpenFailFS lists the files of its MapFS but fails to open the one
// named fail.
type compileOpenFailFS struct {
	fstest.MapFS
	fail string
}

func (f compileOpenFailFS) Open(name string) (fs.File, error) {
	if name == f.fail {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrPermission}
	}
	return f.MapFS.Open(name)
}

// compileHashOf returns the cache key for fsys.
func compileHashOf(t *testing.T, fsys fs.FS) string {
	t.Helper()
	h, err := getRulesHash(t.Context(), []fs.FS{fsys})
	if err != nil {
		t.Fatalf("getRulesHash(): %v", err)
	}
	return h
}

// compileWithByte returns a copy of data with the byte at i set to b.
func compileWithByte(data []byte, i int, b byte) []byte {
	out := bytes.Clone(data)
	out[i] = b
	return out
}

func TestGetRulesHashTracksRuleSources(t *testing.T) {
	t.Parallel()
	// big spans three hash chunks, so edits confined to one chunk are covered.
	big := bytes.Repeat([]byte("rule_bytes\n"), 3*hashChunkSize/11)
	newFS := func() fstest.MapFS {
		m := fstest.MapFS{
			"a.yara":       {Data: []byte("rule a { condition: true }")},
			"nested/b.yar": {Data: []byte("rule b { condition: true }")},
			"notes.txt":    {Data: []byte("notes")},
			"big.yar":      {Data: big},
		}
		for i := range 64 {
			m[fmt.Sprintf("many/r%02d.yara", i)] = &fstest.MapFile{Data: fmt.Appendf(nil, "rule r%02d { condition: true }", i)}
		}
		return m
	}
	base := compileHashOf(t, newFS())

	tests := []struct {
		name       string
		change     func(fstest.MapFS)
		wantChange bool
	}{
		{
			name:       "unchanged sources keep the hash",
			change:     func(fstest.MapFS) {},
			wantChange: false,
		},
		{
			name:       "byte change in the first chunk of a large file alters the hash",
			change:     func(m fstest.MapFS) { m["big.yar"] = &fstest.MapFile{Data: compileWithByte(big, 0, 'X')} },
			wantChange: true,
		},
		{
			name:       "byte change in a middle chunk of a large file alters the hash",
			change:     func(m fstest.MapFS) { m["big.yar"] = &fstest.MapFile{Data: compileWithByte(big, hashChunkSize+5, 'X')} },
			wantChange: true,
		},
		{
			name:       "byte change in the last chunk of a large file alters the hash",
			change:     func(m fstest.MapFS) { m["big.yar"] = &fstest.MapFile{Data: compileWithByte(big, len(big)-1, 'X')} },
			wantChange: true,
		},
		{
			name:       "appending to a large file alters the hash",
			change:     func(m fstest.MapFS) { m["big.yar"] = &fstest.MapFile{Data: append(bytes.Clone(big), '\n')} },
			wantChange: true,
		},
		{
			name:       "truncating a large file at a chunk boundary alters the hash",
			change:     func(m fstest.MapFS) { m["big.yar"] = &fstest.MapFile{Data: bytes.Clone(big[:2*hashChunkSize])} },
			wantChange: true,
		},
		{
			name: "content change in one of many small files alters the hash",
			change: func(m fstest.MapFS) {
				m["many/r31.yara"] = &fstest.MapFile{Data: []byte("rule r31 { condition: false }")}
			},
			wantChange: true,
		},
		{
			name: "swapping the contents of two rule files alters the hash",
			change: func(m fstest.MapFS) {
				m["a.yara"], m["nested/b.yar"] = m["nested/b.yar"], m["a.yara"]
			},
			wantChange: true,
		},
		{
			name:       "emptying a rule file alters the hash",
			change:     func(m fstest.MapFS) { m["a.yara"] = &fstest.MapFile{} },
			wantChange: true,
		},
		{
			name:       "adding a rule file alters the hash",
			change:     func(m fstest.MapFS) { m["c.yara"] = &fstest.MapFile{Data: []byte("rule c { condition: true }")} },
			wantChange: true,
		},
		{
			name:       "removing a rule file alters the hash",
			change:     func(m fstest.MapFS) { delete(m, "many/r00.yara") },
			wantChange: true,
		},
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
			if changed := compileHashOf(t, fsys) != base; changed != tt.wantChange {
				t.Errorf("hash changed: got = %v, want = %v", changed, tt.wantChange)
			}
		})
	}

	t.Run("file boundaries are part of the hash", func(t *testing.T) {
		t.Parallel()
		// Concatenating each path with its content cannot tell these apart.
		joined := fstest.MapFS{"a.yara": {Data: []byte("rule a {}b.yararule b {}")}}
		split := fstest.MapFS{
			"a.yara": {Data: []byte("rule a {}")},
			"b.yara": {Data: []byte("rule b {}")},
		}
		if j, s := compileHashOf(t, joined), compileHashOf(t, split); j == s {
			t.Errorf("hash of joined and split sources: got = %s for both, want different hashes", j)
		}
	})

	t.Run("walk errors are returned", func(t *testing.T) {
		t.Parallel()
		if _, err := getRulesHash(t.Context(), []fs.FS{compileDeniedFS{}}); !errors.Is(err, fs.ErrPermission) {
			t.Errorf("getRulesHash() error: got = %v, want = %v", err, fs.ErrPermission)
		}
	})

	t.Run("open errors are returned", func(t *testing.T) {
		t.Parallel()
		fsys := compileOpenFailFS{MapFS: newFS(), fail: "many/r40.yara"}
		if _, err := getRulesHash(t.Context(), []fs.FS{fsys}); !errors.Is(err, fs.ErrPermission) {
			t.Errorf("getRulesHash() error: got = %v, want = %v", err, fs.ErrPermission)
		}
	})

	t.Run("canceled context is returned", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if _, err := getRulesHash(ctx, []fs.FS{newFS()}); !errors.Is(err, context.Canceled) {
			t.Errorf("getRulesHash() error: got = %v, want = %v", err, context.Canceled)
		}
	})
}

func TestGetRulesHashIndependentOfWorkerCount(t *testing.T) {
	// Not parallel: GOMAXPROCS is process-wide.
	fsys := fstest.MapFS{"big.yar": {Data: bytes.Repeat([]byte("rule_bytes\n"), 3*hashChunkSize/11)}}
	for i := range 200 {
		fsys[fmt.Sprintf("rules/r%03d.yara", i)] = &fstest.MapFile{Data: fmt.Appendf(nil, "rule r%03d { condition: true }", i)}
	}
	prev := runtime.GOMAXPROCS(0)
	t.Cleanup(func() { runtime.GOMAXPROCS(prev) })

	var want string
	for _, procs := range []int{1, 2, 16} {
		runtime.GOMAXPROCS(procs)
		got := compileHashOf(t, fsys)
		if want == "" {
			want = got
			continue
		}
		if got != want {
			t.Errorf("getRulesHash() with GOMAXPROCS=%d: got = %s, want = %s", procs, got, want)
		}
	}
}

func TestPruneStaleCaches(t *testing.T) {
	t.Parallel()
	const day = 24 * time.Hour
	dir := t.TempDir()
	now := time.Now()

	files := []struct {
		name     string
		age      time.Duration
		isDir    bool
		wantKept bool
	}{
		{name: "rules-current.cache", age: 30 * day, wantKept: true},
		{name: "rules-current.cache.sha256", age: 30 * day, wantKept: true},
		{name: "rules-idle.cache", age: staleCacheThreshold + time.Minute, wantKept: false},
		{name: "rules-idle.cache.sha256", age: staleCacheThreshold + time.Minute, wantKept: false},
		{name: "rules-recent.cache", age: staleCacheThreshold - time.Minute, wantKept: true},
		{name: "rules-recent.cache.sha256", age: staleCacheThreshold - time.Minute, wantKept: true},
		// Loading refreshes only the cache, so its sidecar can be far older.
		{name: "rules-loaded.cache", age: day, wantKept: true},
		{name: "rules-loaded.cache.sha256", age: 30 * day, wantKept: true},
		{name: "rules-orphan.cache.sha256", age: staleCacheThreshold + time.Minute, wantKept: false},
		{name: "rules-new-orphan.cache.sha256", age: time.Hour, wantKept: true},
		{name: ".rules-123.cache.tmp", age: 30 * day, wantKept: true},
		{name: "rules-notes.txt", age: 30 * day, wantKept: true},
		{name: "rules-dir.cache", age: 30 * day, isDir: true, wantKept: true},
	}
	for _, f := range files {
		p := filepath.Join(dir, f.name)
		var err error
		if f.isDir {
			err = os.Mkdir(p, 0o700)
		} else {
			err = os.WriteFile(p, []byte("x"), 0o600)
		}
		if err != nil {
			t.Fatalf("create %s: %v", f.name, err)
		}
		mtime := now.Add(-f.age)
		if err := os.Chtimes(p, mtime, mtime); err != nil {
			t.Fatalf("chtimes %s: %v", f.name, err)
		}
	}

	pruneStaleCaches(dir, filepath.Join(dir, "rules-current.cache"), now)

	for _, f := range files {
		t.Run(f.name, func(t *testing.T) {
			t.Parallel()
			_, err := os.Lstat(filepath.Join(dir, f.name))
			if kept := err == nil; kept != f.wantKept {
				t.Errorf("%s kept: got = %v, want = %v (lstat error %v)", f.name, kept, f.wantKept, err)
			}
		})
	}
}

func TestRefreshCacheTime(t *testing.T) {
	t.Parallel()
	now := time.Now()

	tests := []struct {
		name        string
		age         time.Duration
		wantRefresh bool
	}{
		{"cache older than the touch interval is refreshed", cacheTouchInterval + time.Minute, true},
		{"cache well past the touch interval is refreshed", 30 * 24 * time.Hour, true},
		{"cache inside the touch interval keeps its time", cacheTouchInterval - time.Minute, false},
		{"just-written cache keeps its time", time.Minute, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			p := filepath.Join(t.TempDir(), "rules-x.cache")
			if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
				t.Fatalf("write %s: %v", p, err)
			}
			mtime := now.Add(-tt.age)
			if err := os.Chtimes(p, mtime, mtime); err != nil {
				t.Fatalf("chtimes %s: %v", p, err)
			}

			refreshCacheTime(p, now)

			fi, err := os.Stat(p)
			if err != nil {
				t.Fatalf("stat %s: %v", p, err)
			}
			want := mtime
			if tt.wantRefresh {
				want = now
			}
			if fi.ModTime().Sub(want).Abs() > time.Second {
				t.Errorf("modification time: got = %v, want = %v", fi.ModTime(), want)
			}
		})
	}

	t.Run("missing cache is not created", func(t *testing.T) {
		t.Parallel()
		p := filepath.Join(t.TempDir(), "rules-missing.cache")
		refreshCacheTime(p, now)
		if _, err := os.Lstat(p); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("missing cache lstat error: got = %v, want = %v", err, fs.ErrNotExist)
		}
	})
}

func TestRecursiveCachedPrunesAndRefreshesCaches(t *testing.T) {
	// Not parallel: t.Setenv redirects the user cache directory.
	cacheDir := compileIsolateCache(t)
	fss := []fs.FS{fstest.MapFS{"prune.yara": {Data: []byte("rule prune_cache { condition: true }")}}}
	current := filepath.Join(cacheDir, "rules-"+compileHashOf(t, fss[0])+".cache")

	stale := filepath.Join(cacheDir, "rules-stale.cache")
	old := time.Now().Add(-staleCacheThreshold - time.Hour)
	for _, p := range []string{stale, stale + ".sha256"} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatalf("write %s: %v", p, err)
		}
		if err := os.Chtimes(p, old, old); err != nil {
			t.Fatalf("chtimes %s: %v", p, err)
		}
	}

	first, err := RecursiveCached(t.Context(), fss)
	if err != nil || first == nil {
		t.Fatalf("first RecursiveCached(): got rules = %v, error = %v, want rules and nil error", first, err)
	}
	first.Destroy()

	for _, p := range []string{stale, stale + ".sha256"} {
		if _, err := os.Lstat(p); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("stale %s lstat error: got = %v, want = %v", filepath.Base(p), err, fs.ErrNotExist)
		}
	}
	for _, p := range []string{current, current + ".sha256"} {
		if _, err := os.Lstat(p); err != nil {
			t.Errorf("current %s lstat error: got = %v, want = nil", filepath.Base(p), err)
		}
	}

	aged := time.Now().Add(-cacheTouchInterval - time.Hour)
	if err := os.Chtimes(current, aged, aged); err != nil {
		t.Fatalf("chtimes %s: %v", current, err)
	}
	second, err := RecursiveCached(t.Context(), fss)
	if err != nil || second == nil {
		t.Fatalf("second RecursiveCached(): got rules = %v, error = %v, want rules and nil error", second, err)
	}
	second.Destroy()

	fi, err := os.Stat(current)
	if err != nil {
		t.Fatalf("stat %s: %v", current, err)
	}
	if age := time.Since(fi.ModTime()); age >= cacheTouchInterval {
		t.Errorf("loaded cache age: got = %v, want < %v", age, cacheTouchInterval)
	}
}

// removeWithFullPatterns applies both of r's replacements unconditionally.
func removeWithFullPatterns(r *ruleRemover, data []byte) []byte {
	return newlinePattern.ReplaceAll(r.rules.ReplaceAll(data, nil), []byte("\n\n"))
}

func TestRuleRemoverShortcutsMatchFullPatterns(t *testing.T) {
	t.Parallel()
	r := defaultRuleRemover()

	tests := []struct {
		name     string
		data     string
		wantGone string
	}{
		{
			name:     "disabled rule with tags is removed",
			data:     "rule keep { condition: true }\n\nrule Rclone : tool {\n\tcondition: true\n}\n\n\n\nrule after { condition: true }\n",
			wantGone: "rule Rclone",
		},
		{
			name:     "disabled rule among enabled rules is removed",
			data:     "rule a {\n\tcondition: true\n}\nrule Adobe_Type_1_Font {\n\tstrings:\n\t\t$a = \"x\"\n\tcondition:\n\t\t$a\n}\nrule b {\n\tcondition: true\n}\n",
			wantGone: "Adobe_Type_1_Font",
		},
		{
			name: "blank line runs collapse without disabled rules",
			data: "rule a {\n\tcondition: true\n}\n\n\n\n\nrule b {\n\tcondition: true\n}\n",
		},
		{
			name: "source without disabled rules or blank runs is unchanged",
			data: "rule a { condition: true }\n",
		},
		{
			name: "disabled name inside a string is kept",
			data: "rule a { strings: $s = \"rule Rclone\" condition: $s }\n",
		},
		{
			name: "rule whose name extends a disabled name is kept",
			data: "rule Rclone_extra {\n\tcondition: true\n}\n",
		},
		{
			name:     "consecutive disabled rules are removed",
			data:     "rule Rclone {\n\tcondition: true\n}\n\n\nrule Adobe_Type_1_Font {\n\tcondition: true\n}\nrule keep {\n\tcondition: true\n}\n",
			wantGone: "Adobe_Type_1_Font",
		},
		{
			name:     "disabled rule on the line after a closing brace is removed",
			data:     "rule a {\n\tcondition: true\n}\nrule Rclone {\n\tcondition: true\n}\n",
			wantGone: "Rclone",
		},
		{
			name:     "indented disabled rule after whitespace-only lines is removed",
			data:     "rule a { condition: true }\n \t\n\f\n\trule Rclone {\n\tcondition: true\n\t}\n",
			wantGone: "Rclone",
		},
		{
			name:     "disabled rule at the start of the source is removed",
			data:     "  \n rule Rclone {\n condition: true\n}",
			wantGone: "Rclone",
		},
		{
			name:     "disabled rule with CRLF line endings is removed",
			data:     "rule a {\r\n condition: true\r\n}\r\nrule Rclone {\r\n condition: true\r\n}\r\nrule b {\r\n condition: true\r\n}\r\n",
			wantGone: "Rclone",
		},
		{
			name: "disabled keyword after other text on its line is kept",
			data: "x rule Rclone {\n condition: true\n}\n",
		},
		{
			name: "disabled keyword after a vertical tab is kept",
			data: "\vrule Rclone {\n condition: true\n}\n",
		},
		{
			name: "unclosed disabled rule is kept",
			data: "rule keep { condition: true }\nrule Rclone {\n condition: true\n",
		},
		{
			name:     "unclosed disabled rule runs to the next closing line",
			data:     "rule Rclone {\n condition: true\nrule Adobe_Type_1_Font {\n condition: true\n}\nrule keep { condition: true }\n",
			wantGone: "Adobe_Type_1_Font",
		},
		{
			name:     "disabled rule after a rule with a disabled-name prefix is removed",
			data:     "rule Rclone_extra {\n condition: true\n}\n\nrule Rclone {\n condition: true\n}\n",
			wantGone: "rule Rclone {",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			data := []byte(tt.data)
			got := r.remove(data)
			if want := removeWithFullPatterns(r, data); !bytes.Equal(got, want) {
				t.Errorf("remove(): got = %q, want = %q", got, want)
			}
			if tt.wantGone != "" && bytes.Contains(got, []byte(tt.wantGone)) {
				t.Errorf("remove(): got = %q, want %q removed", got, tt.wantGone)
			}
		})
	}

	t.Run("embedded rule sources", func(t *testing.T) {
		t.Parallel()
		files, err := listRuleFiles(getAllRuleFS())
		if err != nil {
			t.Fatalf("listRuleFiles(): %v", err)
		}
		for _, f := range files {
			data, err := fs.ReadFile(f.fsys, f.path)
			if err != nil {
				t.Fatalf("read %s: %v", f.path, err)
			}
			if got, want := r.remove(data), removeWithFullPatterns(r, data); !bytes.Equal(got, want) {
				t.Errorf("remove(%s): got %d bytes, want %d bytes matching the full patterns", f.path, len(got), len(want))
			}
		}
	})
}

func TestLoadCachedRulesMatchesCompiledRules(t *testing.T) {
	t.Parallel()
	compiled, err := yarax.Compile(`
rule hit { strings: $s = "malcontent" condition: $s }
rule miss { condition: false }
`)
	if err != nil {
		t.Fatalf("compile test rules: %v", err)
	}
	defer compiled.Destroy()

	cacheFile := filepath.Join(t.TempDir(), "rules.cache")
	if err := saveCachedRules(compiled, cacheFile); err != nil {
		t.Fatalf("saveCachedRules(): %v", err)
	}
	loaded, err := loadCachedRules(cacheFile)
	if err != nil {
		t.Fatalf("loadCachedRules(): %v", err)
	}
	defer loaded.Destroy()

	matches := func(t *testing.T, yrs *yarax.Rules) []string {
		t.Helper()
		res, err := yrs.Scan([]byte("scanned by malcontent"))
		if err != nil {
			t.Fatalf("Scan(): %v", err)
		}
		matching := res.MatchingRules()
		ids := make([]string, 0, len(matching))
		for _, r := range matching {
			ids = append(ids, r.Identifier())
		}
		return ids
	}
	want := matches(t, compiled)
	if !slices.Equal(want, []string{"hit"}) {
		t.Fatalf("compiled rule matches: got = %q, want = [\"hit\"]", want)
	}
	if got := matches(t, loaded); !slices.Equal(got, want) {
		t.Errorf("loaded rule matches: got = %q, want = %q", got, want)
	}
	if got, want := loaded.Count(), compiled.Count(); got != want {
		t.Errorf("loaded rule count: got = %d, want = %d", got, want)
	}
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
		if got := newRuleRemover(nil).remove(data); !bytes.Equal(got, data) {
			t.Errorf("remove(data) with no names: got = %q, want = %q", got, data)
		}
	})

	t.Run("one name removes that rule", func(t *testing.T) {
		t.Parallel()
		got := string(newRuleRemover([]string{"a"}).remove(data))
		if strings.Contains(got, "rule a") {
			t.Errorf("remove(data) with name a: got = %q, want rule a removed", got)
		}
		if !strings.Contains(got, "rule b {") {
			t.Errorf("remove(data) with name a: got = %q, want rule b kept", got)
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
