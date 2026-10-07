// Copyright 2025 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package compile

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/chainguard-dev/malcontent/pkg/file"
	thirdparty "github.com/chainguard-dev/malcontent/third_party"
)

// getAllRuleFS returns both regular and third-party rule filesystems.
func getAllRuleFS() []fs.FS {
	return []fs.FS{FS, thirdparty.FS}
}

// clearRulesCache removes any existing cached rules.
func clearRulesCache(t *testing.T, fss []fs.FS) {
	t.Helper()
	ctx := t.Context()

	cache, err := openCacheDir()
	if err != nil {
		t.Fatalf("Failed to get cache directory: %v", err)
	}
	defer func() { _ = cache.Close() }()

	hash, err := getRulesHash(ctx, fss)
	if err != nil {
		t.Fatalf("Failed to get rules hash: %v", err)
	}

	if err := cache.Remove(fmt.Sprintf("rules-%s.cache", hash)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Failed to remove cache file: %v", err)
	}
}

// clearRulesCacheB is the benchmark version of clearRulesCache.
func clearRulesCacheB(b *testing.B, fss []fs.FS) {
	b.Helper()
	ctx := b.Context()

	cache, err := openCacheDir()
	if err != nil {
		b.Fatalf("Failed to get cache directory: %v", err)
	}
	defer func() { _ = cache.Close() }()

	hash, err := getRulesHash(ctx, fss)
	if err != nil {
		b.Fatalf("Failed to get rules hash: %v", err)
	}

	if err := cache.Remove(fmt.Sprintf("rules-%s.cache", hash)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		b.Fatalf("Failed to remove cache file: %v", err)
	}
}

func TestRecursive(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	rules, err := Recursive(ctx, getAllRuleFS())
	if err != nil {
		t.Fatalf("Recursive compilation failed: %v", err)
	}

	if rules == nil {
		t.Fatal("Recursive() rules: got = nil, want = compiled rules")
	}
}

func TestGetRulesHash(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	fss := getAllRuleFS()
	hash1, err := getRulesHash(ctx, fss)
	if err != nil {
		t.Fatalf("getRulesHash failed: %v", err)
	}

	if hash1 == "" {
		t.Fatal("getRulesHash(): got = empty, want = a non-empty hash")
	}

	hash2, err := getRulesHash(ctx, fss)
	if err != nil {
		t.Fatalf("getRulesHash failed on second call: %v", err)
	}

	if hash1 != hash2 {
		t.Fatalf("second getRulesHash(): got = %s, want = %s", hash2, hash1)
	}

	t.Logf("Rules hash: %s", hash1)
}

func TestCacheOperations(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	cache := compileOpenRoot(t, t.TempDir())

	originalRules, err := Recursive(ctx, getAllRuleFS())
	if err != nil {
		t.Fatalf("Initial compilation failed: %v", err)
	}

	cacheName := "test-rules.cache"

	err = saveCachedRules(cache, cacheName, originalRules)
	if err != nil {
		t.Fatalf("Failed to save rules to cache: %v", err)
	}

	if _, err := cache.Stat(cacheName); errors.Is(err, fs.ErrNotExist) {
		t.Fatal("Cache file was not created")
	}

	cachedRules, err := loadCachedRules(cache, cacheName)
	if err != nil {
		t.Fatalf("Failed to load rules from cache: %v", err)
	}

	if cachedRules == nil {
		t.Fatal("loadCachedRules() rules: got = nil, want = loaded rules")
	}

	_, err = loadCachedRules(cache, "does-not-exist.cache")
	if err == nil {
		t.Fatal("loadCachedRules(missing file) error: got = nil, want = non-nil")
	}
}

func TestRecursiveCached(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	fss := getAllRuleFS()

	clearRulesCache(t, fss)

	start1 := time.Now()
	rules1, err := RecursiveCached(ctx, fss)
	duration1 := time.Since(start1)

	if err != nil {
		t.Fatalf("First RecursiveCached call failed: %v", err)
	}

	if rules1 == nil {
		t.Fatal("first RecursiveCached() rules: got = nil, want = compiled rules")
	}

	t.Logf("First compilation (cache miss) took: %v", duration1)

	start2 := time.Now()
	rules2, err := RecursiveCached(ctx, fss)
	duration2 := time.Since(start2)

	if err != nil {
		t.Fatalf("Second RecursiveCached call failed: %v", err)
	}

	if rules2 == nil {
		t.Fatal("second RecursiveCached() rules: got = nil, want = compiled rules")
	}

	t.Logf("Second compilation (cache hit) took: %v", duration2)

	if duration2 >= duration1 {
		t.Errorf("Cache hit (%v) was not faster than compilation (%v)", duration2, duration1)
	} else {
		speedup := float64(duration1) / float64(duration2)
		t.Logf("Cache speedup: %.1fx faster", speedup)

		if speedup < 3.0 {
			t.Errorf("cache speedup: got = %.1fx, want >= 3.0x", speedup)
		}
	}
}

func TestRecursiveCachedFallback(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	rules, err := RecursiveCached(ctx, getAllRuleFS())
	if err != nil {
		t.Fatalf("RecursiveCached failed: %v", err)
	}

	if rules == nil {
		t.Fatal("RecursiveCached() rules: got = nil, want = compiled rules")
	}
}

func TestOpenCacheDir(t *testing.T) {
	t.Parallel()
	cache, err := openCacheDir()
	if err != nil {
		t.Fatalf("openCacheDir failed: %v", err)
	}
	defer func() { _ = cache.Close() }()
	var expectedDir string
	if userCacheDir, err := os.UserCacheDir(); err == nil {
		expectedDir = filepath.Join(userCacheDir, "malcontent")
	} else {
		expectedDir = filepath.Join(os.TempDir(), "malcontent-cache")
	}

	if got := cache.Name(); got != expectedDir {
		t.Fatalf("openCacheDir() name: got = %s, want = %s", got, expectedDir)
	}

	info, err := file.Stat(expectedDir)
	if err != nil {
		t.Fatalf("Cache directory does not exist: %v", err)
	}

	if !info.IsDir() {
		t.Fatal("Cache path is not a directory")
	}

	t.Logf("Cache directory: %s", expectedDir)
}

func TestCacheFileSize(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	cache := compileOpenRoot(t, t.TempDir())

	fss := getAllRuleFS()
	rules, err := Recursive(ctx, fss)
	if err != nil {
		t.Fatalf("Compilation failed: %v", err)
	}

	hash, err := getRulesHash(ctx, fss)
	if err != nil {
		t.Fatalf("Hash calculation failed: %v", err)
	}

	cacheName := "rules-" + hash + ".cache"
	err = saveCachedRules(cache, cacheName, rules)
	if err != nil {
		t.Fatalf("Failed to save to cache: %v", err)
	}

	fi, err := cache.Stat(cacheName)
	if err != nil {
		t.Fatalf("Failed to stat cache file: %v", err)
	}

	// yara-x 1.10.0 reduced compiled ruleset sizes
	// originally 50000000
	if fi.Size() < 30000000 {
		t.Fatalf("Cache file seems too small: %d bytes", fi.Size())
	}

	t.Logf("Cache file: %s", filepath.Join(cache.Name(), cacheName))
	t.Logf("Cache file size: %d bytes (%.2f MB)", fi.Size(), float64(fi.Size())/1024/1024)
}

func TestCacheIntegrity_SidecarRoundtrip(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	cache := compileOpenRoot(t, t.TempDir())
	rules, err := Recursive(ctx, getAllRuleFS())
	if err != nil {
		t.Fatalf("Recursive failed: %v", err)
	}

	cacheName := "integrity.cache"
	if err := saveCachedRules(cache, cacheName, rules); err != nil {
		t.Fatalf("saveCachedRules failed: %v", err)
	}

	if _, err := cache.Stat(cacheName); err != nil {
		t.Fatalf("cache file missing: %v", err)
	}
	if _, err := cache.Stat(cacheName + ".sha256"); err != nil {
		t.Fatalf("sidecar missing: %v", err)
	}

	if _, err := loadCachedRules(cache, cacheName); err != nil {
		t.Fatalf("loadCachedRules failed before tamper: %v", err)
	}

	bs, err := cache.ReadFile(cacheName)
	if err != nil {
		t.Fatalf("read cache: %v", err)
	}
	if len(bs) == 0 {
		t.Fatal("cache file is empty; cannot tamper")
	}
	bs[0] ^= 0xff
	if err := cache.WriteFile(cacheName, bs, 0o600); err != nil {
		t.Fatalf("tamper write: %v", err)
	}

	// Corruption must be rejected: a tampered cache yields a non-nil error and
	// no rules, whether the byte change is caught while deserializing or by the
	// post-deserialization digest comparison.
	if got, err := loadCachedRules(cache, cacheName); err == nil {
		t.Fatal("loadCachedRules() after tamper error: got = nil, want = non-nil")
	} else if got != nil {
		t.Fatal("tampered cache must not return rules")
	}

	if err := cache.Remove(cacheName + ".sha256"); err != nil {
		t.Fatalf("remove sidecar: %v", err)
	}
	if _, err := loadCachedRules(cache, cacheName); err == nil {
		t.Fatal("loadCachedRules() without sidecar error: got = nil, want = non-nil")
	}
}

func TestLoadCachedRules_DigestMismatchRejected(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	cache := compileOpenRoot(t, t.TempDir())
	rules, err := Recursive(ctx, getAllRuleFS())
	if err != nil {
		t.Fatalf("Recursive failed: %v", err)
	}

	cacheName := "mismatch.cache"
	if err := saveCachedRules(cache, cacheName, rules); err != nil {
		t.Fatalf("saveCachedRules failed: %v", err)
	}

	// A deserializable cache file paired with a wrong sidecar digest exercises
	// the verify-after-deserialize comparison: ReadFrom succeeds, then the
	// computed digest disagrees with the sidecar and the rules are rejected.
	if _, err := loadCachedRules(cache, cacheName); err != nil {
		t.Fatalf("loadCachedRules failed before sidecar tamper: %v", err)
	}

	wrongDigest := strings.Repeat("0", 64)
	if err := cache.WriteFile(cacheName+".sha256", []byte(wrongDigest+"\n"), 0o600); err != nil {
		t.Fatalf("write tampered sidecar: %v", err)
	}

	got, err := loadCachedRules(cache, cacheName)
	if err == nil {
		t.Fatal("loadCachedRules() with a wrong digest error: got = nil, want = non-nil")
	}
	if got != nil {
		t.Fatal("rules that failed integrity verification must not be returned")
	}
	if !strings.Contains(err.Error(), "integrity mismatch") {
		t.Fatalf("loadCachedRules() error: got = %v, want an integrity mismatch", err)
	}
}

func TestSweepStaleTempFiles(t *testing.T) {
	t.Parallel()

	cache := compileOpenRoot(t, t.TempDir())

	staleCache := ".rules-stale.cache.tmp"
	staleSidecar := ".rules-stale.sha256.tmp"
	freshCache := ".rules-fresh.cache.tmp"
	liveCache := "rules-abc123.cache"
	liveSidecar := "rules-abc123.cache.sha256"

	for _, p := range []string{staleCache, staleSidecar, freshCache, liveCache, liveSidecar} {
		if err := cache.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatalf("write %s: %v", p, err)
		}
	}

	old := time.Now().Add(-48 * time.Hour)
	for _, p := range []string{staleCache, staleSidecar, liveCache, liveSidecar} {
		if err := cache.Chtimes(p, old, old); err != nil {
			t.Fatalf("chtimes %s: %v", p, err)
		}
	}

	sweepStaleTempFiles(cache)

	for _, p := range []string{staleCache, staleSidecar} {
		if _, err := cache.Stat(p); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("stale temp %s stat error: got = %v, want = %v", p, err, fs.ErrNotExist)
		}
	}
	for _, p := range []string{freshCache, liveCache, liveSidecar} {
		if _, err := cache.Stat(p); err != nil {
			t.Errorf("preserved %s stat error: got = %v, want = nil", p, err)
		}
	}
}

// BenchmarkRecursive benchmarks uncached rule compilation.
func BenchmarkRecursive(b *testing.B) {
	ctx := b.Context()
	fss := getAllRuleFS()

	for b.Loop() {
		rules, err := Recursive(ctx, fss)
		if err != nil {
			b.Fatalf("Compilation failed: %v", err)
		}
		if rules == nil {
			b.Fatal("Expected compiled rules")
		}
	}
}

// BenchmarkRecursiveCachedFirstRun benchmarks the first run (cache miss).
func BenchmarkRecursiveCachedFirstRun(b *testing.B) {
	ctx := b.Context()
	fss := getAllRuleFS()

	for b.Loop() {
		rules, err := Recursive(ctx, fss)
		if err != nil {
			b.Fatalf("Compilation failed: %v", err)
		}
		if rules == nil {
			b.Fatal("Expected compiled rules")
		}
	}
}

// BenchmarkRecursiveCachedSubsequentRuns benchmarks subsequent runs (cache hit).
func BenchmarkRecursiveCachedSubsequentRuns(b *testing.B) {
	ctx := b.Context()
	fss := getAllRuleFS()

	_, err := RecursiveCached(ctx, fss)
	if err != nil {
		b.Fatalf("Failed to populate cache: %v", err)
	}

	for b.Loop() {
		rules, err := RecursiveCached(ctx, fss)
		if err != nil {
			b.Fatalf("Cached compilation failed: %v", err)
		}
		if rules == nil {
			b.Fatal("Expected compiled rules")
		}
	}
}

// BenchmarkGetRulesHash benchmarks hash calculation performance.
func BenchmarkGetRulesHash(b *testing.B) {
	ctx := b.Context()
	realFS := getAllRuleFS()

	b.ReportAllocs()
	for b.Loop() {
		hash, err := getRulesHash(ctx, realFS)
		if err != nil {
			b.Fatalf("Hash calculation failed: %v", err)
		}
		if hash == "" {
			b.Fatal("Expected non-empty hash")
		}
	}
}

// BenchmarkCacheOperations benchmarks save/load operations.
func BenchmarkCacheOperations(b *testing.B) {
	ctx := b.Context()
	fss := getAllRuleFS()

	rules, err := Recursive(ctx, fss)
	if err != nil {
		b.Fatalf("Initial compilation failed: %v", err)
	}

	cache := compileOpenRoot(b, b.TempDir())
	cacheName := "benchmark-rules.cache"

	b.Run("Save", func(b *testing.B) {
		for i := 0; b.Loop(); i++ {
			testName := "test-" + string(rune('a'+i%26)) + ".cache"
			err := saveCachedRules(cache, testName, rules)
			if err != nil {
				b.Fatalf("Failed to save rules: %v", err)
			}
		}
	})

	err = saveCachedRules(cache, cacheName, rules)
	if err != nil {
		b.Fatalf("Failed to save rules for load benchmark: %v", err)
	}

	b.Run("Load", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			loadedRules, err := loadCachedRules(cache, cacheName)
			if err != nil {
				b.Fatalf("Failed to load rules: %v", err)
			}
			if loadedRules == nil {
				b.Fatal("Expected loaded rules")
			}
			// Rules read from a cache carry no finalizer, so free each copy
			// outside the timed region.
			b.StopTimer()
			loadedRules.Destroy()
			b.StartTimer()
		}
	})
}

// BenchmarkRuleRemover measures dropping the disabled rules from every
// embedded rule file, the preprocessing Recursive does on a cache miss.
func BenchmarkRuleRemover(b *testing.B) {
	files, err := listRuleFiles(getAllRuleFS())
	if err != nil {
		b.Fatalf("listRuleFiles(): %v", err)
	}
	sources := make([][]byte, 0, len(files))
	var total int64
	for _, f := range files {
		data, err := fs.ReadFile(f.fsys, f.path)
		if err != nil {
			b.Fatalf("read %s: %v", f.path, err)
		}
		sources = append(sources, data)
		total += int64(len(data))
	}
	r := defaultRuleRemover()

	b.SetBytes(total)
	b.ReportAllocs()
	for b.Loop() {
		for _, src := range sources {
			_ = r.remove(src)
		}
	}
}

// BenchmarkCompareCompilation compares compilation methods.
func BenchmarkCompareCompilation(b *testing.B) {
	ctx := b.Context()
	fss := getAllRuleFS()

	b.Run("Uncached", func(b *testing.B) {
		for b.Loop() {
			rules, err := Recursive(ctx, fss)
			if err != nil {
				b.Fatalf("Uncached compilation failed: %v", err)
			}
			if rules == nil {
				b.Fatal("Expected compiled rules")
			}
		}
	})

	b.Run("CachedFirstRun", func(b *testing.B) {
		for b.Loop() {
			rules, err := Recursive(ctx, fss)
			if err != nil {
				b.Fatalf("Compilation failed: %v", err)
			}
			if rules == nil {
				b.Fatal("Expected compiled rules")
			}
		}
	})

	b.Run("CachedSubsequentRuns", func(b *testing.B) {
		clearRulesCacheB(b, fss)

		_, err := RecursiveCached(ctx, fss)
		if err != nil {
			b.Fatalf("Failed to populate rules cache: %v", err)
		}

		b.ResetTimer()
		for b.Loop() {
			rules, err := RecursiveCached(ctx, fss)
			if err != nil {
				b.Fatalf("Cached compilation failed: %v", err)
			}
			if rules == nil {
				b.Fatal("Expected compiled rules")
			}
		}
	})
}
