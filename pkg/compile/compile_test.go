// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package compile

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	thirdparty "github.com/chainguard-dev/malcontent/third_party"
)

// getAllRuleFS returns both regular and third-party rule filesystems.
func getAllRuleFS() []fs.FS {
	return []fs.FS{FS, thirdparty.FS}
}

// clearRulesCache removes any existing cached rules.
func clearRulesCache(t *testing.T, fss []fs.FS) {
	t.Helper()
	ctx := context.Background()

	cacheDir, err := getCacheDir()
	if err != nil {
		t.Fatalf("Failed to get cache directory: %v", err)
	}

	hash, err := getRulesHash(ctx, fss)
	if err != nil {
		t.Fatalf("Failed to get rules hash: %v", err)
	}

	cacheFile := filepath.Join(cacheDir, fmt.Sprintf("rules-%s.cache", hash))

	if err := os.Remove(cacheFile); err != nil && !os.IsNotExist(err) {
		t.Fatalf("Failed to remove cache file: %v", err)
	}
}

// clearRulesCacheB is the benchmark version of clearRulesCache.
func clearRulesCacheB(b *testing.B, fss []fs.FS) {
	b.Helper()
	ctx := context.Background()

	cacheDir, err := getCacheDir()
	if err != nil {
		b.Fatalf("Failed to get cache directory: %v", err)
	}

	hash, err := getRulesHash(ctx, fss)
	if err != nil {
		b.Fatalf("Failed to get rules hash: %v", err)
	}

	cacheFile := filepath.Join(cacheDir, fmt.Sprintf("rules-%s.cache", hash))

	if err := os.Remove(cacheFile); err != nil && !os.IsNotExist(err) {
		b.Fatalf("Failed to remove cache file: %v", err)
	}
}

func TestRecursive(t *testing.T) {
	ctx := context.Background()

	rules, err := Recursive(ctx, getAllRuleFS())
	if err != nil {
		t.Fatalf("Recursive compilation failed: %v", err)
	}

	if rules == nil {
		t.Fatal("Expected compiled rules, got nil")
	}
}

func TestGetRulesHash(t *testing.T) {
	ctx := context.Background()

	fss := getAllRuleFS()
	hash1, err := getRulesHash(ctx, fss)
	if err != nil {
		t.Fatalf("getRulesHash failed: %v", err)
	}

	if hash1 == "" {
		t.Fatal("Expected non-empty hash")
	}

	hash2, err := getRulesHash(ctx, fss)
	if err != nil {
		t.Fatalf("getRulesHash failed on second call: %v", err)
	}

	if hash1 != hash2 {
		t.Fatalf("Expected consistent hash, got %s and %s", hash1, hash2)
	}

	t.Logf("Rules hash: %s", hash1)
}

func TestCacheOperations(t *testing.T) {
	ctx := context.Background()

	tempDir := t.TempDir()

	originalRules, err := Recursive(ctx, getAllRuleFS())
	if err != nil {
		t.Fatalf("Initial compilation failed: %v", err)
	}

	cacheFile := filepath.Join(tempDir, "test-rules.cache")

	err = saveCachedRules(originalRules, cacheFile)
	if err != nil {
		t.Fatalf("Failed to save rules to cache: %v", err)
	}

	if _, err := os.Stat(cacheFile); os.IsNotExist(err) {
		t.Fatal("Cache file was not created")
	}

	cachedRules, err := loadCachedRules(cacheFile)
	if err != nil {
		t.Fatalf("Failed to load rules from cache: %v", err)
	}

	if cachedRules == nil {
		t.Fatal("Expected loaded rules, got nil")
	}

	nonExistentFile := filepath.Join(tempDir, "does-not-exist.cache")
	_, err = loadCachedRules(nonExistentFile)
	if err == nil {
		t.Fatal("Expected error when loading non-existent cache file")
	}
}

func TestRecursiveCached(t *testing.T) {
	ctx := context.Background()

	fss := getAllRuleFS()

	clearRulesCache(t, fss)

	start1 := time.Now()
	rules1, err := RecursiveCached(ctx, fss)
	duration1 := time.Since(start1)

	if err != nil {
		t.Fatalf("First RecursiveCached call failed: %v", err)
	}

	if rules1 == nil {
		t.Fatal("Expected compiled rules from first call")
	}

	t.Logf("First compilation (cache miss) took: %v", duration1)

	start2 := time.Now()
	rules2, err := RecursiveCached(ctx, fss)
	duration2 := time.Since(start2)

	if err != nil {
		t.Fatalf("Second RecursiveCached call failed: %v", err)
	}

	if rules2 == nil {
		t.Fatal("Expected compiled rules from second call")
	}

	t.Logf("Second compilation (cache hit) took: %v", duration2)

	if duration2 >= duration1 {
		t.Errorf("Cache hit (%v) was not faster than compilation (%v)", duration2, duration1)
	} else {
		speedup := float64(duration1) / float64(duration2)
		t.Logf("Cache speedup: %.1fx faster", speedup)

		if speedup < 3.0 {
			t.Errorf("Expected significant speedup, got only %.1fx", speedup)
		}
	}
}

func TestRecursiveCachedFallback(t *testing.T) {
	ctx := context.Background()

	rules, err := RecursiveCached(ctx, getAllRuleFS())
	if err != nil {
		t.Fatalf("RecursiveCached failed: %v", err)
	}

	if rules == nil {
		t.Fatal("Expected rules from compilation")
	}
}

func TestGetCacheDir(t *testing.T) {
	cacheDir, err := getCacheDir()
	if err != nil {
		t.Fatalf("getCacheDir failed: %v", err)
	}
	var expectedDir string
	if userCacheDir, err := os.UserCacheDir(); err == nil {
		expectedDir = filepath.Join(userCacheDir, "malcontent")
	} else {
		expectedDir = filepath.Join(os.TempDir(), "malcontent-cache")
	}

	if cacheDir != expectedDir {
		t.Fatalf("Expected cache dir %s, got %s", expectedDir, cacheDir)
	}

	info, err := os.Stat(cacheDir)
	if err != nil {
		t.Fatalf("Cache directory does not exist: %v", err)
	}

	if !info.IsDir() {
		t.Fatal("Cache path is not a directory")
	}

	t.Logf("Cache directory: %s", cacheDir)
}

func TestCacheFileSize(t *testing.T) {
	ctx := context.Background()

	tempDir := t.TempDir()

	fss := getAllRuleFS()
	rules, err := Recursive(ctx, fss)
	if err != nil {
		t.Fatalf("Compilation failed: %v", err)
	}

	hash, err := getRulesHash(ctx, fss)
	if err != nil {
		t.Fatalf("Hash calculation failed: %v", err)
	}

	cacheFile := filepath.Join(tempDir, "rules-"+hash+".cache")
	err = saveCachedRules(rules, cacheFile)
	if err != nil {
		t.Fatalf("Failed to save to cache: %v", err)
	}

	fi, err := os.Stat(cacheFile)
	if err != nil {
		t.Fatalf("Failed to stat cache file: %v", err)
	}

	if fi.Size() < 50000000 {
		t.Fatalf("Cache file seems too small: %d bytes", fi.Size())
	}

	t.Logf("Cache file: %s", cacheFile)
	t.Logf("Cache file size: %d bytes (%.2f MB)", fi.Size(), float64(fi.Size())/1024/1024)
}

// BenchmarkRecursive benchmarks uncached rule compilation.
func BenchmarkRecursive(b *testing.B) {
	ctx := context.Background()
	fss := getAllRuleFS()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
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
	ctx := context.Background()
	fss := getAllRuleFS()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
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
	ctx := context.Background()
	fss := getAllRuleFS()

	_, err := RecursiveCached(ctx, fss)
	if err != nil {
		b.Fatalf("Failed to populate cache: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
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
	ctx := context.Background()
	realFS := getAllRuleFS()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
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
	ctx := context.Background()
	fss := getAllRuleFS()

	rules, err := Recursive(ctx, fss)
	if err != nil {
		b.Fatalf("Initial compilation failed: %v", err)
	}

	tempDir := b.TempDir()
	cacheFile := filepath.Join(tempDir, "benchmark-rules.cache")

	b.Run("Save", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			testFile := filepath.Join(tempDir, "test-"+string(rune('a'+i%26))+".cache")
			err := saveCachedRules(rules, testFile)
			if err != nil {
				b.Fatalf("Failed to save rules: %v", err)
			}
		}
	})

	err = saveCachedRules(rules, cacheFile)
	if err != nil {
		b.Fatalf("Failed to save rules for load benchmark: %v", err)
	}

	b.Run("Load", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			loadedRules, err := loadCachedRules(cacheFile)
			if err != nil {
				b.Fatalf("Failed to load rules: %v", err)
			}
			if loadedRules == nil {
				b.Fatal("Expected loaded rules")
			}
		}
	})
}

// BenchmarkCompareCompilation compares compilation methods.
func BenchmarkCompareCompilation(b *testing.B) {
	ctx := context.Background()
	fss := getAllRuleFS()

	b.Run("Uncached", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
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
		for i := 0; i < b.N; i++ {
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
		for i := 0; i < b.N; i++ {
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
