// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package action

import (
	"io/fs"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"testing/fstest"

	"github.com/chainguard-dev/malcontent/pkg/malcontent"
)

// scanTestClearRuleCache empties the package-level compiled rule cache so the
// next CachedRules call compiles again.
func scanTestClearRuleCache() {
	compileOnce = sync.Once{}
	compiledRuleCache.Store(nil)
}

func TestCachedRulesCompileOnFirstUse(t *testing.T) {
	// Not parallel: replaces the package-level rule cache and redirects the
	// on-disk compile cache away from the user's cache directory.
	yrs, _ := scanTestRules(t)
	saved := compiledRuleCache.Load()
	t.Cleanup(func() {
		compileOnce = sync.Once{}
		compiledRuleCache.Store(saved)
	})
	cacheHome := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", cacheHome)
	t.Setenv("HOME", cacheHome)

	valid := []fs.FS{fstest.MapFS{"valid.yara": {Data: []byte("rule scan_test_valid {\n  strings:\n    $a = \"scan-test-marker\"\n  condition:\n    $a\n}\n")}}}
	invalid := []fs.FS{fstest.MapFS{"invalid.yara": {Data: []byte("rule scan_test_invalid {\n  condition:\n")}}}
	path := scanTestWriteFile(t, filepath.Join(t.TempDir(), "locale.sh"), []byte(scanTestLocaleScript))

	t.Run("first compile returns the compiled rules", func(t *testing.T) {
		scanTestClearRuleCache()
		got, err := CachedRules(t.Context(), valid)
		if err != nil {
			t.Fatalf("CachedRules: %v", err)
		}
		if got == nil {
			t.Fatal("rules: got = nil, want = compiled rules")
		}
		again, err := CachedRules(t.Context(), invalid)
		if err != nil {
			t.Fatalf("CachedRules after compile: %v", err)
		}
		if again != got {
			t.Errorf("rules after compile: got = %p, want cached %p", again, got)
		}
	})

	t.Run("compile failure is returned", func(t *testing.T) {
		scanTestClearRuleCache()
		got, err := CachedRules(t.Context(), invalid)
		if err == nil {
			t.Fatal("error: got = nil, want = compile error")
		}
		if got != nil {
			t.Errorf("rules: got = %p, want = nil", got)
		}
	})

	t.Run("configured rules are used without compiling the rule FS", func(t *testing.T) {
		scanTestClearRuleCache()
		c := malcontent.Config{Rules: yrs, RuleFS: invalid}
		if _, err := scanSinglePath(t.Context(), c, path, invalid, path, "", nil); err != nil {
			t.Errorf("scanSinglePath: got = %v, want = nil", err)
		}
	})

	t.Run("rule FS compile failure fails the file scan", func(t *testing.T) {
		scanTestClearRuleCache()
		c := malcontent.Config{RuleFS: invalid}
		_, err := scanSinglePath(t.Context(), c, path, invalid, path, "", nil)
		if err == nil || !strings.HasPrefix(err.Error(), "rules: ") {
			t.Errorf("scanSinglePath error: got = %v, want a rules compile error", err)
		}
	})
}
