// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package action

import (
	"context"
	"errors"
	"io/fs"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/malcontent/pkg/malcontent"

	yarax "github.com/VirusTotal/yara-x/go"
)

// scanTestClearRuleCache empties the package-level compiled rule cache so the
// next CachedRules call compiles again.
func scanTestClearRuleCache() {
	compiledRuleCache.Store(nil)
}

// scanTestWaitForLockWaiter returns once a goroutine is acquiring a mutex
// inside fn, a function name qualified by its package's last element, such
// as "action.CachedRules".
func scanTestWaitForLockWaiter(t *testing.T, fn string) {
	t.Helper()
	buf := make([]byte, 64<<10)
	for {
		n := runtime.Stack(buf, true)
		if n == len(buf) {
			buf = make([]byte, 2*len(buf))
			continue
		}
		for g := range strings.SplitSeq(string(buf[:n]), "\n\n") {
			if strings.Contains(g, "Mutex).Lock") && strings.Contains(g, fn+"(") {
				return
			}
		}
		runtime.Gosched()
	}
}

func TestCachedRulesCompileOnFirstUse(t *testing.T) {
	// Not parallel: replaces the package-level rule cache and redirects the
	// on-disk compile cache away from the user's cache directory.
	yrs, _ := scanTestRules(t)
	saved := compiledRuleCache.Load()
	t.Cleanup(func() {
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

	t.Run("compile failure is returned on every call until a compile succeeds", func(t *testing.T) {
		scanTestClearRuleCache()
		for range 2 {
			got, err := CachedRules(t.Context(), invalid)
			if err == nil {
				t.Fatal("error: got = nil, want = compile error")
			}
			if got != nil {
				t.Errorf("rules: got = %p, want = nil", got)
			}
		}
		got, err := CachedRules(t.Context(), valid)
		if err != nil || got == nil {
			t.Errorf("CachedRules after failures: got = %p, %v, want compiled rules", got, err)
		}
	})

	t.Run("canceled compile is not cached", func(t *testing.T) {
		scanTestClearRuleCache()
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if _, err := CachedRules(ctx, valid); !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled CachedRules: got = %v, want = %v", err, context.Canceled)
		}
		got, err := CachedRules(t.Context(), valid)
		if err != nil || got == nil {
			t.Errorf("CachedRules after cancellation: got = %p, %v, want compiled rules", got, err)
		}
	})

	t.Run("canceled context is reported with rules cached", func(t *testing.T) {
		compiledRuleCache.Store(yrs)
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		got, err := CachedRules(ctx, valid)
		if !errors.Is(err, context.Canceled) || got != nil {
			t.Errorf("CachedRules: got = %p, %v, want = nil, %v", got, err, context.Canceled)
		}
	})

	t.Run("rules compiled while waiting for the lock are reused", func(t *testing.T) {
		scanTestClearRuleCache()
		type result struct {
			rules *yarax.Rules
			err   error
		}
		done := make(chan result, 1)
		compileMu.Lock()
		go func() {
			// The rule FS does not compile, so only reusing the rules
			// another caller compiled succeeds.
			rules, err := CachedRules(t.Context(), invalid)
			done <- result{rules: rules, err: err}
		}()
		scanTestWaitForLockWaiter(t, "action.CachedRules")
		compiledRuleCache.Store(yrs)
		compileMu.Unlock()
		if got := <-done; got.err != nil || got.rules != yrs {
			t.Errorf("CachedRules: got = %p, %v, want = %p, nil", got.rules, got.err, yrs)
		}
	})

	t.Run("rules the scope split cannot divide are compiled together", func(t *testing.T) {
		scanTestClearRuleCache()
		// A line in a comment that reads like a rule declaration misleads the
		// split into a broken universal rule set.
		tricky := []fs.FS{fstest.MapFS{"tricky.yara": {Data: []byte("rule scan_test_scoped {\n  meta:\n    filetypes = \"sh\"\n  strings:\n    $a = \"LANG=C.UTF-8\"\n  condition:\n    $a\n  /*\nrule scan_test_commented {\n  */\n}\n")}}}
		yrs, err := CachedRules(t.Context(), tricky)
		if err != nil {
			t.Fatalf("CachedRules: %v", err)
		}
		if scopedFor(yrs) != nil {
			t.Errorf("scoped rules: got a split, want every rule compiled together")
		}
		fr, err := scanSinglePath(t.Context(), malcontent.Config{Rules: yrs, RuleFS: tricky}, path, tricky, path, "", nil)
		if err != nil {
			t.Fatalf("scanSinglePath: %v", err)
		}
		if got := len(fr.Behaviors); got != 1 {
			t.Errorf("behaviors: got = %d, want the scoped rule to match", got)
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

func TestCompileRulesCanceledContext(t *testing.T) {
	t.Parallel()
	logger, logs := scanTestLogger()
	ctx, cancel := context.WithCancel(clog.WithLogger(t.Context(), logger))
	cancel()
	valid := []fs.FS{fstest.MapFS{"valid.yara": {Data: []byte("rule scan_test_valid {\n  strings:\n    $a = \"scan-test-marker\"\n  condition:\n    $a\n}\n")}}}

	got, err := compileRules(ctx, valid)
	if got != nil {
		t.Errorf("rules: got = %p, want = nil", got)
	}
	// The cancellation is returned as is, without falling back to compiling
	// the rules together.
	if !errors.Is(err, context.Canceled) || err.Error() != context.Canceled.Error() {
		t.Errorf("error: got = %v, want = %v", err, context.Canceled)
	}
	if out := logs.String(); out != "" {
		t.Errorf("logs: got = %q, want none", out)
	}
}
