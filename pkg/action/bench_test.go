// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package action

import (
	"context"
	"io/fs"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/chainguard-dev/malcontent/rules"
	thirdparty "github.com/chainguard-dev/malcontent/third_party"
	"github.com/puzpuzpuz/xsync/v4"
)

// benchRuleFS returns the rule filesystem slice used by every action bench.
func benchRuleFS() []fs.FS {
	return []fs.FS{rules.FS, thirdparty.FS}
}

// benchConfig builds a minimal Config wired with compiled rules; benchmarks
// that need rule compilation share the same yarax.Rules.
func benchConfig(ctx context.Context, b *testing.B) (malcontent.Config, []fs.FS) {
	b.Helper()
	rfs := benchRuleFS()
	yrs, err := CachedRules(ctx, rfs)
	if err != nil {
		b.Skipf("CachedRules unavailable (yara-x not built?): %v", err)
	}
	return malcontent.Config{
		Concurrency:      1,
		IgnoreSelf:       false,
		IncludeDataFiles: false,
		MinFileRisk:      0,
		MinRisk:          0,
		Rules:            yrs,
		RuleFS:           rfs,
	}, rfs
}

// BenchmarkScanSinglePath measures scan of a tiny shell fixture end-to-end.
func BenchmarkScanSinglePath(b *testing.B) {
	ctx := context.Background()
	cfg, rfs := benchConfig(ctx, b)
	path := filepath.Join("testdata", "shell")
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_, _ = scanSinglePath(ctx, cfg, path, rfs, path, "", nil)
	}
}

// BenchmarkProcessPath dispatches through the archive vs single-file branch.
func BenchmarkProcessPath(b *testing.B) {
	ctx := context.Background()
	cfg, _ := benchConfig(ctx, b)
	path := filepath.Join("testdata", "shell")
	scanInfo := scanPathInfo{originalPath: path, effectivePath: path}
	r := initializeReport(nil)
	matchChan := make(chan matchResult, 1)
	var matchOnce sync.Once
	logger := clog.FromContext(ctx)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_ = processPath(ctx, path, scanInfo, cfg, r, matchChan, &matchOnce, logger)
		r.Files = xsync.NewMap[string, *malcontent.FileReport]()
	}
}

// BenchmarkHandleSingleFile measures the single-file scan-and-store path.
func BenchmarkHandleSingleFile(b *testing.B) {
	ctx := context.Background()
	cfg, _ := benchConfig(ctx, b)
	path := filepath.Join("testdata", "shell")
	scanInfo := scanPathInfo{originalPath: path, effectivePath: path}
	r := initializeReport(nil)
	matchChan := make(chan matchResult, 1)
	var matchOnce sync.Once
	logger := clog.FromContext(ctx)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_ = handleSingleFile(ctx, path, scanInfo, cfg, r, matchChan, &matchOnce, logger)
		r.Files = xsync.NewMap[string, *malcontent.FileReport]()
	}
}

// BenchmarkCachedRules measures the cached-rule retrieval fast path.
func BenchmarkCachedRules(b *testing.B) {
	ctx := context.Background()
	rfs := benchRuleFS()
	if _, err := CachedRules(ctx, rfs); err != nil {
		b.Skipf("CachedRules unavailable (yara-x not built?): %v", err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_, _ = CachedRules(ctx, rfs)
	}
}

// silence atomic.Int64 lint when the type is not otherwise referenced.
var _ atomic.Int64
