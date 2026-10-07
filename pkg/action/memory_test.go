// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package action

import (
	"context"
	"io/fs"
	"math"
	"path/filepath"
	"runtime"
	"slices"
	"sync"
	"testing"
	"testing/fstest"

	"github.com/chainguard-dev/malcontent/pkg/compile"
	"github.com/chainguard-dev/malcontent/pkg/malcontent"
	"github.com/minio/sha256-simd"

	yarax "github.com/VirusTotal/yara-x/go"
)

func TestScanMemoryWeight(t *testing.T) {
	t.Parallel()
	const roomy = 1 << 40
	tests := []struct {
		name string
		m    *scanMemory
		size int64
		want int64
	}{
		{name: "no budget weighs nothing", m: nil, size: 1 << 30, want: 0},
		{name: "empty file weighs nothing", m: newScanMemory(roomy), size: 0, want: 0},
		{name: "small scan weighs a multiple of its size", m: newScanMemory(roomy), size: 4096, want: 4096 * scanMemoryFactor},
		{name: "large scan weighs a multiple of its size", m: newScanMemory(roomy), size: largeScan, want: largeScan * scanMemoryFactor},
		{name: "scan beyond the budget weighs the whole budget", m: newScanMemory(largeScan), size: largeScan, want: largeScan},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.m.weight(tt.size); got != tt.want {
				t.Errorf("weight(%d): got = %d, want = %d", tt.size, got, tt.want)
			}
		})
	}
}

func TestNewScanMemoryWithoutBudget(t *testing.T) {
	t.Parallel()
	for _, budget := range []int64{0, -1} {
		if m := newScanMemory(budget); m != nil {
			t.Errorf("newScanMemory(%d): got = %+v, want = nil", budget, m)
		}
	}
}

func TestScanMemoryAcquire(t *testing.T) {
	t.Parallel()
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	const share = largeScan * scanMemoryFactor
	tests := []struct {
		name string
		ctx  context.Context
		size int64
		// leftWhileHeld is the budget left while the share is held.
		leftWhileHeld int64
	}{
		{name: "large scan holds its share", ctx: t.Context(), size: largeScan, leftWhileHeld: share / 2},
		{name: "small scan holds its share", ctx: t.Context(), size: 4096, leftWhileHeld: share*3/2 - 4096*scanMemoryFactor},
		{name: "empty file holds nothing", ctx: t.Context(), size: 0, leftWhileHeld: share * 3 / 2},
		{name: "scan of an ended context holds nothing", ctx: canceled, size: largeScan, leftWhileHeld: share * 3 / 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			m := newScanMemory(share * 3 / 2)
			release := m.acquire(tt.ctx, tt.size)
			if !m.sem.TryAcquire(tt.leftWhileHeld) {
				t.Errorf("budget left while held: got less than %d, want %d", tt.leftWhileHeld, tt.leftWhileHeld)
			} else {
				if m.sem.TryAcquire(1) {
					t.Errorf("budget left while held: got more than %d, want %d", tt.leftWhileHeld, tt.leftWhileHeld)
					m.sem.Release(1)
				}
				m.sem.Release(tt.leftWhileHeld)
			}
			release()
			if !m.sem.TryAcquire(m.budget) {
				t.Error("budget after release: got less than the whole budget, want all of it")
			}
		})
	}
}

func TestScanMemoryAcquireWithoutBudget(t *testing.T) {
	t.Parallel()
	var m *scanMemory
	m.acquire(t.Context(), 1<<40)()
}

func TestScanMemoryFrom(t *testing.T) {
	t.Parallel()
	if got := scanMemoryFrom(withScanMemory(t.Context(), 1<<30)); got == nil || got.budget != 1<<30 {
		t.Errorf("carried budget: got = %+v, want a budget of %d", got, 1<<30)
	}
	if got := scanMemoryFrom(withScanMemory(t.Context(), 0)); got != nil {
		t.Errorf("carried zero budget: got = %+v, want nil", got)
	}
	if got, want := scanMemoryFrom(t.Context()), defaultScanMemory(); got != want {
		t.Errorf("without a carried budget: got = %p, want the process-wide %p", got, want)
	}
}

func TestMemoryBudget(t *testing.T) {
	t.Parallel()
	tests := []struct {
		limit, want int64
	}{
		{limit: 0, want: 0},
		{limit: 16 << 30, want: 10 << 30},
		{limit: 8 << 30, want: 4 << 30},
		{limit: 4 << 30, want: 1 << 30},
		{limit: 2 << 30, want: 512 << 20},
		{limit: 10, want: 2},
		{limit: math.MaxInt64, want: math.MaxInt64/4*3 - 2<<30},
	}
	for _, tt := range tests {
		if got := memoryBudget(tt.limit); got != tt.want {
			t.Errorf("memoryBudget(%d): got = %d, want = %d", tt.limit, got, tt.want)
		}
	}
}

func TestDefaultScanMemoryFollowsTheLimit(t *testing.T) {
	t.Parallel()
	want := memoryBudget(memoryLimit())
	got := defaultScanMemory()
	switch {
	case want <= 0 && got != nil:
		t.Errorf("default budget without a limit: got = %d, want none", got.budget)
	case want > 0 && (got == nil || got.budget != want):
		t.Errorf("default budget: got = %+v, want %d", got, want)
	}
}

// memoryTestPoolHolds drains the scanner pool for yrs and reports whether it held
// s, then refills it.
func memoryTestPoolHolds(t *testing.T, yrs *yarax.Rules, s *yarax.Scanner) bool {
	t.Helper()
	sp := acquireScannerPool(yrs)
	defer sp.release()
	n := getMaxConcurrency(runtime.GOMAXPROCS(0))
	held := make([]*yarax.Scanner, 0, n)
	for range n {
		held = append(held, sp.scanners.Get(yrs))
	}
	defer func() {
		for _, h := range held {
			sp.scanners.Put(h)
		}
	}()
	return slices.Contains(held, s)
}

// recordDestroyed replaces destroyScanner for the duration of the test with
// one that records each scanner before destroying it.
func recordDestroyed(t *testing.T) func() []*yarax.Scanner {
	t.Helper()
	orig := destroyScanner
	var (
		mu        sync.Mutex
		destroyed []*yarax.Scanner
	)
	destroyScanner = func(s *yarax.Scanner) {
		mu.Lock()
		destroyed = append(destroyed, s)
		mu.Unlock()
		orig(s)
	}
	t.Cleanup(func() { destroyScanner = orig })
	return func() []*yarax.Scanner {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(destroyed)
	}
}

func TestWithScannerReplacesScannerAfterLargeScan(t *testing.T) {
	// Not parallel: drains the shared scanner pool and replaces destroyScanner.
	yrs, _ := scanTestRules(t)
	tests := []struct {
		name     string
		size     int64
		wantKept bool
	}{
		{name: "scanner of a small scan returns to the pool", size: largeScan - 1, wantKept: true},
		{name: "scanner of a large scan is replaced", size: largeScan, wantKept: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			destroyed := recordDestroyed(t)
			var used *yarax.Scanner
			_, err := withScanner(yrs, tt.size, func(s *yarax.Scanner) (*yarax.ScanResults, error) {
				used = s
				return s.Scan([]byte("hello"))
			})
			if err != nil {
				t.Fatalf("withScanner: %v", err)
			}
			if got := memoryTestPoolHolds(t, yrs, used); got != tt.wantKept {
				t.Errorf("pool holds the scanner used: got = %v, want = %v", got, tt.wantKept)
			}
			if got := slices.Contains(destroyed(), used); got == tt.wantKept {
				t.Errorf("scanner used destroyed: got = %v, want = %v", got, !tt.wantKept)
			}
		})
	}
}

func TestWithScannerDestroysScopedScannerAfterLargeScan(t *testing.T) {
	// Not parallel: replaces destroyScanner.
	destroyed := recordDestroyed(t)
	rules, err := compile.Recursive(t.Context(), []fs.FS{fstest.MapFS{"x.yara": {Data: []byte(`rule x { strings: $a = "hello" condition: $a }`)}}})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	set := &scopedSet{rules: rules}
	scopedSets.Store(rules, set)
	t.Cleanup(func() { scopedSets.Delete(rules) })

	var used *yarax.Scanner
	res, err := withScanner(rules, largeScan, func(s *yarax.Scanner) (*yarax.ScanResults, error) {
		used = s
		return s.Scan([]byte("hello"))
	})
	if err != nil {
		t.Fatalf("withScanner: %v", err)
	}
	if got := len(res.MatchingRules()); got != 1 {
		t.Errorf("matching rules of the scan: got = %d, want = 1", got)
	}
	if !slices.Contains(destroyed(), used) {
		t.Error("scanner of a large scan: got it kept, want it destroyed")
	}
	if got, ok := set.scanners.Get().(*yarax.Scanner); ok && got == used {
		t.Error("scoped set scanners: got the scanner of a large scan back, want it destroyed")
	}

	// The scanner of a small scan is kept, by the set rather than by the pool
	// of the universal rules. sync.Pool may drop it, notably under the race
	// detector, so only the scanner pool is checked.
	pool := activeScannerPool.Load()
	if _, err := withScanner(rules, largeScan-1, func(s *yarax.Scanner) (*yarax.ScanResults, error) {
		used = s
		return s.Scan([]byte("hello"))
	}); err != nil {
		t.Fatalf("withScanner: %v", err)
	}
	if slices.Contains(destroyed(), used) {
		t.Error("scanner of a small scan: got it destroyed, want it kept")
	}
	if got := activeScannerPool.Load(); got != pool {
		t.Errorf("active scanner pool: got = %p, want the universal pool %p unchanged", got, pool)
	}
}

func TestSniffedHoldsMemoryShareUntilClosed(t *testing.T) {
	// Not parallel: replaces scanBytes.
	yrs, _ := scanTestRules(t)
	dir := t.TempDir()
	path := scanTestWriteFile(t, filepath.Join(dir, "large.bin"), make([]byte, largeScan))
	ctx := withScanMemory(t.Context(), 1<<20)
	m := scanMemoryFrom(ctx)
	s, err := sniffEntry(ctx, scanTestOpenRoot(t, dir), "large.bin", path, true)
	if err != nil {
		t.Fatalf("sniffEntry: %v", err)
	}
	if m.sem.TryAcquire(1) {
		m.sem.Release(1)
		t.Error("budget after reading the contents: got some left, want the file to hold all of it")
	}
	orig := scanBytes
	var scans, unheld int
	scanBytes = func(yrs *yarax.Rules, fc []byte, sum [sha256.Size]byte) (*yarax.ScanResults, error) {
		scans++
		if m.sem.TryAcquire(1) {
			unheld++
			m.sem.Release(1)
		}
		return orig(yrs, fc, sum)
	}
	t.Cleanup(func() { scanBytes = orig })

	fc := s.content.Bytes()
	if _, err := scanFile(ctx, malcontent.Config{Rules: yrs}, s, path, "", fc, sha256.Sum256(capContents(fc))); err != nil {
		t.Fatalf("scanFile: %v", err)
	}
	if scans == 0 || unheld != 0 {
		t.Errorf("scans holding the whole budget: got %d of %d without it, want every scan to hold it", unheld, scans)
	}
	s.close()
	if !m.sem.TryAcquire(m.budget) {
		t.Error("budget after close: got less than all of it, want it released")
	}
}
