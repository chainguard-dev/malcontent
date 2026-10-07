// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package action

import (
	"context"
	"sync"

	"golang.org/x/sync/semaphore"
)

// largeScan is the content size, 16 MiB, from which a scan's memory is
// released once the scan ends rather than kept by its scanner. Scanning a
// large executable can take more than ten times its size, chiefly in the
// modules that parse it.
const largeScan = 16 << 20

// scanMemoryFactor estimates the memory a scan takes, with the contents it
// scans, as a multiple of their size. Scanning a large Go executable takes
// about eight to twelve times its size.
const scanMemoryFactor = 10

// memoryBudget returns the share of limit, the memory the process may use,
// that scans may take together: three quarters, less 2 GiB for the rules,
// extracted archives on a memory-backed temporary directory, the Go heap, and
// the rest of the system, but at least a quarter.
func memoryBudget(limit int64) int64 {
	return max(limit/4, limit/4*3-2<<30)
}

// scanMemory admits scans while their estimated memory fits a budget.
// It is safe for concurrent use. A nil *scanMemory admits every scan at once.
type scanMemory struct {
	sem    *semaphore.Weighted
	budget int64
}

// newScanMemory returns a scanMemory with budget bytes, or nil when budget
// is not positive.
func newScanMemory(budget int64) *scanMemory {
	if budget <= 0 {
		return nil
	}
	return &scanMemory{sem: semaphore.NewWeighted(budget), budget: budget}
}

// defaultScanMemory is shared by every scan in the process, since memory is
// a process-wide resource. Without a known memory limit there is no budget.
var defaultScanMemory = sync.OnceValue(func() *scanMemory {
	return newScanMemory(memoryBudget(memoryLimit()))
})

type scanMemoryCtxKey struct{}

// withScanMemory returns ctx carrying a scanMemory with budget bytes, in
// place of the process-wide one.
func withScanMemory(ctx context.Context, budget int64) context.Context {
	return context.WithValue(ctx, scanMemoryCtxKey{}, newScanMemory(budget))
}

// scanMemoryFrom returns the scanMemory ctx carries, or the process-wide one.
func scanMemoryFrom(ctx context.Context) *scanMemory {
	if m, ok := ctx.Value(scanMemoryCtxKey{}).(*scanMemory); ok {
		return m
	}
	return defaultScanMemory()
}

// weight returns the share of the budget a scan of size bytes takes: at most
// the whole budget, so that a scan estimated to need more than the budget
// still runs, alone. Every file counts: many workers scanning files just
// below 16 MiB at once take as much as a few large ones.
func (m *scanMemory) weight(size int64) int64 {
	if m == nil || size <= 0 {
		return 0
	}
	return min(size*scanMemoryFactor, m.budget)
}

// acquire waits until a scan of size bytes fits the budget and returns the
// function that gives its share back. Once ctx ends the scan proceeds
// without a share: it returns early.
func (m *scanMemory) acquire(ctx context.Context, size int64) func() {
	w := m.weight(size)
	if w == 0 {
		return func() {}
	}
	if err := m.sem.Acquire(ctx, w); err != nil {
		return func() {}
	}
	return func() { m.sem.Release(w) }
}
