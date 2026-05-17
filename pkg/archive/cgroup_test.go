// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"context"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestCPUQuotaSignatureSane(t *testing.T) {
	t.Parallel()
	n, ok := CPUQuota()
	if ok && n <= 0 {
		t.Fatalf("CPUQuota returned ok=true with non-positive count %d", n)
	}
	if !ok && n != 0 {
		t.Fatalf("CPUQuota returned ok=false but non-zero count %d", n)
	}
}

func TestEffectiveMaxConcurrencyClamping(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name        string
		quotaCPUs   int
		quotaOK     bool
		gomaxprocs  int
		configured  int
		expectedMin int
		expectedMax int
	}{
		{
			name:        "cgroup_overrides_high_config",
			quotaCPUs:   2,
			quotaOK:     true,
			gomaxprocs:  32,
			configured:  16,
			expectedMin: 2,
			expectedMax: 2,
		},
		{
			name:        "config_overrides_cgroup_when_lower",
			quotaCPUs:   8,
			quotaOK:     true,
			gomaxprocs:  32,
			configured:  4,
			expectedMin: 4,
			expectedMax: 4,
		},
		{
			name:        "gomaxprocs_caps_when_smallest",
			quotaCPUs:   16,
			quotaOK:     true,
			gomaxprocs:  4,
			configured:  16,
			expectedMin: 4,
			expectedMax: 4,
		},
		{
			name:        "floor_one_when_zero_configured",
			quotaCPUs:   0,
			quotaOK:     false,
			gomaxprocs:  8,
			configured:  0,
			expectedMin: 1,
			expectedMax: 1,
		},
		{
			name:        "no_cgroup_uses_min_of_remaining",
			quotaCPUs:   0,
			quotaOK:     false,
			gomaxprocs:  4,
			configured:  16,
			expectedMin: 4,
			expectedMax: 4,
		},
		{
			name:        "negative_configured_floors_to_one",
			quotaCPUs:   0,
			quotaOK:     false,
			gomaxprocs:  8,
			configured:  -5,
			expectedMin: 1,
			expectedMax: 1,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := effectiveConcurrencyFor(tc.quotaCPUs, tc.quotaOK, tc.gomaxprocs, tc.configured)
			if got < tc.expectedMin || got > tc.expectedMax {
				t.Fatalf("effectiveConcurrencyFor(%d,%t,%d,%d) = %d; want in [%d,%d]",
					tc.quotaCPUs, tc.quotaOK, tc.gomaxprocs, tc.configured, got,
					tc.expectedMin, tc.expectedMax)
			}
			if got < 1 {
				t.Fatalf("floor violated: got %d", got)
			}
		})
	}
}

func TestEffectiveMaxConcurrencyMatchesPublic(t *testing.T) {
	t.Parallel()
	configured := 32
	got := EffectiveMaxConcurrency(configured)
	if got < 1 {
		t.Fatalf("EffectiveMaxConcurrency(%d) = %d; want >=1", configured, got)
	}
	if got > runtime.GOMAXPROCS(0) {
		t.Fatalf("EffectiveMaxConcurrency(%d) = %d; exceeds GOMAXPROCS %d",
			configured, got, runtime.GOMAXPROCS(0))
	}
}

func TestGlobalExtractionSemaphoreUnblocks(t *testing.T) {
	t.Parallel()

	weight := 2
	sem := newExtractionSemaphoreForTest(weight)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Fill the semaphore to capacity.
	for i := range weight {
		if err := sem.Acquire(ctx, 1); err != nil {
			t.Fatalf("Acquire %d failed: %v", i, err)
		}
	}

	// The (cap+1)th must block until a release.
	blocked := make(chan struct{})
	acquired := make(chan struct{})
	var acqOK atomic.Bool
	var wg sync.WaitGroup
	wg.Go(func() {
		close(blocked)
		if err := sem.Acquire(ctx, 1); err != nil {
			return
		}
		acqOK.Store(true)
		close(acquired)
		sem.Release(1)
	})

	<-blocked
	select {
	case <-acquired:
		t.Fatal("(cap+1)th Acquire did not block when semaphore full")
	case <-time.After(50 * time.Millisecond):
	}

	sem.Release(1)

	select {
	case <-acquired:
	case <-time.After(2 * time.Second):
		t.Fatal("(cap+1)th Acquire did not unblock after Release")
	}

	if !acqOK.Load() {
		t.Fatal("blocked acquirer did not record successful acquisition")
	}

	// Drain remaining permit.
	sem.Release(1)
	wg.Wait()
}

func TestExtractionSemaphoreLazyInit(t *testing.T) {
	t.Parallel()
	sem := extractionSemaphore()
	if sem == nil {
		t.Fatal("extractionSemaphore() returned nil")
	}
	// Repeat call returns the same instance.
	sem2 := extractionSemaphore()
	if sem != sem2 {
		t.Fatal("extractionSemaphore() not memoized")
	}
}
